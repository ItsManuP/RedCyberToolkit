import time, uuid, json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime

class TaskStatus(Enum):
    PENDING = "pending"; RUNNING = "running"
    DONE = "done";       FAILED = "failed"

class AttackPhase(Enum):
    DISCOVERY   = 1; CVE_CHECK   = 2
    AUTH_ATTACK = 3; EXPLOIT     = 4
    TRAFFIC     = 5; REPORT      = 6

@dataclass
class Task:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    phase: AttackPhase = AttackPhase.DISCOVERY
    agent_name: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    def duration(self):
        if self.started_at and self.finished_at:
            return round(self.finished_at - self.started_at, 2)
        return None

@dataclass
class SessionState:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str = ""
    ip: str = ""
    authorized: bool = False
    started_at: float = field(default_factory=time.time)
    phases_completed: List[AttackPhase] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    cve_list: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    exploits: List[Dict] = field(default_factory=list)
    traffic_data: List[Dict] = field(default_factory=list)

class MessageBus:
    def __init__(self):
        self._subscribers: Dict[str, List] = {}
        self._history: List[Dict] = []

    def subscribe(self, topic: str, callback):
        self._subscribers.setdefault(topic, []).append(callback)

    def publish(self, topic: str, payload: Dict, sender: str = "orchestrator"):
        msg = {"id": str(uuid.uuid4())[:8], "topic": topic,
               "sender": sender, "payload": payload,
               "timestamp": datetime.utcnow().isoformat()}
        self._history.append(msg)
        for cb in self._subscribers.get(topic, []):
            cb(msg)
        return msg

class Orchestrator:
    PHASE_ORDER = [
        AttackPhase.DISCOVERY, AttackPhase.CVE_CHECK,
        AttackPhase.AUTH_ATTACK, AttackPhase.EXPLOIT,
        AttackPhase.TRAFFIC, AttackPhase.REPORT,
    ]

    def __init__(self, target: str, authorized: bool, options: Dict = None):
        self.state = SessionState(target=target, authorized=authorized)
        self.bus = MessageBus()
        self.task_queue: List[Task] = []
        self.options = options or {}
        self._agents: Dict[str, Any] = {}
        self._log: List[str] = []

    def register_agent(self, name: str, agent_instance):
        self._agents[name] = agent_instance
        self._log_event(f"Agent registrato: {name}")

    def enqueue(self, phase: AttackPhase, agent_name: str, params: Dict = None) -> Task:
        task = Task(phase=phase, agent_name=agent_name, params=params or {})
        self.task_queue.append(task)
        return task

    def _run_task(self, task: Task) -> Task:
        agent = self._agents.get(task.agent_name)
        if agent is None:
            task.status = TaskStatus.FAILED
            task.error = f"Agent '{task.agent_name}' non trovato"
            return task
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        self._log_event(f"[{task.phase.name}] Avvio {task.agent_name} (id:{task.id})")
        self.bus.publish("task.started",
            {"task_id": task.id, "agent": task.agent_name, "phase": task.phase.name})
        try:
            result = agent.run(self.state, task.params)
            task.result = result
            task.status = TaskStatus.DONE
            self._ingest_result(task.phase, result)
        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            self._log_event(f"  ERRORE in {task.agent_name}: {exc}")
        task.finished_at = time.time()
        self._log_event(f"  → {task.status.value} in {task.duration()}s")
        self.bus.publish("task.finished",
            {"task_id": task.id, "status": task.status.value})
        return task

    def _ingest_result(self, phase: AttackPhase, result: Dict):
        if phase == AttackPhase.DISCOVERY:
            self.state.open_ports.extend(result.get("ports", []))
            self.state.ip = result.get("ip", self.state.target)
        elif phase == AttackPhase.CVE_CHECK:
            self.state.cve_list.extend(result.get("cves", []))
        elif phase == AttackPhase.AUTH_ATTACK:
            self.state.credentials.extend(result.get("credentials", []))
        elif phase == AttackPhase.EXPLOIT:
            self.state.exploits.extend(result.get("exploits", []))
        elif phase == AttackPhase.TRAFFIC:
            self.state.traffic_data.extend(result.get("captures", []))
        self.state.findings.append({"phase": phase.name, "data": result})

    def run_pipeline(self, phases: List[AttackPhase] = None) -> SessionState:
        if not self.state.authorized:
            raise PermissionError("Autorizzazione non confermata. Operazione annullata.")
        selected = phases or self.PHASE_ORDER
        self._log_event(f"=== SESSIONE {self.state.session_id} AVVIATA ===")
        self._log_event(f"Target: {self.state.target}")
        
        total_tasks = sum(1 for t in self.task_queue if t.phase in selected)
        completed_tasks = 0
        
        for phase in selected:
            phase_tasks = [t for t in self.task_queue if t.phase == phase]
            if not phase_tasks:
                continue
            self._log_event(f"\n{'='*50}\nFASE: {phase.name} ({len(phase_tasks)} task)\n{'='*50}")
            for idx, task in enumerate(phase_tasks, 1):
                # Mostra progresso fase corrente
                self._log_event(f"--> Task {idx}/{len(phase_tasks)}: {task.agent_name}")
                self._run_task(task)
                completed_tasks += 1
                percent = (completed_tasks / total_tasks) * 100
                self._log_event(f"--> Avanzamento totale: {completed_tasks}/{total_tasks} ({percent:.1f}%)")
                
                if task.status == TaskStatus.FAILED and phase == AttackPhase.DISCOVERY:
                    self._log_event("DISCOVERY fallita — pipeline interrotta.")
                    return self.state
            self.state.phases_completed.append(phase)
        self._log_event(f"\n=== PIPELINE COMPLETATA in {round(time.time()-self.state.started_at,2)}s ===")
        return self.state

    def _log_event(self, msg: str):
        ts = datetime.utcnow().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._log.append(line)
        print(line)



    def _task_summary(self, task: Task) -> str:
        if task.phase == AttackPhase.DISCOVERY:
            ports = len(task.result.get("ports", [])) if task.result else 0
            return f"Trovate {ports} porte aperte"
        elif task.phase == AttackPhase.CVE_CHECK:
            cves = task.result.get("total", 0) if task.result else 0
            crit = task.result.get("critical_count", 0) if task.result else 0
            return f"Trovate {cves} CVE (di cui {crit} critiche)"
        elif task.phase == AttackPhase.AUTH_ATTACK:
            creds = task.result.get("total_found", 0) if task.result else 0
            return f"Trovate {creds} credenziali valide"
        elif task.phase == AttackPhase.EXPLOIT:
            success = task.result.get("total_successful", 0) if task.result else 0
            return f"Exploit riusciti: {success}"
        elif task.phase == AttackPhase.TRAFFIC:
            findings = task.result.get("total_findings", 0) if task.result else 0
            return f"Trovati {findings} issue di traffico"
        elif task.phase == AttackPhase.REPORT:
            files = task.result.get("saved_files", []) if task.result else []
            return f"Report salvati: {', '.join(files)}"
        return "Task completato"

    def summary(self) -> Dict:
        return {
            "session_id": self.state.session_id,
            "target": self.state.target,
            "phases_completed": [p.name for p in self.state.phases_completed],
            "open_ports": len(self.state.open_ports),
            "cves_found": len(self.state.cve_list),
            "credentials_found": len(self.state.credentials),
            "exploits_successful": sum(1 for e in self.state.exploits if e.get("success")),
            "duration_s": round(time.time() - self.state.started_at, 2),
        }