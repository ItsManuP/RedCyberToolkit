import time
from core.orchestrator import Orchestrator, TaskStatus
from core.ai_assistant import AIAssistant


class AIOrchestrator(Orchestrator):
    """Orchestrator that injects AI comments before/after each task and phase"""


    def __init__(self, target: str, authorized: bool, options: dict = None):
        super().__init__(target, authorized, options)
        self.ai = AIAssistant()
        self._log_event("🧠 Integrated AI assistant (DeepSeek)")


    def run_pipeline(self, phases=None):
        if not self.state.authorized:
            raise PermissionError("Authorization not confirmed")


        selected = phases or self.PHASE_ORDER
        self._log_event(f"=== SESSION {self.state.session_id} STARTED ===")
        self._log_event(f"Target: {self.state.target}")


        for phase in selected:
            phase_tasks = [t for t in self.task_queue if t.phase == phase]
            if not phase_tasks:
                continue


            # AI advice before the phase
            advice = self.ai.analyze_orchestrator_decision(self.state, phase.name)
            self._log_event(f"🤖 AI suggests for phase {phase.name}: {advice[:200]}...")


            self._log_event(f"\n{'='*50}\nPHASE: {phase.name}\n{'='*50}")
            for task in phase_tasks:
                self._run_task_with_ai(task)
                if task.status == TaskStatus.FAILED and phase.name == "DISCOVERY":
                    self._log_event("DISCOVERY failed — pipeline interrupted.")
                    return self.state
            self.state.phases_completed.append(phase)


        self._log_event(f"\n=== PIPELINE COMPLETED in {round(time.time()-self.state.started_at,2)}s ===")
        return self.state


    def _run_task_with_ai(self, task):
        agent = self._agents.get(task.agent_name)
        if agent is None:
            task.status = TaskStatus.FAILED
            task.error = f"Agent '{task.agent_name}' not found"
            return task


        # AI analysis before the task
        pre_analysis = self.ai.analyze_before_task(
            task.agent_name, task.phase.name, self.state, task.params
        )
        self._log_event(f"🤖 [PRE] {task.agent_name}: {pre_analysis[:150]}...")


        # Original execution
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        self._log_event(f"[{task.phase.name}] Starting {task.agent_name} (id:{task.id})")
        self.bus.publish("task.started", {"task_id": task.id, "agent": task.agent_name})


        try:
            result = agent.run(self.state, task.params)
            task.result = result
            task.status = TaskStatus.DONE
            self._ingest_result(task.phase, result)
            if task.result:
                if task.phase == AttackPhase.DISCOVERY:
                    self._log_event(f"✅ {task.agent_name}: Scoperti {len(task.result.get('ports', []))} porte aperte")
                elif task.phase == AttackPhase.CVE_CHECK:
                    self._log_event(f"✅ {task.agent_name}: Trovate {len(task.result.get('cves', []))} CVE")
                elif task.phase == AttackPhase.AUTH_ATTACK:
                    self._log_event(f"✅ {task.agent_name}: Ottenute {len(task.result.get('credentials', []))} credenziali")
        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            self._log_event(f"  ERROR in {task.agent_name}: {exc}")


        task.finished_at = time.time()
        self._log_event(f"  → {task.status.value} in {task.duration()}s")


        # AI analysis after the task (if successful or in any case)
        if task.result:
            post_analysis = self.ai.analyze_after_task(
                task.agent_name, task.phase.name, self.state, task.result
            )
            self._log_event(f"🤖 [POST] {task.agent_name}: {post_analysis[:150]}...")
        else:
            self._log_event(f"🤖 [POST] {task.agent_name}: No result to analyze.")


        self.bus.publish("task.finished", {"task_id": task.id, "status": task.status.value})
        return task