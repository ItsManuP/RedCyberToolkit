import time
from typing import Any, Dict, List

from core.ai_assistant import AIAssistant
from core.log_config import get_logger
from core.orchestrator import AttackPhase, Orchestrator

logger = get_logger("ai_orchestrator")


class AIOrchestrator(Orchestrator):
    def __init__(self, target: str, ip: str):
        super().__init__(target, ip)
        self.ai = AIAssistant()
        self.dynamic_tasks: List[Dict[str, Any]] = []
        logger.info("AI Orchestrator initialized (sequential phases + dynamic planning)")

    def _run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        agent = task["agent"]
        name = task["name"]
        phase = task["phase"]
        params = task.get("params", {}) or {}

        logger.info(f"Requesting pre-analysis for {name}")
        pre_analysis = self.ai.analyze_before_task(name, phase.name, self.state, params)
        logger.info(f"Pre-analysis: {pre_analysis[:150]}...")

        logger.info(f"Executing task: {name}")
        start = time.time()
        try:
            result = agent.run(self.state, params)
            elapsed = time.time() - start
            logger.info(f"Task {name} completed in {elapsed:.2f}s")
            self._ingest_result(phase, result)
            self._log_task_result(phase, name, result)
        except Exception as exc:
            logger.error(f"Error in {name}: {exc}", exc_info=True)
            self.state.errors.append({"task": name, "error": str(exc)})
            result = {"error": str(exc)}

        logger.info(f"Requesting post-analysis for {name}")
        post_analysis = self.ai.analyze_after_task(name, phase.name, self.state, result)
        logger.info(f"Post-analysis: {post_analysis[:150]}...")
        return result

    def _enqueue_dynamic(self, agent_name: str, params: Dict[str, Any]) -> None:
        agent_instance = self.agents.get(agent_name)
        if not agent_instance:
            logger.warning(f"Unknown agent '{agent_name}' - cannot enqueue")
            return
        phase = self._guess_phase_for_agent(agent_name)
        self.dynamic_tasks.append({"agent": agent_instance, "name": agent_name, "phase": phase, "params": params or {}})
        logger.info(f"Dynamically enqueued task: {agent_name} (phase {phase.name})")

    def _guess_phase_for_agent(self, agent_name: str) -> AttackPhase:
        mapping = {
            "port_scanner": AttackPhase.DISCOVERY,
            "service_detector": AttackPhase.DISCOVERY,
            "traffic": AttackPhase.DISCOVERY,
            "wp_enum": AttackPhase.DISCOVERY,
            "cve_checker": AttackPhase.CVE_CHECK,
            "bruteforcer": AttackPhase.AUTH_ATTACK,
            "exploiter": AttackPhase.EXPLOITATION,
            "report": AttackPhase.REPORTING,
        }
        return mapping.get(agent_name, AttackPhase.EXPLOITATION)

    def _phase_tasks(self, phase: AttackPhase) -> List[Dict[str, Any]]:
        static_tasks = [task for task in self.tasks if task["phase"] == phase]
        dynamic_tasks = [task for task in self.dynamic_tasks if task["phase"] == phase]
        self.dynamic_tasks = [task for task in self.dynamic_tasks if task["phase"] != phase]

        if phase == AttackPhase.DISCOVERY:
            priority = {"port_scanner": 0, "service_detector": 1, "traffic": 2, "wp_enum": 3}
            return sorted(static_tasks + dynamic_tasks, key=lambda task: priority.get(task["name"], 50))
        return static_tasks + dynamic_tasks

    def run(self):
        logger.info(f"Starting test on {self.state.target} ({self.state.ip})")
        phases = [AttackPhase.DISCOVERY, AttackPhase.CVE_CHECK, AttackPhase.AUTH_ATTACK, AttackPhase.EXPLOITATION]

        for phase in phases:
            logger.info(f"Starting phase {phase.value}...")
            phase_tasks = self._phase_tasks(phase)
            if not phase_tasks:
                logger.info(f"No tasks for phase {phase.value}, skipping.")
                continue

            last_result = {}
            for task in phase_tasks:
                if task["name"] == "service_detector" and not self.state.open_ports:
                    logger.info("Skipping service_detector because no open ports are available yet")
                    continue
                last_result = self._run_task(task)

            suggestions = self.ai.plan_next_actions(self.state, phase.name, last_result)
            for suggestion in suggestions[:3]:
                agent_name = suggestion.get("agent_name")
                params = suggestion.get("params", {})
                if agent_name:
                    self._enqueue_dynamic(agent_name, params)
            time.sleep(1)

        logger.info("Test finished")
        return self.state
