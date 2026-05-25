# core/ai_orchestrator.py
import time
from core.orchestrator import Orchestrator, AttackPhase
from core.ai_assistant import AIAssistant
from core.log_config import get_logger

logger = get_logger("ai_orchestrator")

class AIOrchestrator(Orchestrator):
    def __init__(self, target: str, ip: str):
        super().__init__(target, ip)
        self.ai = AIAssistant()
        logger.info("AI Orchestrator initialized (7s rate limiting)")

    def _run_task(self, task):
        agent = task["agent"]
        name = task["name"]
        phase = task["phase"]

        # Pre-task AI analysis
        logger.info(f"Requesting pre-analysis for {name}")
        pre_analysis = self.ai.analyze_before_task(
            agent_name=name,
            phase=phase.name,
            state=self.state,
            params=task.get("params", {})
        )
        logger.info(f"Pre-analysis: {pre_analysis[:150]}...")

        # Task execution
        logger.info(f"Executing task: {name}")
        start = time.time()
        try:
            result = agent.run(self.state)
            elapsed = time.time() - start
            logger.info(f"Task {name} completed in {elapsed:.2f}s")
            self._ingest_result(phase, result)
            self._log_task_result(phase, name, result)
        except Exception as e:
            logger.error(f"Error in {name}: {e}", exc_info=True)
            result = {"error": str(e)}

        # Post-task AI analysis
        logger.info(f"Requesting post-analysis for {name}")
        post_analysis = self.ai.analyze_after_task(
            agent_name=name,
            phase=phase.name,
            state=self.state,
            result=result if result else {}
        )
        logger.info(f"Post-analysis: {post_analysis[:150]}...")
        return result