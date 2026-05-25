# core/orchestrator.py
import time
from enum import Enum
from core.log_config import get_logger
from core.state import State
from core.agents import (
    PortScannerAgent, ServiceDetectorAgent,
    CVECheckerAgent, BruteForceAgent, ExploitAgent
)

logger = get_logger("orchestrator")

class AttackPhase(Enum):
    DISCOVERY = "discovery"
    CVE_CHECK = "cve_check"
    AUTH_ATTACK = "auth_attack"
    EXPLOITATION = "exploitation"

class Orchestrator:
    def __init__(self, target: str, ip: str):
        self.state = State(target=target, ip=ip)
        self.tasks = self._build_tasks()
        logger.info(f"Orchestrator initialized for {target} ({ip})")

    def _build_tasks(self):
        return [
            {"phase": AttackPhase.DISCOVERY, "agent": PortScannerAgent(), "name": "port_scanner"},
            {"phase": AttackPhase.DISCOVERY, "agent": ServiceDetectorAgent(), "name": "service_detector"},
            {"phase": AttackPhase.CVE_CHECK, "agent": CVECheckerAgent(), "name": "cve_checker"},
            {"phase": AttackPhase.AUTH_ATTACK, "agent": BruteForceAgent(), "name": "bruteforcer"},
            {"phase": AttackPhase.EXPLOITATION, "agent": ExploitAgent(), "name": "exploiter"},
        ]

    def _run_task(self, task):
        agent = task["agent"]
        name = task["name"]
        phase = task["phase"]
        logger.info(f"Executing task: {name} (phase {phase.value})")
        start = time.time()
        try:
            result = agent.run(self.state)
            elapsed = time.time() - start
            logger.info(f"Task {name} completed in {elapsed:.2f}s")
            self._ingest_result(phase, result)
            self._log_task_result(phase, name, result)
        except Exception as e:
            logger.error(f"Error in {name}: {e}", exc_info=True)
            self.state.errors.append({"task": name, "error": str(e)})

    def _log_task_result(self, phase: AttackPhase, agent_name: str, result: dict):
        if not result:
            logger.warning(f"{agent_name}: no results")
            return
        if phase == AttackPhase.DISCOVERY:
            ports = result.get('ports', [])
            if ports:
                port_list = [p['port'] for p in ports[:5]]
                more = f" +{len(ports)-5}" if len(ports) > 5 else ""
                logger.info(f"{agent_name}: discovered {len(ports)} ports: {port_list}{more}")
            else:
                logger.info(f"{agent_name}: no open ports")
        elif phase == AttackPhase.CVE_CHECK:
            cves = result.get('cves', [])
            logger.info(f"{agent_name}: found {len(cves)} CVEs")
        elif phase == AttackPhase.AUTH_ATTACK:
            creds = result.get('credentials', [])
            logger.info(f"{agent_name}: obtained {len(creds)} credentials")
        elif phase == AttackPhase.EXPLOITATION:
            exploits = result.get('exploits', [])
            success = sum(1 for e in exploits if e.get('success'))
            logger.info(f"{agent_name}: {success} successful exploits out of {len(exploits)}")

    def _ingest_result(self, phase: AttackPhase, result: dict):
        if phase == AttackPhase.DISCOVERY:
            if 'ports' in result:
                self.state.open_ports.extend(result['ports'])
            if 'services' in result:
                self.state.services.update(result['services'])
        elif phase == AttackPhase.CVE_CHECK and 'cves' in result:
            self.state.cve_list.extend(result['cves'])
        elif phase == AttackPhase.AUTH_ATTACK and 'credentials' in result:
            self.state.credentials.extend(result['credentials'])
        elif phase == AttackPhase.EXPLOITATION and 'exploits' in result:
            self.state.exploits.extend(result['exploits'])

    def run(self):
        logger.info(f"Starting test on {self.state.target} ({self.state.ip})")
        phases = [AttackPhase.DISCOVERY, AttackPhase.CVE_CHECK, AttackPhase.AUTH_ATTACK, AttackPhase.EXPLOITATION]
        for phase in phases:
            logger.info(f"Starting phase {phase.value}...")
            tasks_for_phase = [t for t in self.tasks if t["phase"] == phase]
            for task in tasks_for_phase:
                self._run_task(task)
            logger.info(f"Phase {phase.value} completed")
            time.sleep(1)  # short pause between phases
        logger.info("Test finished, generating report...")
        return self.state