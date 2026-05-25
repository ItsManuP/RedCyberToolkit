import time
from enum import Enum
from typing import Any, Dict, List

from core.agents import (
    BruteForceAgent,
    CVECheckerAgent,
    ExploitAgent,
    PortScannerAgent,
    ReportAgent,
    ServiceDetectorAgent,
    TrafficAgent,
    WPAgent,
)
from core.log_config import get_logger
from core.state import State

logger = get_logger("orchestrator")


class AttackPhase(Enum):
    DISCOVERY = "discovery"
    CVE_CHECK = "cve_check"
    AUTH_ATTACK = "auth_attack"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class Orchestrator:
    def __init__(self, target: str, ip: str):
        self.state = State(target=target, ip=ip)
        self.agents = self._build_agents()
        self.tasks = self._build_tasks()
        logger.info(f"Orchestrator initialized for {target} ({ip})")

    def _build_agents(self) -> Dict[str, Any]:
        return {
            "port_scanner": PortScannerAgent(),
            "service_detector": ServiceDetectorAgent(),
            "cve_checker": CVECheckerAgent(),
            "bruteforcer": BruteForceAgent(),
            "exploiter": ExploitAgent(),
            "traffic": TrafficAgent(),
            "wp_enum": WPAgent(),
            "report": ReportAgent(),
        }

    def _build_tasks(self) -> List[Dict[str, Any]]:
        return [
            {"phase": AttackPhase.DISCOVERY, "agent": self.agents["port_scanner"], "name": "port_scanner", "params": {}},
            {"phase": AttackPhase.DISCOVERY, "agent": self.agents["service_detector"], "name": "service_detector", "params": {}},
            {"phase": AttackPhase.CVE_CHECK, "agent": self.agents["cve_checker"], "name": "cve_checker", "params": {"include_filtered": True}},
            {"phase": AttackPhase.AUTH_ATTACK, "agent": self.agents["bruteforcer"], "name": "bruteforcer", "params": {}},
            {"phase": AttackPhase.EXPLOITATION, "agent": self.agents["exploiter"], "name": "exploiter", "params": {"include_filtered": True}},
        ]

    def _run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        agent = task["agent"]
        name = task["name"]
        phase = task["phase"]
        params = task.get("params", {}) or {}
        logger.info(f"Executing task: {name} (phase {phase.value})")
        start = time.time()
        try:
            result = agent.run(self.state, params)
            elapsed = time.time() - start
            logger.info(f"Task {name} completed in {elapsed:.2f}s")
            self._ingest_result(phase, result)
            self._log_task_result(phase, name, result)
            return result
        except Exception as exc:
            logger.error(f"Error in {name}: {exc}", exc_info=True)
            self.state.errors.append({"task": name, "error": str(exc)})
            return {"error": str(exc)}

    def _log_task_result(self, phase: AttackPhase, agent_name: str, result: Dict[str, Any]) -> None:
        if not result:
            logger.warning(f"{agent_name}: no results")
            return
        if phase == AttackPhase.DISCOVERY:
            if "ports" in result or "filtered_ports" in result or "closed_ports" in result:
                logger.info(
                    f"{agent_name}: open={len(result.get('ports', []))}, filtered={len(result.get('filtered_ports', []))}, closed={len(result.get('closed_ports', []))}"
                )
            elif "services" in result:
                logger.info(f"{agent_name}: identified {len(result.get('services', {}))} service banners")
            elif "web_findings" in result:
                logger.info(f"{agent_name}: collected {len(result.get('web_findings', []))} web findings")
            elif "wordpress_plugins" in result:
                logger.info(f"{agent_name}: found {len(result.get('wordpress_plugins', []))} WordPress plugins")
        elif phase == AttackPhase.CVE_CHECK:
            logger.info(f"{agent_name}: found {len(result.get('cves', []))} CVEs")
        elif phase == AttackPhase.AUTH_ATTACK:
            logger.info(f"{agent_name}: obtained {len(result.get('credentials', []))} credentials")
        elif phase == AttackPhase.EXPLOITATION:
            exploits = result.get("exploits", [])
            success = sum(1 for exploit in exploits if exploit.get("success"))
            logger.info(f"{agent_name}: {success} successful exploits out of {len(exploits)}")
        elif phase == AttackPhase.REPORTING:
            logger.info(f"{agent_name}: generated {len(result.get('reports_generated', []))} reports")

    def _merge_unique(self, existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], keys: List[str]) -> List[Dict[str, Any]]:
        seen = {tuple(item.get(key) for key in keys) for item in existing}
        for item in incoming:
            marker = tuple(item.get(key) for key in keys)
            if marker not in seen:
                existing.append(item)
                seen.add(marker)
        return existing

    def _ingest_result(self, phase: AttackPhase, result: Dict[str, Any]) -> None:
        if not result:
            return
        if phase == AttackPhase.DISCOVERY:
            if "ports" in result:
                self.state.open_ports = self._merge_unique(self.state.open_ports, result["ports"], ["port", "protocol", "state"])
            if "filtered_ports" in result:
                self.state.filtered_ports = self._merge_unique(self.state.filtered_ports, result["filtered_ports"], ["port", "protocol", "state"])
            if "closed_ports" in result:
                self.state.closed_ports = self._merge_unique(self.state.closed_ports, result["closed_ports"], ["port", "protocol", "state"])
            if "services" in result:
                self.state.services.update(result["services"])
            if "web_findings" in result:
                self.state.web_findings = self._merge_unique(self.state.web_findings, result["web_findings"], ["url", "status_code"])
            if "wordpress_plugins" in result:
                self.state.wordpress_plugins = self._merge_unique(self.state.wordpress_plugins, result["wordpress_plugins"], ["plugin", "version"])
        elif phase == AttackPhase.CVE_CHECK and "cves" in result:
            self.state.cve_list = self._merge_unique(self.state.cve_list, result["cves"], ["cve_id", "port", "source_state"])
        elif phase == AttackPhase.AUTH_ATTACK and "credentials" in result:
            self.state.credentials = self._merge_unique(self.state.credentials, result["credentials"], ["username", "password", "service", "port"])
        elif phase == AttackPhase.EXPLOITATION and "exploits" in result:
            self.state.exploits = self._merge_unique(self.state.exploits, result["exploits"], ["exploit_name", "cve_id", "source_state"])
        elif phase == AttackPhase.REPORTING and "reports_generated" in result:
            for path in result["reports_generated"]:
                self.state.reports.append({"path": path})

    def run(self) -> State:
        logger.info(f"Starting test on {self.state.target} ({self.state.ip})")
        phases = [AttackPhase.DISCOVERY, AttackPhase.CVE_CHECK, AttackPhase.AUTH_ATTACK, AttackPhase.EXPLOITATION]
        for phase in phases:
            logger.info(f"Starting phase {phase.value}...")
            tasks_for_phase = [task for task in self.tasks if task["phase"] == phase]
            for task in tasks_for_phase:
                self._run_task(task)
            logger.info(f"Phase {phase.value} completed")
            time.sleep(0.5)
        logger.info("Test finished")
        return self.state
