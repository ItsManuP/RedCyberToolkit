# core/report_generator.py
from datetime import datetime
from core.log_config import get_logger

logger = get_logger("report")

class ReportGenerator:
    def __init__(self, state):
        self.state = state

    def generate(self) -> str:
        logger.info("Generating report...")
        sections = []

        logger.debug("Creating summary section")
        sections.append(self._summary_section())

        logger.debug("Open ports section")
        sections.append(self._ports_section())

        logger.debug("CVEs section")
        sections.append(self._cve_section())

        logger.debug("Credentials section")
        sections.append(self._credentials_section())

        logger.debug("Exploits section")
        sections.append(self._exploit_section())

        logger.info("Report generation completed")
        return "\n\n".join(sections)

    def _summary_section(self) -> str:
        return f"""# RedTeam Report - {self.state.target}
Date: {datetime.now().isoformat()}
IP: {self.state.ip}

## Summary
- Open ports: {len(self.state.open_ports)}
- Detected services: {len(self.state.services)}
- CVEs found: {len(self.state.cve_list)}
- Credentials obtained: {len(self.state.credentials)}
- Exploits attempted: {len(self.state.exploits)}
"""

    def _ports_section(self) -> str:
        lines = ["## Open Ports"]
        for p in self.state.open_ports:
            lines.append(f"- {p['port']}/{p.get('protocol', 'tcp')} : {p.get('service', 'unknown')}")
        return "\n".join(lines) if len(lines) > 1 else "## Open Ports\nNo ports detected."

    def _cve_section(self) -> str:
        if not self.state.cve_list:
            return "## CVEs Found\nNo CVEs identified."
        lines = ["## CVEs Found"]
        for cve in self.state.cve_list[:20]:
            lines.append(f"- {cve.get('cve_id')} : {cve.get('description', '')[:100]}")
        if len(self.state.cve_list) > 20:
            lines.append(f"... and {len(self.state.cve_list)-20} more CVEs.")
        return "\n".join(lines)

    def _credentials_section(self) -> str:
        if not self.state.credentials:
            return "## Credentials Obtained\nNo credentials discovered."
        lines = ["## Credentials Obtained"]
        for cred in self.state.credentials:
            lines.append(f"- {cred.get('username')}:{cred.get('password')} (service: {cred.get('service', 'unknown')})")
        return "\n".join(lines)

    def _exploit_section(self) -> str:
        if not self.state.exploits:
            return "## Exploits Attempted\nNo exploits executed."
        lines = ["## Exploits Attempted"]
        for e in self.state.exploits:
            status = "✓ successful" if e.get("success") else "✗ failed"
            lines.append(f"- {e.get('exploit_name')} : {status}")
        return "\n".join(lines)