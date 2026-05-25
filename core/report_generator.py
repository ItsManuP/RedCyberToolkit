from datetime import datetime

from core.log_config import get_logger

logger = get_logger("report")


class ReportGenerator:
    def __init__(self, state):
        self.state = state

    def generate(self) -> str:
        logger.info("Generating report...")
        sections = [
            self._summary_section(),
            self._ports_section(),
            self._services_section(),
            self._cve_section(),
            self._credentials_section(),
            self._exploit_section(),
            self._web_findings_section(),
            self._wordpress_section(),
            self._errors_section(),
        ]
        logger.info("Report generation completed")
        return "".join(section for section in sections if section)

    def _summary_section(self) -> str:
        return f"""# RedTeam Report - {self.state.target}
        Date: {datetime.now().isoformat()}
        IP: {self.state.ip}

        ## Summary
        - Open ports: {len(self.state.open_ports)}
        - Filtered ports: {len(self.state.filtered_ports)}
        - Closed ports: {len(self.state.closed_ports)}
        - Detected services: {len(self.state.services)}
        - CVEs found: {len(self.state.cve_list)}
        - Credentials obtained: {len(self.state.credentials)}
        - Exploits attempted: {len(self.state.exploits)}
        - Web findings: {len(self.state.web_findings)}
        - WordPress plugins: {len(self.state.wordpress_plugins)}
        - Errors: {len(self.state.errors)}
        """

    def _ports_section(self) -> str:
        blocks = []
        if self.state.open_ports:
            lines = ["## Open Ports"]
            for port in self.state.open_ports:
                lines.append(f"- {port['port']}/{port.get('protocol', 'tcp')} : {port.get('service', 'unknown')} {port.get('version', '')}".rstrip())
            blocks.append("".join(lines))
        else:
            blocks.append("## Open Ports No open ports detected.")

        if self.state.filtered_ports:
            lines = ["## Filtered Ports"]
            for port in self.state.filtered_ports:
                lines.append(f"- {port['port']}/{port.get('protocol', 'tcp')} : {port.get('service', 'unknown')} ({port.get('state', 'filtered')})")
            blocks.append("".join(lines))
        else:
            blocks.append("## Filtered PortsNo filtered ports detected.")

        if self.state.closed_ports:
            lines = ["## Closed Ports"]
            for port in self.state.closed_ports:
                lines.append(f"- {port['port']}/{port.get('protocol', 'tcp')} : {port.get('service', 'unknown')} ({port.get('state', 'closed')})")
            blocks.append("".join(lines))
        else:
            blocks.append("## Closed Ports No closed ports recorded.")
        return "".join(blocks)

    def _services_section(self) -> str:
        if not self.state.services:
            return "## Service Banners No service banners collected."
        lines = ["## Service Banners"]
        for port, banner in sorted(self.state.services.items()):
            lines.append(f"- Port {port}: {banner}")
        return "".join(lines)

    def _cve_section(self) -> str:
        if not self.state.cve_list:
            return "## CVEs Found No CVEs identified."
        lines = ["## CVEs Found"]
        for cve in self.state.cve_list[:20]:
            lines.append(f"- {cve.get('cve_id')} : {cve.get('description', '')[:150]} [source={cve.get('source_state', 'unknown')}]")
        if len(self.state.cve_list) > 20:
            lines.append(f"... and {len(self.state.cve_list) - 20} more CVEs.")
        return "".join(lines)

    def _credentials_section(self) -> str:
        if not self.state.credentials:
            return "## Credentials Obtained No credentials discovered."
        lines = ["## Credentials Obtained"]
        for cred in self.state.credentials:
            lines.append(f"- {cred.get('username')}:{cred.get('password')} (service: {cred.get('service', 'unknown')}, port: {cred.get('port', 'n/a')})")
        return "".join(lines)

    def _exploit_section(self) -> str:
        if not self.state.exploits:
            return "## Exploits Attempted No exploits executed."
        lines = ["## Exploits Attempted"]
        for exploit in self.state.exploits:
            status = "✓ successful" if exploit.get("success") else "✗ failed"
            lines.append(f"- {exploit.get('exploit_name')} : {status} [source={exploit.get('source_state', 'unknown')}]")
        return "".join(lines)

    def _web_findings_section(self) -> str:
        if not self.state.web_findings:
            return "## Web Findings No web findings collected."
        lines = ["## Web Findings"]
        for finding in self.state.web_findings:
            lines.append(f"- {finding.get('status_code')} {finding.get('url')}")
        return "".join(lines)

    def _wordpress_section(self) -> str:
        if not self.state.wordpress_plugins:
            return "## WordPress Plugins No WordPress plugins identified."
        lines = ["## WordPress Plugins"]
        for plugin in self.state.wordpress_plugins:
            lines.append(f"- {plugin.get('plugin')} : version {plugin.get('version', 'unknown')}")
        return "".join(lines)

    def _errors_section(self) -> str:
        if not self.state.errors:
            return "## Errors No execution errors recorded."
        lines = ["## Errors"]
        for error in self.state.errors:
            lines.append(f"- {error.get('task', 'unknown')}: {error.get('error', 'unknown error')}")
        return "".join(lines)
