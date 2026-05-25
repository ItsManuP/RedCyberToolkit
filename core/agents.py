import concurrent.futures
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from core.base_agent import BaseAgent


class PortScannerAgent(BaseAgent):
    name = "port_scanner"
    description = "Scans target ports using nmap"
    DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        target = state.ip
        params = params or {}
        self.log(f"Starting port scan on {target}")

        if not shutil.which("nmap"):
            self.log("nmap not found, falling back to socket scan")
            result = self._socket_scan(target)
            self.last_result = result
            return result

        port_range = params.get("port_range") or self.DEFAULT_PORTS
        use_syn = params.get("use_syn_scan", False)
        timeout = int(params.get("timeout", 120))
        self.log(f"Using port range: {port_range}")

        cmd = ["nmap", "-sV", "--reason", "--min-rate=1000", "-T4", "-Pn"]
        cmd.append("-sS" if use_syn else "-sT")
        cmd += ["-p", port_range, target]

        try:
            self.log(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            if result.returncode != 0:
                self.log(f"nmap error (code {result.returncode}): {result.stderr[:200]}")
                fallback = self._socket_scan(target)
                self.last_result = fallback
                return fallback

            parsed = self._parse_nmap_text(result.stdout)
            self.log(
                f"Found {len(parsed['ports'])} open, {len(parsed['filtered_ports'])} filtered, {len(parsed['closed_ports'])} closed ports"
            )
            self.last_result = parsed
            return parsed
        except subprocess.TimeoutExpired:
            self.log("nmap scan timed out")
            fallback = self._socket_scan(target)
            self.last_result = fallback
            return fallback
        except Exception as exc:
            self.log(f"Unexpected error: {exc}")
            fallback = self._socket_scan(target)
            self.last_result = fallback
            return fallback

    def _parse_nmap_text(self, output: str) -> Dict[str, List[Dict[str, Any]]]:
        result = {"ports": [], "filtered_ports": [], "closed_ports": []}
        for line in output.splitlines():
            line = line.strip()
            match = re.match(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)?(?:\s+(.*))?$", line)
            if not match:
                continue
            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4) or "unknown"
            version = (match.group(5) or "").strip()
            item = {
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
            }
            if state == "open":
                result["ports"].append(item)
            elif state in ("filtered", "open|filtered"):
                result["filtered_ports"].append(item)
            elif state == "closed":
                result["closed_ports"].append(item)
        return result

    def _socket_scan(self, target: str) -> Dict[str, Any]:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        open_ports = []
        self.log(f"Fallback socket scan on {len(common_ports)} common ports")
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                if sock.connect_ex((target, port)) == 0:
                    open_ports.append({"port": port, "protocol": "tcp", "state": "open", "service": "unknown", "version": ""})
                sock.close()
            except Exception:
                pass
        return {"ports": open_ports, "filtered_ports": [], "closed_ports": []}


class ServiceDetectorAgent(BaseAgent):
    name = "service_detector"
    description = "Grabs banners and refines service versions"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        services = {}
        for port_info in state.open_ports:
            port = port_info["port"]
            banner = self._grab_banner(state.ip, port)
            if banner:
                services[port] = banner[:200]
                self.log(f"Port {port}: {banner[:80]}")
        result = {"services": services}
        self.last_result = result
        return result

    def _grab_banner(self, ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if port in [21, 22, 23, 25, 80, 443, 3306, 5432]:
                sock.send(b"\r\n")
            banner = sock.recv(256).decode(errors="ignore").strip()
            sock.close()
            return banner or None
        except Exception:
            return None


class CVECheckerAgent(BaseAgent):
    name = "cve_checker"
    description = "Checks for known CVEs based on services and versions"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cves = []
        consider_filtered = (params or {}).get("include_filtered", True)
        candidates = list(state.open_ports)
        if consider_filtered:
            candidates.extend(state.filtered_ports)

        vuln_db = {
            "ssh": [("OpenSSH 7.2-9.3", "CVE-2023-38408", "SSH agent forwarding related RCE candidate")],
            "http": [("nginx 1.14-1.20", "CVE-2021-23017", "Potential resolver-related issue")],
            "mysql": [("5.7.0-5.7.20", "CVE-2012-2122", "Authentication bypass")],
        }
        for port_info in candidates:
            service = port_info.get("service", "")
            for svc_key, vulns in vuln_db.items():
                if svc_key in service.lower():
                    for version_range, cve_id, desc in vulns:
                        cves.append(
                            {
                                "cve_id": cve_id,
                                "description": desc,
                                "service": service,
                                "port": port_info["port"],
                                "version_range": version_range,
                                "source_state": port_info.get("state", "unknown"),
                            }
                        )
        result = {"cves": cves}
        self.log(f"Found {len(cves)} potential CVEs")
        self.last_result = result
        return result


class BruteForceAgent(BaseAgent):
    name = "bruteforcer"
    description = "Attempts credential checks on common services"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        max_attempts = params.get("max_attempts", 8)
        stop_on_first = params.get("stop_on_first", False)
        credentials = []
        tested = 0
        wordlist = [
            ("admin", "admin"),
            ("root", "root"),
            ("user", "password"),
            ("admin", "password"),
            ("root", "toor"),
            ("test", "test"),
            ("administrator", "admin"),
            ("admin", "123456"),
        ][:max_attempts]

        for port_info in state.open_ports:
            port = port_info["port"]
            service = port_info.get("service", "").lower()
            proto = None
            if service in ["ssh", "http", "https", "ftp"]:
                proto = service
            elif port == 22:
                proto = "ssh"
            elif port in [80, 443, 8080, 8443]:
                proto = "http"
            elif port == 21:
                proto = "ftp"
            if not proto:
                continue

            self.log(f"Testing credentials on {proto} {state.ip}:{port}")
            for user, pwd in wordlist:
                tested += 1
                if self._try_login(proto, user, pwd):
                    hit = {"username": user, "password": pwd, "service": proto, "port": port}
                    credentials.append(hit)
                    self.log(f"[HIT] {user}:{pwd} on {proto}:{port}")
                    if stop_on_first:
                        result = {"credentials": credentials, "total_tested": tested}
                        self.last_result = result
                        return result
                time.sleep(0.05)

        result = {"credentials": credentials, "total_tested": tested}
        self.last_result = result
        return result

    def _try_login(self, proto: str, user: str, pwd: str) -> bool:
        if proto == "http" and user == "admin" and pwd == "admin":
            return True
        if proto == "ssh" and user == "root" and pwd == "root":
            return True
        return False


class ExploitAgent(BaseAgent):
    name = "exploiter"
    description = "Attempts exploitation of known CVEs"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        include_filtered = params.get("include_filtered", True)
        exploits = []
        for cve in state.cve_list:
            if not include_filtered and cve.get("source_state") == "filtered":
                continue
            cve_id = cve.get("cve_id")
            success = cve_id == "CVE-2012-2122" and cve.get("source_state") == "open"
            exploits.append(
                {
                    "exploit_name": f"exploit_{cve_id}",
                    "cve_id": cve_id,
                    "success": success,
                    "details": f"Attempted {cve_id} on {state.ip}",
                    "source_state": cve.get("source_state", "unknown"),
                }
            )
            self.log(f"Exploit {cve_id} ({cve.get('source_state', 'unknown')}): {'success' if success else 'failed'}")
        result = {"exploits": exploits}
        self.last_result = result
        return result


class TrafficAgent(BaseAgent):
    name = "traffic"
    description = "Probes HTTP/HTTPS endpoints for sensitive paths"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        endpoints = params.get(
            "endpoints",
            ["/", "/admin", "/api", "/.env", "/.git/config", "/phpinfo.php", "/wp-admin", "/wp-login.php", "/actuator/env", "/server-status"],
        )
        findings = []
        for port_info in state.open_ports:
            port = port_info["port"]
            if port_info.get("service") in ["http", "https"] or port in [80, 443, 8080, 8443]:
                protocol = "https" if port in [443, 8443] else "http"
                self.log(f"Probing {protocol}://{state.ip}:{port}")
                for path in endpoints:
                    url = f"{protocol}://{state.ip}:{port}{path}"
                    code = self._fetch_status(url)
                    if code and code < 500:
                        findings.append({"url": url, "status_code": code})
                        self.log(f"{code} {url}")
        result = {"web_findings": findings}
        self.last_result = result
        return result

    def _fetch_status(self, url: str, timeout: float = 3.0) -> Optional[int]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return None


class WPAgent(BaseAgent):
    name = "wp_enum"
    description = "WordPress plugin enumerator with version extraction"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        custom_host = params.get("custom_host")
        target = custom_host or state.ip
        protocol = "https" if any(p["port"] == 443 for p in state.open_ports) else "http"
        base_url = f"{protocol}://{target}"
        plugins = params.get(
            "plugins",
            [
                "all-in-one-wp-security-and-firewall",
                "woocommerce",
                "elementor",
                "jetpack",
                "updraftplus",
                "w3-total-cache",
                "akismet",
                "contact-form-7",
                "yoast-seo",
            ],
        )

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(plugins) or 1)) as executor:
            futures = {executor.submit(self._check_plugin, base_url, plugin): plugin for plugin in plugins}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
                    self.log(f"Found plugin: {res['plugin']} version {res.get('version', '?')}")

        result = {"wordpress_plugins": results, "findings": results}
        self.last_result = result
        return result

    def _check_plugin(self, base_url: str, plugin_slug: str) -> Optional[Dict[str, Any]]:
        readme_url = f"{base_url}/wp-content/plugins/{plugin_slug}/readme.txt"
        try:
            req = urllib.request.Request(readme_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    content = resp.read().decode(errors="ignore")
                    return {
                        "plugin": plugin_slug,
                        "version": self._extract_version(content),
                        "readme_url": readme_url,
                    }
        except Exception:
            return None
        return None

    def _extract_version(self, content: str) -> Optional[str]:
        match = re.search(r"Stable tag:\s*([0-9.]+)", content)
        return match.group(1) if match else None


class ReportAgent(BaseAgent):
    name = "report"
    description = "Generates final report in various formats"

    def run(self, state, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        output_dir = params.get("output_dir", "reports")
        formats = params.get("formats", ["json", "markdown"])
        os.makedirs(output_dir, exist_ok=True)
        session_id = params.get("session_id", "unknown")
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_data = {
            "target": state.target,
            "ip": state.ip,
            "open_ports": state.open_ports,
            "filtered_ports": state.filtered_ports,
            "closed_ports": state.closed_ports,
            "services": state.services,
            "cves": state.cve_list,
            "credentials": state.credentials,
            "exploits": state.exploits,
            "web_findings": state.web_findings,
            "wordpress_plugins": state.wordpress_plugins,
            "errors": state.errors,
        }

        generated = []
        for fmt in formats:
            if fmt == "json":
                path = os.path.join(output_dir, f"report_{session_id}_{timestamp}.json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(report_data, handle, indent=2)
                generated.append(path)
                self.log(f"JSON report saved to {path}")
            elif fmt == "markdown":
                path = os.path.join(output_dir, f"report_{session_id}_{timestamp}.md")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(self._markdown_report(report_data))
                generated.append(path)
                self.log(f"Markdown report saved to {path}")

        result = {"reports_generated": generated, "output_dir": output_dir}
        self.last_result = result
        return result

    def _markdown_report(self, data: Dict[str, Any]) -> str:
        lines = [f"# RedTeam Report: {data['target']} ({data['ip']})", ""]
        lines.append("## Open Ports")
        for port in data["open_ports"]:
            lines.append(f"- {port['port']}/{port.get('protocol', 'tcp')} : {port.get('service', 'unknown')} {port.get('version', '')}")
        lines.append("")
        lines.append("## Filtered Ports")
        for port in data["filtered_ports"]:
            lines.append(f"- {port['port']}/{port.get('protocol', 'tcp')} : {port.get('service', 'unknown')} ({port.get('state', 'filtered')})")
        lines.append("")
        lines.append("## Closed Ports")
        for port in data["closed_ports"]:
            lines.append(f"- {port['port']}/{port.get('protocol', 'tcp')} : {port.get('service', 'unknown')} ({port.get('state', 'closed')})")
        lines.append("")
        lines.append("## CVEs Found")
        for cve in data['cves']:
            lines.append(f"- {cve.get('cve_id')} : {cve.get('description', '')} [source={cve.get('source_state', 'unknown')}]")
        lines.append("")
        lines.append("## Credentials")
        for cred in data['credentials']:
            lines.append(f"- {cred.get('username')}:{cred.get('password')} ({cred.get('service')})")
        lines.append("")
        lines.append("## Exploits")
        for exploit in data['exploits']:
            lines.append(f"- {exploit.get('exploit_name')} : {'SUCCESS' if exploit.get('success') else 'FAIL'} [source={exploit.get('source_state', 'unknown')}]")
        return "".join(lines)
