# core/agents.py
import subprocess
import socket
import shutil
import time
import concurrent.futures
import re
from typing import Dict, List, Any, Optional

# ============================================================================
# Base Agent (optional, for consistency)
# ============================================================================
class BaseAgent:
    """Base class for all agents."""
    name = "base"
    description = "Base agent"
    def log(self, msg: str):
        print(f"[{self.name}] {msg}")
    def run(self, state, params: dict) -> dict:
        raise NotImplementedError

# ============================================================================
# Port Scanner Agent (uses nmap with common ports or custom range)
# ============================================================================
class PortScannerAgent(BaseAgent):
    name = "port_scanner"
    description = "Scans target ports using nmap"

    # List of common ports to scan by default (much faster and reliable than full range)
    DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"

    def run(self, state, params: dict = None) -> dict:
        target = state.ip
        self.log(f"Starting port scan on {target}")

        if not shutil.which("nmap"):
            self.log("nmap not found, falling back to socket scan")
            return self._socket_scan(target, params)

        if params is None:
            params = {}
        
        # Use custom port range/list if provided, otherwise use common ports
        port_range = params.get("port_range")
        if not port_range:
            port_range = self.DEFAULT_PORTS
            self.log(f"No port_range specified, using common ports: {port_range}")
        
        use_syn = params.get("use_syn_scan", False)

        cmd = ["nmap", "-sV", "--min-rate=1000", "-T4"]
        cmd.append("-sT" if not use_syn else "-sS")
        cmd += ["-p", port_range, target]

        try:
            self.log(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            if result.returncode != 0:
                self.log(f"nmap error (code {result.returncode}): {result.stderr[:200]}")
                return self._socket_scan(target, params)

            ports = self._parse_nmap_text(result.stdout)
            self.log(f"Found {len(ports)} open ports")
            if ports:
                for p in ports[:5]:
                    self.log(f"  {p['port']}/{p['protocol']} {p['service']} {p['version']}")
            else:
                # If no ports found and port_range is not the full common list, try common ports
                if port_range != self.DEFAULT_PORTS and port_range != "1-1000":
                    self.log("No ports found, falling back to common ports list")
                    return self.run(state, {"port_range": self.DEFAULT_PORTS, "use_syn_scan": use_syn})
            return {"ports": ports}

        except subprocess.TimeoutExpired:
            self.log("nmap scan timed out")
            return self._socket_scan(target, params)
        except Exception as e:
            self.log(f"Unexpected error: {e}")
            return self._socket_scan(target, params)

    def _parse_nmap_text(self, output: str) -> List[Dict]:
        """Extract open ports from nmap text output."""
        ports = []
        lines = output.splitlines()
        for line in lines:
            # Match lines like: "80/tcp   open  http    nginx 1.18.0"
            # or: "443/tcp  open  https   nginx"
            match = re.search(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
            if match:
                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3)
                version = match.group(4) if match.group(4) else ""
                ports.append({
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version.strip()
                })
        return ports

    def _socket_scan(self, target: str, params: dict) -> dict:
        common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
        open_ports = []
        self.log(f"Fallback socket scan on {len(common_ports)} common ports")
        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                if s.connect_ex((target, port)) == 0:
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "service": "unknown",
                        "version": ""
                    })
                s.close()
            except:
                pass
        return {"ports": open_ports}

# ============================================================================
# Service Detector Agent (banner grabbing)
# ============================================================================
class ServiceDetectorAgent(BaseAgent):
    name = "service_detector"
    description = "Grabs banners and refines service versions"

    def run(self, state, params: dict = None) -> dict:
        target = state.ip
        services = {}
        for port_info in state.open_ports:
            port = port_info["port"]
            banner = self._grab_banner(target, port)
            if banner:
                services[port] = banner[:200]
                self.log(f"Port {port}: {banner[:80]}")
        return {"services": services}

    def _grab_banner(self, ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in [21,22,23,25,80,443,3306,5432]:
                s.send(b"\r\n")
            banner = s.recv(256).decode(errors="ignore").strip()
            s.close()
            return banner
        except:
            return None

# ============================================================================
# CVE Checker Agent (mock database, can be extended with NVD API)
# ============================================================================
class CVECheckerAgent(BaseAgent):
    name = "cve_checker"
    description = "Checks for known CVEs based on services and versions"

    def run(self, state, params: dict = None) -> dict:
        cves = []
        # Mock CVE database (service -> [(version_range, cve_id, description)])
        vuln_db = {
            "ssh": [("OpenSSH 7.2-9.3", "CVE-2023-38408", "SSH pre-auth RCE")],
            "http": [("nginx 1.14-1.20", "CVE-2021-23017", "HTTP request smuggling")],
            "mysql": [("5.7.0-5.7.20", "CVE-2012-2122", "Authentication bypass")],
        }
        for port_info in state.open_ports:
            service = port_info.get("service", "")
            version = port_info.get("version", "")
            for svc_key, vulns in vuln_db.items():
                if svc_key in service.lower():
                    for vrange, cve_id, desc in vulns:
                        cves.append({
                            "cve_id": cve_id,
                            "description": desc,
                            "service": service,
                            "port": port_info["port"],
                            "version_range": vrange
                        })
        self.log(f"Found {len(cves)} potential CVEs")
        return {"cves": cves}

# ============================================================================
# Brute Force Agent (threaded)
# ============================================================================
class BruteForceAgent(BaseAgent):
    name = "bruteforcer"
    description = "Attempts brute force on SSH/HTTP/FTP with threading"

    def run(self, state, params: dict = None) -> dict:
        if params is None:
            params = {}
        max_attempts = params.get("max_attempts", 100)
        stop_on_first = params.get("stop_on_first", False)
        credentials = []
        tested = 0

        # Common credentials to try
        wordlist = [
            ("admin", "admin"), ("root", "root"), ("user", "password"),
            ("admin", "password"), ("root", "toor"), ("test", "test"),
            ("administrator", "admin"), ("admin", "123456")
        ][:max_attempts]

        for port_info in state.open_ports:
            port = port_info["port"]
            service = port_info.get("service", "").lower()
            proto = None
            if service in ["ssh", "http", "https", "ftp"]:
                proto = service
            elif port == 22: proto = "ssh"
            elif port == 80 or port == 443: proto = "http"
            elif port == 21: proto = "ftp"
            else: continue

            self.log(f"Brute-forcing {proto} on {state.ip}:{port}")
            for user, pwd in wordlist:
                tested += 1
                success = self._try_login(proto, state.ip, port, user, pwd)
                if success:
                    entry = {"username": user, "password": pwd, "service": proto, "port": port}
                    credentials.append(entry)
                    self.log(f"[HIT] {user}:{pwd} on {proto}:{port}")
                    if stop_on_first:
                        return {"credentials": credentials, "total_tested": tested}
                time.sleep(0.1)
        return {"credentials": credentials, "total_tested": tested}

    def _try_login(self, proto: str, host: str, port: int, user: str, pwd: str) -> bool:
        # Simplified simulation
        if proto == "http" and user == "admin" and pwd == "admin":
            return True
        if proto == "ssh" and user == "root" and pwd == "root":
            return True
        return False

# ============================================================================
# Exploit Agent (simulated)
# ============================================================================
class ExploitAgent(BaseAgent):
    name = "exploiter"
    description = "Attempts exploitation of known CVEs"

    def run(self, state, params: dict = None) -> dict:
        exploits = []
        for cve in state.cve_list:
            cve_id = cve.get("cve_id")
            success = (cve_id == "CVE-2012-2122")
            exploits.append({
                "exploit_name": f"exploit_{cve_id}",
                "cve_id": cve_id,
                "success": success,
                "details": f"Attempted {cve_id} on {state.ip}"
            })
            self.log(f"Exploit {cve_id}: {'success' if success else 'failed'}")
        return {"exploits": exploits}

# ============================================================================
# Traffic Agent (web endpoint probing)
# ============================================================================
class TrafficAgent(BaseAgent):
    name = "traffic"
    description = "Probes HTTP/HTTPS endpoints for sensitive paths"

    def run(self, state, params: dict = None) -> dict:
        if params is None:
            params = {}
        endpoints = params.get("endpoints", [
            "/", "/admin", "/api", "/.env", "/.git/config", "/phpinfo.php",
            "/wp-admin", "/wp-login.php", "/actuator/env", "/server-status"
        ])
        findings = []
        for port_info in state.open_ports:
            port = port_info["port"]
            if port_info.get("service") in ["http", "https"] or port in [80,443,8080,8443]:
                protocol = "https" if port == 443 else "http"
                self.log(f"Probing {protocol}://{state.ip}:{port}")
                for path in endpoints:
                    url = f"{protocol}://{state.ip}:{port}{path}"
                    code = self._fetch_status(url)
                    if code and code < 500:
                        findings.append({"url": url, "status_code": code})
                        self.log(f"  {code} {url}")
        return {"web_findings": findings}

    def _fetch_status(self, url: str, timeout: float = 3.0) -> Optional[int]:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except:
            return None

# ============================================================================
# WordPress Enumeration Agent (max effort)
# ============================================================================
class WPAgent(BaseAgent):
    name = "wp_enum"
    description = "WordPress plugin enumerator with version extraction"

    def run(self, state, params: dict = None) -> dict:
        if params is None:
            params = {}
        custom_host = params.get("custom_host")
        target = custom_host if custom_host else state.ip
        protocol = "https" if 443 in [p["port"] for p in state.open_ports] else "http"
        base_url = f"{protocol}://{target}"

        plugins = [
            "all-in-one-wp-security-and-firewall", "woocommerce", "elementor", "jetpack",
            "updraftplus", "w3-total-cache", "akismet", "contact-form-7", "yoast-seo"
        ]
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_plugin, base_url, p): p for p in plugins}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
                    self.log(f"Found plugin: {res['plugin']} version {res.get('version','?')}")
        return {"wordpress_plugins": results, "findings": results}

    def _check_plugin(self, base_url: str, plugin_slug: str) -> Optional[Dict]:
        readme_url = f"{base_url}/wp-content/plugins/{plugin_slug}/readme.txt"
        try:
            import urllib.request
            req = urllib.request.Request(readme_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    content = resp.read().decode(errors="ignore")
                    version = self._extract_version(content)
                    return {"plugin": plugin_slug, "version": version, "readme_url": readme_url}
        except:
            pass
        return None

    def _extract_version(self, content: str) -> Optional[str]:
        import re
        match = re.search(r"Stable tag:\s*([0-9.]+)", content)
        return match.group(1) if match else None

# ============================================================================
# Report Agent (generates final report)
# ============================================================================
class ReportAgent(BaseAgent):
    name = "report"
    description = "Generates final report in various formats"

    def run(self, state, params: dict = None) -> dict:
        if params is None:
            params = {}
        output_dir = params.get("output_dir", "reports")
        formats = params.get("formats", ["json", "markdown"])
        import os, json
        os.makedirs(output_dir, exist_ok=True)
        session_id = getattr(state, "session_id", "unknown")
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_data = {
            "target": state.target,
            "ip": state.ip,
            "open_ports": state.open_ports,
            "cves": state.cve_list,
            "credentials": state.credentials,
            "exploits": state.exploits,
            "web_findings": getattr(state, "web_findings", [])
        }
        for fmt in formats:
            if fmt == "json":
                path = os.path.join(output_dir, f"report_{session_id}_{timestamp}.json")
                with open(path, "w") as f:
                    json.dump(report_data, f, indent=2)
                self.log(f"JSON report saved to {path}")
            elif fmt == "markdown":
                path = os.path.join(output_dir, f"report_{session_id}_{timestamp}.md")
                with open(path, "w") as f:
                    f.write(self._markdown_report(report_data))
                self.log(f"Markdown report saved to {path}")
        return {"reports_generated": formats, "output_dir": output_dir}

    def _markdown_report(self, data: dict) -> str:
        lines = [f"# RedTeam Report: {data['target']} ({data['ip']})", ""]
        lines.append("## Open Ports")
        for p in data['open_ports']:
            lines.append(f"- {p['port']}/{p.get('protocol','tcp')} : {p.get('service','unknown')} {p.get('version','')}")
        lines.append("")
        lines.append("## CVEs Found")
        for c in data['cves']:
            lines.append(f"- {c.get('cve_id')} : {c.get('description','')}")
        lines.append("")
        lines.append("## Credentials")
        for cred in data['credentials']:
            lines.append(f"- {cred.get('username')}:{cred.get('password')} ({cred.get('service')})")
        lines.append("")
        lines.append("## Exploits")
        for e in data['exploits']:
            lines.append(f"- {e.get('exploit_name')} : {'SUCCESS' if e.get('success') else 'FAIL'}")
        return "\n".join(lines)