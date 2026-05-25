import socket, struct, threading, time, re, urllib.request
from typing import Any, Dict, List, Optional
from core.base_agent import BaseAgent

SECURITY_HEADERS = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
                    "X-Content-Type-Options","Referrer-Policy","Permissions-Policy","X-XSS-Protection"]
PROBE_ENDPOINTS = ["/.git/config","/.env","/config.php","/admin/","/api/","/phpinfo.php","/server-status","/actuator/env"]

class TrafficAgent(BaseAgent):
    name = "traffic"
    description = "HTTP header analysis, endpoint probe, traffic sniff, SSL check"
    phase = "TRAFFIC"

    def run(self, state: Any, params: Dict) -> Dict:
        ip = getattr(state, "ip", state.target)
        ports = state.open_ports
        probe_endpoints = params.get("probe_endpoints", True)
        check_ssl = params.get("check_ssl", True)
        captures, findings = [], []
        for port_info in ports:
            service = port_info.get("service", "").lower()
            port_num = port_info.get("port")
            proto = "https" if port_num in (443,8443) else "http"
            if service in ("http","https") or port_num in (80,443,8080,8443):
                header_result = self._analyze_http_headers(ip, port_num, proto)
                if header_result:
                    findings.append(header_result)
                if probe_endpoints:
                    ep_results = self._probe_endpoints(ip, port_num, proto)
                    findings.extend(ep_results)
                if check_ssl and proto == "https":
                    ssl_result = self._check_ssl(ip, port_num)
                    findings.append(ssl_result)
        critical_findings = [f for f in findings if f.get("severity") in ("CRITICAL","HIGH")]
        self.log(f"Finding totali: {len(findings)} | Critici: {len(critical_findings)}")
        return {"captures": [], "findings": findings, "total_findings": len(findings),
                "critical": len(critical_findings), "missing_headers": self._count_missing_headers(findings)}

    def _analyze_http_headers(self, host: str, port: int, proto: str) -> Optional[Dict]:
        url = f"{proto}://{host}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            ctx = self._ssl_context() if proto == "https" else None
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                headers = dict(resp.getheaders())
        except Exception as e:
            return {"url": url, "error": str(e), "severity": "INFO"}
        missing = [h for h in SECURITY_HEADERS if h.lower() not in {k.lower() for k in headers}]
        severity = "HIGH" if "Strict-Transport-Security" in missing and proto == "http" else "MEDIUM" if len(missing)>=5 else "LOW"
        server = headers.get("Server", headers.get("server", ""))
        self.log(f"    Status: {resp.status} | Server: {server} | Missing headers: {len(missing)}")
        return {"url": url, "status": resp.status, "server_banner": server, "missing_security_headers": missing,
                "severity": severity}

    def _probe_endpoints(self, host: str, port: int, proto: str) -> List[Dict]:
        results = []
        for endpoint in PROBE_ENDPOINTS:
            url = f"{proto}://{host}:{port}{endpoint}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                ctx = self._ssl_context() if proto == "https" else None
                with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
                    status = resp.status
                    body = resp.read(512).decode(errors="replace")
            except urllib.error.HTTPError as e:
                status = e.code
                body = ""
            except Exception:
                continue
            if status in (200,301,302,403):
                severity = "HIGH" if any(k in body.lower() for k in ["password","secret","key"]) else "LOW"
                if status==200 and endpoint in ("/.env","/.git/config","/backup.sql"):
                    severity = "CRITICAL"
                results.append({"endpoint": endpoint, "url": url, "status": status, "severity": severity})
                self.log(f"    [{severity}] {status} {endpoint}")
        return results

    def _check_ssl(self, host: str, port: int) -> Dict:
        import ssl
        result = {"host": host, "port": port, "type": "ssl_check", "severity": "INFO"}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                version = s.version()
                result.update({"tls_version": version, "severity": "HIGH" if version in ("TLSv1","TLSv1.1","SSLv3") else "LOW"})
        except Exception as e:
            result.update({"error": str(e), "severity": "MEDIUM"})
        return result

    def _ssl_context(self):
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _count_missing_headers(self, findings: List[Dict]) -> int:
        return sum(len(f.get("missing_security_headers", [])) for f in findings)