# core/agents.py
import subprocess
import socket
import requests
from typing import Dict, List, Any

class PortScannerAgent:
    """Scans for open ports using nmap (or fallback to socket)."""
    name = "port_scanner"

    def run(self, state) -> Dict[str, Any]:
        target = state.ip
        ports = []
        try:
            # Try nmap first (more reliable)
            result = subprocess.run(
                ["nmap", "-p-", "--min-rate=1000", "-T4", target],
                capture_output=True, text=True, timeout=60
            )
            # Parse nmap output (simplified)
            for line in result.stdout.splitlines():
                if "/tcp" in line or "/udp" in line:
                    parts = line.split()
                    port_proto = parts[0]
                    port = int(port_proto.split('/')[0])
                    proto = port_proto.split('/')[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    ports.append({"port": port, "protocol": proto, "service": service})
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback to basic socket scan on common ports
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((target, port)) == 0:
                    ports.append({"port": port, "protocol": "tcp", "service": "unknown"})
                sock.close()
        return {"ports": ports}

class ServiceDetectorAgent:
    """Detects service versions on open ports."""
    name = "service_detector"

    def run(self, state) -> Dict[str, Any]:
        services = {}
        for port_info in state.open_ports:
            port = port_info["port"]
            try:
                # Simple banner grabbing
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((state.ip, port))
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
                services[port] = banner[:100] if banner else "unknown"
                sock.close()
            except Exception:
                services[port] = "unknown"
        return {"services": services}

class CVECheckerAgent:
    """Checks for CVEs based on services (simulated)."""
    name = "cve_checker"

    def run(self, state) -> Dict[str, Any]:
        cves = []
        # Mock CVE database - in reality you'd call an API like NVD or searchsploit
        known_vulns = {
            "21": ["CVE-2016-6210", "CVE-2019-1287"],  # FTP
            "22": ["CVE-2016-6210", "CVE-2018-15473"], # SSH
            "80": ["CVE-2017-5638", "CVE-2019-0232"], # HTTP
            "443": ["CVE-2014-0160", "CVE-2017-5638"], # HTTPS
            "3306": ["CVE-2012-2122"], # MySQL
        }
        for port_info in state.open_ports:
            port = str(port_info["port"])
            if port in known_vulns:
                for cve_id in known_vulns[port]:
                    cves.append({
                        "cve_id": cve_id,
                        "description": f"Potential {cve_id} on port {port}",
                        "port": port
                    })
        return {"cves": cves}

class BruteForceAgent:
    """Attempts brute force authentication on services."""
    name = "bruteforcer"

    def run(self, state) -> Dict[str, Any]:
        credentials = []
        # Simulated credential discovery (in real tool use hydra or custom logic)
        common_creds = [("admin", "admin"), ("root", "root"), ("user", "password")]
        for port_info in state.open_ports:
            port = port_info["port"]
            service = port_info.get("service", "unknown")
            # Mock: if SSH or HTTP, try default creds
            if service in ["ssh", "http", "https"]:
                for user, passwd in common_creds:
                    credentials.append({
                        "username": user,
                        "password": passwd,
                        "service": service,
                        "port": port
                    })
        return {"credentials": credentials}

class ExploitAgent:
    """Exploits known vulnerabilities."""
    name = "exploiter"

    def run(self, state) -> Dict[str, Any]:
        exploits = []
        # Simulated exploitation
        for cve in state.cve_list:
            if cve["cve_id"] == "CVE-2014-0160":  # Heartbleed
                exploits.append({
                    "exploit_name": "heartbleed",
                    "target": f"{state.ip}:443",
                    "success": False,  # would be real result
                    "details": "Simulated exploit attempt"
                })
            else:
                exploits.append({
                    "exploit_name": f"exploit_{cve['cve_id']}",
                    "target": state.ip,
                    "success": False,
                    "details": "Not implemented"
                })
        return {"exploits": exploits}