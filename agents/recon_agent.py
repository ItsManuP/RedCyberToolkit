import socket
import subprocess
import json
import re
from typing import Any, Dict, List
from core.base_agent import BaseAgent

COMMON_PORTS = {
    21:   "FTP", 22:   "SSH", 23:   "Telnet", 25:   "SMTP", 53:   "DNS",
    80:   "HTTP", 110:  "POP3", 143:  "IMAP", 443:  "HTTPS", 445:  "SMB",
    993:  "IMAPS", 995:  "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017:"MongoDB",
}

class ReconAgent(BaseAgent):
    name = "recon"
    description = "Port scanning, OS fingerprinting, service/banner detection"
    phase = "DISCOVERY"

    def run(self, state: Any, params: Dict) -> Dict:
        target = state.target
        port_range = params.get("port_range", "1-1024")
        use_nmap = params.get("use_nmap", True)
        timeout = params.get("timeout", 1.0)

        self.log(f"Target: {target}")
        self.log(f"Porta range: {port_range} | nmap: {use_nmap}")

        ip = self._resolve(target)
        self.log(f"IP risolto: {ip}")

        if use_nmap and self._nmap_available():
            scan_result = self._nmap_scan(ip, port_range)
        else:
            self.log("nmap non disponibile — uso socket scan")
            scan_result = self._socket_scan(ip, port_range, timeout)

        open_ports = scan_result.get("ports", [])
        self.log(f"Porte aperte trovate: {len(open_ports)}")
        for p in open_ports:
            self.log(f"  {p['port']}/{p['proto']} — {p['service']} {p.get('version','')}")

        banners = {}
        for p in open_ports:
            banner = self._grab_banner(ip, p["port"], timeout=timeout)
            if banner:
                banners[p["port"]] = banner
                self.log(f"  Banner {p['port']}: {banner[:60]}")

        os_info = scan_result.get("os", "Unknown")
        hostname = self._reverse_dns(ip)

        result = {
            "target": target, "ip": ip, "hostname": hostname,
            "os": os_info, "ports": open_ports, "banners": banners,
            "total_open": len(open_ports),
        }
        self.log(f"Discovery completata. OS: {os_info} | {len(open_ports)} porte aperte")
        return result

    def _resolve(self, target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return target

    def _reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def _nmap_available(self) -> bool:
        try:
            r = subprocess.run(["nmap", "--version"], capture_output=True, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    def _nmap_scan(self, ip: str, port_range: str) -> Dict:
        self.log(f"Avvio nmap SYN scan su {ip} range {port_range}")
        cmd = ["nmap", "-sS", "-sV", "-O", "--open", "-T4", f"-p{port_range}", "-oX", "-", ip]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return self._parse_nmap_xml(proc.stdout)
        except subprocess.TimeoutExpired:
            self.log("nmap timeout — fallback a socket scan")
            return self._socket_scan(ip, port_range, 1.0)
        except Exception as e:
            self.log(f"nmap errore: {e}")
            return {"ports": [], "os": "Unknown"}

    def _parse_nmap_xml(self, xml: str) -> Dict:
        ports = []
        port_matches = re.findall(
            r'<port protocol="(\w+)" portid="(\d+)">'
            r'.*?<state state="open".*?/>'
            r'.*?<service name="([^"]*)"(?:[^>]*version="([^"]*)")?',
            xml, re.DOTALL
        )
        for proto, portid, svc, ver in port_matches:
            ports.append({
                "port": int(portid), "proto": proto,
                "service": svc or COMMON_PORTS.get(int(portid), "unknown"),
                "version": ver or "",
            })
        os_match = re.search(r'<osmatch name="([^"]+)"', xml)
        os_info = os_match.group(1) if os_match else "Unknown"
        return {"ports": ports, "os": os_info}

    def _socket_scan(self, ip: str, port_range: str, timeout: float) -> Dict:
        start_p, end_p = map(int, port_range.split("-"))
        open_ports = []
        self.log(f"Socket scan {ip} porte {start_p}-{end_p}")
        for port in range(start_p, min(end_p + 1, start_p + 1025)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append({
                            "port": port, "proto": "tcp",
                            "service": COMMON_PORTS.get(port, "unknown"),
                            "version": "",
                        })
            except Exception:
                pass
        return {"ports": open_ports, "os": "Unknown (socket scan — no OS detect)"}

    def _grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                if port in (80, 8080, 8000):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                else:
                    s.send(b"\r\n")
                data = s.recv(1024)
                return data.decode(errors="replace").strip()[:200]
        except Exception:
            return ""