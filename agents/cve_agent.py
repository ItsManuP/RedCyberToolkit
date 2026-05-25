import json, re, time, urllib.request, urllib.parse
from typing import Any, Dict, List
from core.base_agent import BaseAgent

SERVICE_CPE_MAP = {
    "apache": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:nginx:nginx",
    "openssh": "cpe:2.3:a:openbsd:openssh",
    "mysql": "cpe:2.3:a:mysql:mysql",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "smb": "cpe:2.3:a:samba:samba",
    "redis": "cpe:2.3:a:redis:redis",
}

OFFLINE_CVE_DB = [
    {"cve_id": "CVE-2021-41773", "service": "apache", "version_pattern": r"2\.4\.4[89]",
     "description": "Path traversal e RCE in Apache HTTP Server 2.4.49", "cvss_score": 9.8,
     "severity": "CRITICAL", "exploit_available": True},
    {"cve_id": "CVE-2021-42013", "service": "apache", "version_pattern": r"2\.4\.4[89]",
     "description": "Path traversal bypass in Apache 2.4.49/2.4.50", "cvss_score": 9.8,
     "severity": "CRITICAL", "exploit_available": True},
    {"cve_id": "CVE-2023-38408", "service": "ssh", "version_pattern": r"OpenSSH_[0-8]\.",
     "description": "Remote code execution in ssh-agent (OpenSSH < 9.3p2)", "cvss_score": 9.8,
     "severity": "CRITICAL", "exploit_available": True},
    {"cve_id": "CVE-2017-0144", "service": "smb", "version_pattern": r".*",
     "description": "EternalBlue — SMBv1 RCE", "cvss_score": 8.1, "severity": "HIGH",
     "exploit_available": True},
]

class CVEAgent(BaseAgent):
    name = "cve"
    description = "CVE lookup, CVSS scoring, ExploitDB matching"
    phase = "CVE_CHECK"
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def run(self, state: Any, params: Dict) -> Dict:
        ports = state.open_ports
        use_api = params.get("use_api", False)
        max_results = params.get("max_results", 20)
        self.log(f"Analisi {len(ports)} servizi rilevati")
        all_cves = []

        for port_info in ports:
            service = port_info.get("service", "").lower()
            version = port_info.get("version", "")
            port_num = port_info.get("port")
            self.log(f"  Controllo {service} {version} (porta {port_num})")
            offline_hits = self._offline_lookup(service, version)
            all_cves.extend(offline_hits)
            if use_api and version:
                api_hits = self._nvd_lookup(service, version, max_results=5)
                existing_ids = {c["cve_id"] for c in all_cves}
                for hit in api_hits:
                    if hit["cve_id"] not in existing_ids:
                        all_cves.append(hit)
                time.sleep(0.6)

        seen = set()
        unique_cves = []
        for cve in all_cves:
            if cve["cve_id"] not in seen:
                seen.add(cve["cve_id"])
                unique_cves.append(cve)
        unique_cves.sort(key=lambda c: c.get("cvss_score", 0), reverse=True)

        critical = [c for c in unique_cves if c.get("severity") == "CRITICAL"]
        high = [c for c in unique_cves if c.get("severity") == "HIGH"]
        self.log(f"CVE trovate: {len(unique_cves)} (CRITICAL: {len(critical)}, HIGH: {len(high)})")
        return {
            "cves": unique_cves, "total": len(unique_cves),
            "critical_count": len(critical), "high_count": len(high),
            "exploit_available_count": sum(1 for c in unique_cves if c.get("exploit_available")),
            "top_cve": unique_cves[0] if unique_cves else None,
        }

    def _offline_lookup(self, service: str, version: str) -> List[Dict]:
        matches = []
        for entry in OFFLINE_CVE_DB:
            if entry["service"] not in service and service not in entry["service"]:
                continue
            if version and entry.get("version_pattern"):
                if not re.search(entry["version_pattern"], version, re.IGNORECASE):
                    continue
            matches.append(dict(entry))
        return matches

    def _nvd_lookup(self, service: str, version: str, max_results: int = 5) -> List[Dict]:
        keyword = f"{service} {version}".strip()
        params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": max_results})
        url = f"{self.NVD_API}?{params}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RedTeamToolkit/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            return [self._parse_nvd_item(v) for v in data.get("vulnerabilities", [])]
        except Exception as e:
            self.log(f"NVD API non raggiungibile: {e}")
            return []

    def _parse_nvd_item(self, item: Dict) -> Dict:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cvss_score = 0.0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cvss_score = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                break
        severity = "CRITICAL" if cvss_score >= 9.0 else "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW" if cvss_score > 0 else "NONE"
        return {"cve_id": cve_id, "description": desc[:200], "cvss_score": cvss_score,
                "severity": severity, "exploit_available": False, "service": "api_result"}