import json, time, os
from datetime import datetime
from typing import Any, Dict, List
from core.base_agent import BaseAgent

REMEDIATION_DB = {
    "CVE-2021-41773": "Aggiornare Apache HTTP Server a versione >= 2.4.51 immediatamente.",
    "CVE-2021-42013": "Aggiornare Apache HTTP Server a versione >= 2.4.51.",
    "CVE-2023-38408": "Aggiornare OpenSSH a versione >= 9.3p2.",
    "CVE-2017-0144": "Disabilitare SMBv1. Applicare patch MS17-010.",
    "DEFAULT_CREDS": "Cambiare tutte le credenziali di default. Abilitare MFA.",
}

class ReportAgent(BaseAgent):
    name = "report"
    description = "Finding aggregation, CVSS scoring, remediation, multi-format export"
    phase = "REPORT"

    def run(self, state: Any, params: Dict) -> Dict:
        output_dir = params.get("output_dir", "reports")
        formats = params.get("formats", ["json", "markdown", "txt"])
        os.makedirs(output_dir, exist_ok=True)
        self.log("Aggregazione risultati in corso...")
        report = self._build_report(state)
        self.log(f"Report costruito: {report['summary']['total_findings']} finding totali")
        saved_files = []
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base = f"{output_dir}/report_{state.session_id}_{ts}"
        if "json" in formats:
            with open(f"{base}.json", "w") as f:
                json.dump(report, f, indent=2, default=str)
            saved_files.append(f"{base}.json")
        if "markdown" in formats:
            with open(f"{base}.md", "w", encoding="utf-8") as f:
                f.write(self._to_markdown(report))
            saved_files.append(f"{base}.md")
        if "txt" in formats:
            with open(f"{base}.txt", "w", encoding="utf-8") as f:
                f.write(self._to_text(report))
            saved_files.append(f"{base}.txt")
        return {"report": report, "saved_files": saved_files, "summary": report["summary"]}

    def _build_report(self, state):
        cves = state.cve_list
        credentials = state.credentials
        exploits = state.exploits
        findings = self._collect_findings(cves, credentials, exploits)
        risk = self._compute_risk_score(cves, credentials, exploits)
        return {
            "meta": {"session_id": state.session_id, "target": state.target,
                     "generated_at": datetime.utcnow().isoformat()+"Z",
                     "phases_completed": [p.name for p in state.phases_completed]},
            "summary": {"overall_risk": risk["label"], "cvss_max": risk["max_cvss"], "cvss_avg": risk["avg_cvss"],
                        "total_findings": len(findings), "open_ports": len(state.open_ports),
                        "cves_found": len(cves), "critical_cves": sum(1 for c in cves if c.get("severity")=="CRITICAL"),
                        "credentials_found": len(credentials),
                        "exploits_successful": sum(1 for e in exploits if e.get("success"))},
            "cve_findings": sorted(cves, key=lambda c: c.get("cvss_score",0), reverse=True),
            "credential_findings": credentials,
            "exploit_findings": exploits,
            "all_findings": findings,
            "remediations": self._build_remediations(findings),
            "risk_score": risk,
        }

    def _collect_findings(self, cves, credentials, exploits):
        findings = []
        for cve in cves:
            findings.append({"id": cve["cve_id"], "type": "CVE", "severity": cve.get("severity","UNKNOWN"),
                             "cvss": cve.get("cvss_score",0), "description": cve.get("description","")[:80]})
        for cred in credentials:
            findings.append({"id": f"AUTH-{cred['protocol'].upper()}", "type": "CREDENTIAL", "severity": "CRITICAL",
                             "cvss": 9.0, "description": f"Credenziali trovate: {cred['username']}@{cred['host']}:{cred['port']}"})
        for exp in exploits:
            if exp.get("success"):
                findings.append({"id": exp.get("exploit_id","EXP"), "type": "EXPLOIT", "severity": exp.get("risk","HIGH"),
                                 "cvss": 9.8, "description": f"{exp['name']} confermato su {exp['host']}:{exp['port']}"})
        return sorted(findings, key=lambda f: f.get("cvss",0), reverse=True)

    def _compute_risk_score(self, cves, credentials, exploits):
        scores = [c.get("cvss_score",0) for c in cves]
        if credentials: scores.extend([9.0]*len(credentials))
        if any(e.get("success") for e in exploits): scores.append(9.8)
        if not scores: return {"label":"NONE","max_cvss":0,"avg_cvss":0}
        max_s = max(scores)
        avg_s = round(sum(scores)/len(scores),1)
        label = "NONE" if max_s==0 else "CRITICAL" if max_s>=9.0 else "HIGH" if max_s>=7.0 else "MEDIUM" if max_s>=4.0 else "LOW"
        return {"label": label, "max_cvss": max_s, "avg_cvss": avg_s}

    def _build_remediations(self, findings):
        result, seen = [], set()
        for f in findings:
            for key, rem in REMEDIATION_DB.items():
                if key in f["id"] and key not in seen:
                    seen.add(key)
                    result.append({"finding_id": f["id"], "priority": f["severity"], "action": rem})
        if any(f["type"]=="CREDENTIAL" for f in findings) and "DEFAULT_CREDS" not in seen:
            result.append({"finding_id":"ALL-CREDENTIALS","priority":"CRITICAL","action":REMEDIATION_DB["DEFAULT_CREDS"]})
        return result

    def _to_markdown(self, r):
        lines = [f"# Red Team Report — {r['meta']['target']}",
                 f"**Session:** `{r['meta']['session_id']}` | **Date:** {r['meta']['generated_at']}",
                 "", "## Summary", "", f"| Risk Level | **{r['summary']['overall_risk']}** |",
                 f"| CVE Trovate | {r['summary']['cves_found']} (Critical: {r['summary']['critical_cves']}) |",
                 f"| Credenziali | {r['summary']['credentials_found']} |",
                 f"| Exploit OK | {r['summary']['exploits_successful']} |",
                 "", "## Remediation", "", "| Priorità | Azione |", "|---|---|"]
        for rem in r["remediations"]:
            lines.append(f"| **{rem['priority']}** | {rem['action']} |")
        return "\n".join(lines)

    def _to_text(self, r):
        SEP = "="*60
        lines = [SEP, "RED TEAM REPORT", f"Target  : {r['meta']['target']}",
                 f"Session : {r['meta']['session_id']}", SEP,
                 f"RISK LEVEL : {r['summary']['overall_risk']}",
                 f"CVE        : {r['summary']['cves_found']}",
                 f"CREDS      : {r['summary']['credentials_found']}",
                 f"EXPLOITS   : {r['summary']['exploits_successful']}",
                 SEP, "REMEDIATION", SEP]
        for i,rem in enumerate(r["remediations"],1):
            lines.append(f"{i}. [{rem['priority']}] {rem['action']}")
        return "\n".join(lines)