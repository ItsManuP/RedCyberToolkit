#!/usr/bin/env python3
"""
RedTeam Toolkit — Entry Point with AI Injection (DeepSeek)
Every task and phase is commented on by a red teaming expert.
"""


import sys, os, argparse
sys.path.insert(0, os.path.dirname(__file__))


from core.ai_orchestrator import AIOrchestrator
from core.orchestrator import AttackPhase
from agents.recon_agent import ReconAgent
from agents.cve_agent import CVEAgent
from agents.auth_agent import AuthAgent
from agents.exploit_agent import ExploitAgent
from agents.traffic_agent import TrafficAgent
from agents.report_agent import ReportAgent
from utils.consent import ask_authorization


BANNER = """
╔══════════════════════════════════════════════════════╗
    RedCyber ToolKIT — AI-Augmented Multi-Agent v1.0   
║   FOR AUTHORIZED PENETRATION TESTING ONLY            ║
                    🤖 DeepSeek                      
╚══════════════════════════════════════════════════════╝
"""


PHASE_MAP = {
    "discovery": AttackPhase.DISCOVERY,
    "cve": AttackPhase.CVE_CHECK,
    "auth": AttackPhase.AUTH_ATTACK,
    "exploit": AttackPhase.EXPLOIT,
    "traffic": AttackPhase.TRAFFIC,
    "report": AttackPhase.REPORT,
}


def build_ai_orchestrator(target: str, authorized: bool, opts: dict) -> AIOrchestrator:
    orch = AIOrchestrator(target=target, authorized=authorized, options=opts)
    orch.register_agent("recon", ReconAgent())
    orch.register_agent("cve", CVEAgent())
    orch.register_agent("auth", AuthAgent())
    orch.register_agent("exploit", ExploitAgent())
    orch.register_agent("traffic", TrafficAgent())
    orch.register_agent("report", ReportAgent())


    # Enqueue standard task
    orch.enqueue(AttackPhase.DISCOVERY, "recon", {"port_range": opts.get("port_range","1-1024"), "use_nmap": opts.get("use_nmap",True)})
    orch.enqueue(AttackPhase.CVE_CHECK, "cve", {"use_api": opts.get("use_nvd_api",False), "max_results":20})
    orch.enqueue(AttackPhase.AUTH_ATTACK, "auth", {"max_attempts": opts.get("max_attempts",100), "protocols":["ssh","ftp","http","mysql","postgresql","redis"]})
    orch.enqueue(AttackPhase.EXPLOIT, "exploit", {"safe_mode": opts.get("safe_mode",True), "max_exploits":15})
    orch.enqueue(AttackPhase.TRAFFIC, "traffic", {"probe_endpoints":True, "check_ssl":True})
    orch.enqueue(AttackPhase.REPORT, "report", {"output_dir":"reports", "formats":["json","markdown","txt"]})
    return orch


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="RedTeam Toolkit with AI injection (DeepSeek)")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--phases", default="all", help="all or a comma-separated list: discovery,cve,auth,exploit,traffic,report")
    parser.add_argument("--port-range", default="1-1024")
    parser.add_argument("--no-nmap", action="store_true")
    parser.add_argument("--safe-mode", action="store_true", default=True)
    parser.add_argument("--use-nvd-api", action="store_true")
    parser.add_argument("--max-attempts", type=int, default=100)
    parser.add_argument("--yes", action="store_true", help="Skip authorization prompt")
    args = parser.parse_args()


    if not args.yes and not ask_authorization(args.target):
        print("\n[ABORT] Authorization not confirmed.")
        sys.exit(1)


    if args.phases == "all":
        phases = list(AttackPhase)
    else:
        phases = [PHASE_MAP[p.strip()] for p in args.phases.split(",") if p.strip() in PHASE_MAP]


    opts = {
        "port_range": args.port_range,
        "use_nmap": not args.no_nmap,
        "safe_mode": args.safe_mode,
        "use_nvd_api": args.use_nvd_api,
        "max_attempts": args.max_attempts,
    }


    orch = build_ai_orchestrator(args.target, authorized=True, opts=opts)
    state = orch.run_pipeline(phases)


    print("\n" + "="*60)
    print("SESSION SUMMARY (with AI)")
    print("="*60)
    for k, v in orch.summary().items():
        print(f"  {k:<25}: {v}")
    print("="*60)


if __name__ == "__main__":
    main()