import ast
import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

from core.log_config import get_logger

load_dotenv()
logger = get_logger("ai_assistant")


class AIAssistant:
    _last_api_call_time = 0.0
    _api_lock = threading.Lock()
    MIN_INTERVAL = 7

    def __init__(self):
        api_key = os.getenv("deepseek_api_key") or os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("Missing API key: set deepseek_api_key or OPENROUTER_API_KEY in .env")

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            default_headers={
                "HTTP-Referer": os.getenv("SITE_URL", "http://localhost"),
                "X-Title": os.getenv("APP_NAME", "RedCyberToolkit"),
            },
        )
        self.model = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat-v3-0324:free")
        self.system_prompt = (
            "You are an expert red-team AI. Guide a controlled assessment pipeline. "
            "Be concise, technical, and respond in Italian. Consider both open and filtered ports in your reasoning, but distinguish reachable services from filtered exposure."
        )
        logger.info("AI Assistant ready")

    def ask(self, prompt: str, max_tokens: int = 2000, temperature: float = 0.2) -> str:
        logger.info("Sending request to OpenRouter...")
        with self._api_lock:
            now = time.time()
            elapsed = now - self._last_api_call_time
            if self._last_api_call_time and elapsed < self.MIN_INTERVAL:
                wait_time = self.MIN_INTERVAL - elapsed
                logger.warning(f"Rate limit: waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)

            start = time.time()
            try:
                completion = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                result = completion.choices[0].message.content.strip()
                elapsed = time.time() - start
                logger.info(f"Response received in {elapsed:.1f}s ({len(result)} characters)")
                AIAssistant._last_api_call_time = time.time()
                return result
            except Exception as exc:
                logger.error(f"API call error: {exc}")
                return f"[AI ERROR] {exc}"

    def analyze_before_task(self, agent_name: str, phase: str, state, params: Dict[str, Any]) -> str:
        prompt = (
            f"We are about to run agent {agent_name} in phase {phase}.\n"
            f"Target: {state.target} ({state.ip})\n"
            f"Open ports: {[p['port'] for p in state.open_ports]}\n"
            f"Filtered ports: {[p['port'] for p in state.filtered_ports]}\n"
            f"Known CVEs: {len(state.cve_list)}\n"
            f"Known credentials: {len(state.credentials)}\n"
            f"Task params: {params}\n"
            "Provide a short operational recommendation."
        )
        return self.ask(prompt)

    def analyze_after_task(self, agent_name: str, phase: str, state, result: Dict[str, Any]) -> str:
        prompt = (
            f"Agent {agent_name} in phase {phase} has completed."
            f"Result summary: {self._summarize_result(result)}"
            f"Updated state: open_ports={len(state.open_ports)}, filtered_ports={len(state.filtered_ports)}, cves={len(state.cve_list)}, creds={len(state.credentials)}"
            "Provide a short technical assessment."
        )
        return self.ask(prompt)

    def plan_next_actions(self, state, last_phase: str, last_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        prompt = (
            "Based on the current assessment state, return only a JSON array of next actions. "
            "Each action must have agent_name and params. Allowed agents: port_scanner, service_detector, cve_checker, bruteforcer, exploiter, traffic, wp_enum, report."
            f"Last phase: {last_phase}"
            f"Last result: {self._summarize_result(last_result)}"
            f"Open ports: {[p['port'] for p in state.open_ports]}"
            f"Filtered ports: {[p['port'] for p in state.filtered_ports]}"
            f"Services: {list(state.services.keys())}"
            f"CVEs: {[c.get('cve_id') for c in state.cve_list]}"
            f"Credentials: {len(state.credentials)}"
            f"WordPress plugins: {[p.get('plugin') for p in state.wordpress_plugins]}"
            "Filtered ports can inform hypotheses and candidate CVEs, but direct service enumeration should prefer open ports."
        )
        response = self.ask(prompt, max_tokens=600, temperature=0.1)
        return self._parse_action_list(response)

    def _parse_action_list(self, response: str) -> List[Dict[str, Any]]:
        if not response or response.startswith("[AI ERROR]"):
            return []
        try:
            parsed = json.loads(response)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            pass
        try:
            parsed = ast.literal_eval(response)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            pass
        match = re.search(r"\[.*\]", response, re.DOTALL)
        if match:
            snippet = match.group(0)
            try:
                parsed = json.loads(snippet)
                return parsed if isinstance(parsed, list) else []
            except Exception:
                try:
                    parsed = ast.literal_eval(snippet)
                    return parsed if isinstance(parsed, list) else []
                except Exception:
                    return []
        return []

    def _summarize_result(self, result: Optional[Dict[str, Any]]) -> str:
        if not result:
            return "No results"
        if "ports" in result or "filtered_ports" in result or "closed_ports" in result:
            return (
                f"open={len(result.get('ports', []))}, filtered={len(result.get('filtered_ports', []))}, "
                f"closed={len(result.get('closed_ports', []))}"
            )
        if "services" in result:
            return f"Collected {len(result['services'])} service banners"
        if "cves" in result:
            return f"Found {len(result['cves'])} CVEs"
        if "credentials" in result:
            return f"Found {len(result['credentials'])} credentials"
        if "exploits" in result:
            success = sum(1 for item in result.get("exploits", []) if item.get("success"))
            return f"{success} successful exploits out of {len(result.get('exploits', []))}"
        if "web_findings" in result:
            return f"Found {len(result['web_findings'])} web findings"
        if "wordpress_plugins" in result:
            return f"Found {len(result['wordpress_plugins'])} WordPress plugins"
        return str(result)[:200]
