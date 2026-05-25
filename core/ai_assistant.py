# core/ai_assistant.py
import os
import time
from dotenv import load_dotenv
from openai import OpenAI
from core.log_config import get_logger

load_dotenv()
logger = get_logger("ai_assistant")

class AIAssistant:
    _last_api_call_time = 0
    MIN_INTERVAL = 7  # seconds

    def __init__(self):
        api_key = os.getenv("deepseek_api_key")
        if not api_key:
            raise ValueError("deepseek_api_key not found in .env file")
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            default_headers={
                "HTTP-Referer": os.getenv("SITE_URL", "http://localhost"),
                "X-Title": os.getenv("APP_NAME", "RedCyberToolkit"),
            }
        )
        self.model = os.getenv("OPENROUTER_MODEL")
        self.system_prompt = (
        """
            You are an expert red-team AI. Your goal is to guide a penetration testing pipeline.
            You think step by step, like this:

            1. **Discover** open ports and services.
            2. **Interpret** what you see (e.g., redirect to WordPress → change Host header).
            3. **Enumerate** specifics (plugin versions, endpoints).
            4. **Check CVEs** for each component and version.
            5. **Attempt exploitation** only if a reliable vulnerability exists.
            6. **Report** findings and stop if the target is hardened.

            Always justify your next action based on the current state. 
            Be concise but technical. Respond in Italian. 
        """
        )
        logger.info("AI Assistant ready")

    def _rate_limit_wait(self):
        now = time.time()
        elapsed = now - self._last_api_call_time
        if elapsed < self.MIN_INTERVAL and self._last_api_call_time != 0:
            wait_time = self.MIN_INTERVAL - elapsed
            logger.warning(f"Rate limit: waiting {wait_time:.1f} seconds")
            time.sleep(wait_time)

    def ask(self, prompt: str, max_tokens: int = 5000, temperature: float = 0.3) -> str:
        logger.info("Sending request to OpenRouter...")
        self._rate_limit_wait()
        start = time.time()
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            elapsed = time.time() - start
            result = completion.choices[0].message.content.strip()
            logger.info(f"Response received in {elapsed:.1f}s ({len(result)} characters)")
            AIAssistant._last_api_call_time = time.time()
            return result
        except Exception as e:
            logger.error(f"API call error: {e}")
            return f"[AI ERROR] {e}"

    # The following methods use self.ask and do not require additional logging changes
    def analyze_before_task(self, agent_name: str, phase: str, state, params: dict) -> str:
        prompt = f"""We are about to run agent **{agent_name}** in phase **{phase}**.
    Target: {state.target} (IP: {state.ip})
    Ports already discovered: {[p['port'] for p in state.open_ports]}
    CVE already found: {len(state.cve_list)}
    Credentials already found: {len(state.credentials)}
    Task parameters: {params}

    Briefly comment on the strategy, possible risks, or recommendations before proceeding."""
        return self.ask(prompt, max_tokens=5000, temperature=0.2)

    def analyze_after_task(self, agent_name: str, phase: str, state, result: dict) -> str:
        if result:
            if "ports" in result:
                summary = f"Found {len(result['ports'])} open ports"
            elif "cves" in result:
                summary = f"Found {len(result['cves'])} CVE"
            elif "credentials" in result:
                summary = f"Found {len(result['credentials'])} credentials"
            elif "exploits" in result:
                success = sum(1 for e in result.get("exploits", []) if e.get("success"))
                summary = f"{success} successful exploits out of {len(result.get('exploits', []))} attempted"
            else:
                summary = str(result)[:200]
        else:
            summary = "No results"
        prompt = f"""Agent **{agent_name}** (phase {phase}) has completed execution.
Result: {summary}
Updated state: Open ports={len(state.open_ports)}, CVE={len(state.cve_list)}, Credentials={len(state.credentials)}

Provide a technical evaluation of the results and suggest any next steps for the red team."""
        return self.ask(prompt, max_tokens=5000, temperature=0.2)

    def analyze_orchestrator_decision(self, state, next_phase: str) -> str:
        prompt = f"""The orchestrator is about to start phase **{next_phase}**.
Current state:
- Target: {state.target}
- Open ports: {[p['port'] for p in state.open_ports]}
- Known CVE: {[c['cve_id'] for c in state.cve_list[:3]]}
- Available credentials: {len(state.credentials)}
- Exploits already attempted: {len(state.exploits)}

What are the main risks and operational recommendations before proceeding with this phase?"""
        return self.ask(prompt, max_tokens=5000, temperature=0.2)



    def plan_next_actions(self, state, last_phase: str, last_result: dict) -> list:
        """
        Suggests a list of new tasks (agent_name, params) based on current state and last result.
        Returns a list of dicts: [{"agent_name": str, "params": dict}, ...]
        """
        # Creiamo un prompt che include la "storia" recente e uno stile few-shot
        prompt = f"""
    You are an expert red-team orchestrator. Based on the current state and the last phase result,
    suggest the NEXT actions (max 3) as a list of agents to run. Use the following reasoning style:

    === EXAMPLE (few-shot) ===
    Last phase: DISCOVERY
    Result: Ports open: 22(SSH),80(HTTP),443(HTTPS). HTTP redirects to https://chambalmedia.com/wp-signup.php?new=...
    State analysis: Target is a WordPress site behind Nginx. Must use Host: chambalmedia.com.
    Suggested next actions:
    - agent: wp_enum, params: {{"custom_host": "chambalmedia.com", "fuzz_plugins": true}}
    - agent: traffic, params: {{"probe_endpoints": ["/wp-login.php", "/wp-json/"]}}

    Last phase: CVE_CHECK
    Result: Found CVE-2023-38408 (OpenSSH) but target has OpenSSH 9.6 (patched). No other CVEs.
    State analysis: SSH not vulnerable. WordPress plugins unknown.
    Suggested next actions:
    - agent: wp_enum, params: {{"action": "plugin_version_extraction"}}

    Last phase: AUTH_ATTACK
    Result: No credentials found. HTTP basic auth not present.
    State analysis: Brute force blocked by security plugin.
    Suggested next actions:
    - agent: exploit, params: {{"search_cve_for_plugins": ["updraftplus", "w3-total-cache"]}}

    === CURRENT SITUATION ===
    Last phase: {last_phase}
    Last result (summary): {self._summarize_result(last_result)}
    Current state:
    - Target: {state.target}
    - Open ports: {[p['port'] for p in state.open_ports]}
    - Services: {list(state.services.keys())}
    - CVEs found: {[c.get('cve_id') for c in state.cve_list]}
    - Credentials: {len(state.credentials)}
    - Exploits attempted: {len(state.exploits)}
    - Extra info: {getattr(state, 'wp_plugins', [])}   (if any)

    Now produce a JSON-like list of suggested next actions (agent_name, params). Only include agents that exist in your toolkit (recon, cve, auth, exploit, traffic, wp_enum, report). Return ONLY the list, no extra text.
    """
        response = self.ask(prompt, max_tokens=500, temperature=0.2)
        # Parsing della risposta (assumiamo che l'AI restituisca una lista Python valida)
        try:
            import ast
            suggestions = ast.literal_eval(response)
            if isinstance(suggestions, list):
                return suggestions
        except:
            # fallback: estrai con regex semplice
            import re
            match = re.search(r"\[.*\]", response, re.DOTALL)
            if match:
                try:
                    suggestions = ast.literal_eval(match.group())
                    if isinstance(suggestions, list):
                        return suggestions
                except:
                    pass
        return []

    def _summarize_result(self, result: dict) -> str:
        if not result:
            return "No results"
        if "ports" in result:
            return f"Found {len(result['ports'])} open ports"
        if "cves" in result:
            return f"Found {len(result['cves'])} CVEs"
        if "credentials" in result:
            return f"Found {len(result['credentials'])} credentials"
        if "exploits" in result:
            success = sum(1 for e in result.get("exploits",[]) if e.get("success"))
            return f"{success} successful exploits out of {len(result.get('exploits',[]))}"
        return str(result)[:200]