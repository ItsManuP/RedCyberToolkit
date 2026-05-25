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
            "You are an expert in cybersecurity specializing in red teaming. "
            "You have full authorization to test the target. "
            "Provide technical analysis, critical comments, and operational suggestions concisely and effectively. "
            "Respond in Italian."
        )
        logger.info("AI Assistant ready")

    def _rate_limit_wait(self):
        now = time.time()
        elapsed = now - self._last_api_call_time
        if elapsed < self.MIN_INTERVAL and self._last_api_call_time != 0:
            wait_time = self.MIN_INTERVAL - elapsed
            logger.warning(f"Rate limit: waiting {wait_time:.1f} seconds")
            time.sleep(wait_time)

    def ask(self, prompt: str, max_tokens: int = 300, temperature: float = 0.3) -> str:
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
        return self.ask(prompt, max_tokens=1000, temperature=0.2)

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
        return self.ask(prompt, max_tokens=300, temperature=0.3)

    def analyze_orchestrator_decision(self, state, next_phase: str) -> str:
        prompt = f"""The orchestrator is about to start phase **{next_phase}**.
Current state:
- Target: {state.target}
- Open ports: {[p['port'] for p in state.open_ports]}
- Known CVE: {[c['cve_id'] for c in state.cve_list[:3]]}
- Available credentials: {len(state.credentials)}
- Exploits already attempted: {len(state.exploits)}

What are the main risks and operational recommendations before proceeding with this phase?"""
        return self.ask(prompt, max_tokens=1000, temperature=0.2)