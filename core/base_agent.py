from abc import ABC, abstractmethod
from typing import Any, Dict
from datetime import datetime

class BaseAgent(ABC):
    name: str = "base"
    description: str = ""
    phase: str = ""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self._log: list = []

    @abstractmethod
    def run(self, state: Any, params: Dict) -> Dict:
        """Esegue il task. Riceve SessionState e params, restituisce dict."""

    def log(self, msg: str):
        ts = datetime.utcnow().strftime("%H:%M:%S")
        entry = f"  [{self.name}][{ts}] {msg}"
        self._log.append(entry)
        print(entry)

    def get_log(self) -> list:
        return self._log