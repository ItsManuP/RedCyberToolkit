from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional


class BaseAgent(ABC):
    name: str = "base"
    description: str = ""
    phase: Optional[str] = None

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._log: List[str] = []
        self.last_result: Dict[str, Any] = {}

    @abstractmethod
    def run(self, state: Any, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the task and return a result dict."""

    def log(self, msg: str) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        entry = f"[{self.name}][{ts}] {msg}"
        self._log.append(entry)
        print(entry)

    def get_log(self) -> List[str]:
        return self._log[:]
