from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class State:
    """Central state container for the orchestration pipeline."""

    target: str
    ip: str
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    filtered_ports: List[Dict[str, Any]] = field(default_factory=list)
    closed_ports: List[Dict[str, Any]] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    cve_list: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    exploits: List[Dict[str, Any]] = field(default_factory=list)
    web_findings: List[Dict[str, Any]] = field(default_factory=list)
    wordpress_plugins: List[Dict[str, Any]] = field(default_factory=list)
    reports: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
