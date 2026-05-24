"""QAYAMAT — Plugin Base Class"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BasePlugin(ABC):
    name: str = "base"
    version: str = "1.0"
    description: str = ""
    author: str = ""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    @abstractmethod
    def run(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute the plugin.

        context keys:
          - targets: list of in-scope targets
          - profile: testing profile string
          - policy: PolicyEngine instance
          - logger: AuditLogger instance

        Returns a list of finding dicts with keys:
          title, severity, url, vuln_type, description (all optional except title+severity)
        """
        pass

    def validate(self) -> bool:
        """Return True if plugin is properly configured."""
        return True
