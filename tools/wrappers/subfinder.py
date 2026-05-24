from .base import ToolWrapper
from typing import List

class SubfinderWrapper(ToolWrapper):
    name = "subfinder"
    def enumerate(self, domain: str) -> List[str]:
        out = self.run(["-d", domain, "-silent", "-all"], target=domain)
        return [l.strip() for l in out.splitlines() if l.strip()]
