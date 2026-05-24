from .base import ToolWrapper
from typing import List

class AmassWrapper(ToolWrapper):
    name = "amass"
    def enum(self, domain: str) -> List[str]:
        out = self.run(["enum", "-passive", "-d", domain, "-silent"], target=domain)
        return [l.strip() for l in out.splitlines() if l.strip()]
