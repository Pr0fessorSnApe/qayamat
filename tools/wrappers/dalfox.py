from .base import ToolWrapper
from typing import List

class DalfoxWrapper(ToolWrapper):
    name = "dalfox"
    def scan(self, url: str) -> List[str]:
        out = self.run(["url", url, "--silence", "--format", "json"], target=url)
        return [l for l in out.splitlines() if l.strip()]
