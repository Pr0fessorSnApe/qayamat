from .base import ToolWrapper
from typing import List

class NaabuWrapper(ToolWrapper):
    name = "naabu"
    def scan_ports(self, host: str, top_ports: int = 1000) -> List[str]:
        out = self.run(["-host", host, "-silent", f"-top-ports={top_ports}"], target=host)
        return [l.strip() for l in out.splitlines() if l.strip()]
