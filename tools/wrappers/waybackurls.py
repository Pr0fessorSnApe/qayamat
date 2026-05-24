from .base import ToolWrapper
from typing import List

class WaybackurlsWrapper(ToolWrapper):
    name = "waybackurls"
    def fetch(self, domain: str) -> List[str]:
        out = self.run([domain], target=domain)
        return [l.strip() for l in out.splitlines() if l.strip()]
