from .base import ToolWrapper
from typing import List

class GauWrapper(ToolWrapper):
    name = "gau"
    def get_urls(self, domain: str) -> List[str]:
        out = self.run([domain, "--blacklist", "png,jpg,gif,css,woff"], target=domain)
        return [l.strip() for l in out.splitlines() if l.strip()]
