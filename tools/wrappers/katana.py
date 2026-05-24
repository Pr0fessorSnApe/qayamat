from .base import ToolWrapper
from typing import List

class KatanaWrapper(ToolWrapper):
    name = "katana"
    def crawl(self, url: str, depth: int = 3) -> List[str]:
        out = self.run(["-u", url, "-silent", "-d", str(depth)], target=url)
        return [l.strip() for l in out.splitlines() if l.strip()]
