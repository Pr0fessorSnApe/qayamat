from .base import ToolWrapper
from typing import List, Optional

class FfufWrapper(ToolWrapper):
    name = "ffuf"
    def fuzz(self, url: str, wordlist: str, extra_args: Optional[List[str]] = None) -> List[str]:
        args = ["-u", url, "-w", wordlist, "-mc", "200,301,302,403", "-s"] + (extra_args or [])
        out = self.run(args, target=url, timeout=600)
        return [l for l in out.splitlines() if l.strip()]
