from .base import ToolWrapper
from typing import List

class ArjunWrapper(ToolWrapper):
    name = "arjun"
    def discover_params(self, url: str) -> List[str]:
        out = self.run(["-u", url, "-oJ", "/tmp/arjun_out.json"], target=url)
        return [l for l in out.splitlines() if l.strip()]
