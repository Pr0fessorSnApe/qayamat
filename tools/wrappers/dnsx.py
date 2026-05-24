from .base import ToolWrapper
from typing import List
import tempfile, os

class DnsxWrapper(ToolWrapper):
    name = "dnsx"
    def resolve(self, domains: List[str]) -> List[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains)); tmp = f.name
        try:
            out = self.run(["-l", tmp, "-silent", "-resp"])
            return [l for l in out.splitlines() if l.strip()]
        finally:
            os.unlink(tmp)
