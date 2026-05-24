from .base import ToolWrapper
from typing import List, Optional
import tempfile, os

class HttpxWrapper(ToolWrapper):
    name = "httpx"
    def probe(self, urls: List[str], extra_args: Optional[List[str]] = None) -> List[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls)); tmp = f.name
        try:
            args = ["-l", tmp, "-silent", "-title", "-tech-detect", "-status-code"] + (extra_args or [])
            out = self.run(args, timeout=300)
            return [l for l in out.splitlines() if l.strip()]
        finally:
            os.unlink(tmp)
