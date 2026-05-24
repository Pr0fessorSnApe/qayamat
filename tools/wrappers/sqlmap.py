from .base import ToolWrapper
from typing import List

class SqlmapWrapper(ToolWrapper):
    name = "sqlmap"
    def safe_scan(self, url: str) -> List[str]:
        """Boolean-based blind only — no writes, no destructive techniques."""
        args = ["-u", url, "--batch", "--smart", "--level=1", "--risk=1",
                "--technique=B", "--no-cast", "--output-dir=/tmp/sqlmap_output"]
        out = self.run(args, target=url, timeout=600)
        return [l for l in out.splitlines() if l.strip()]
