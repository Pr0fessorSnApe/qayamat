from .base import ToolWrapper
from typing import List

class TrufflehogWrapper(ToolWrapper):
    name = "trufflehog"
    def scan_git(self, repo_url: str) -> List[str]:
        out = self.run(["git", repo_url, "--json"])
        return [l for l in out.splitlines() if l.strip()]
