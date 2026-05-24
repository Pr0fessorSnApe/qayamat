from .base import ToolWrapper
from typing import List, Optional

class NucleiWrapper(ToolWrapper):
    name = "nuclei"
    def scan(self, target: str, templates: Optional[str] = None, severity: Optional[str] = None) -> List[str]:
        args = ["-u", target, "-silent", "-jsonl"]
        if templates:
            args += ["-t", templates]
        if severity:
            args += ["-severity", severity]
        out = self.run(args, target=target, timeout=600)
        return [l for l in out.splitlines() if l.strip()]
