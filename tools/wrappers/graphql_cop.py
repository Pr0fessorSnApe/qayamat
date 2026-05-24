from .base import ToolWrapper
from typing import List

class GraphqlCopWrapper(ToolWrapper):
    name = "graphql-cop"
    def audit(self, endpoint: str) -> List[str]:
        out = self.run(["-t", endpoint], target=endpoint)
        return [l for l in out.splitlines() if l.strip()]
