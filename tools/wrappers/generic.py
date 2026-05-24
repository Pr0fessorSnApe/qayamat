"""Generic wrapper for any tool not explicitly wrapped."""
from .base import ToolWrapper
from typing import List

class GenericTool(ToolWrapper):
    def __init__(self, orchestrator, tool_name: str):
        super().__init__(orchestrator)
        self.name = tool_name

    def execute(self, args: List[str]) -> str:
        return self.run(args)

def create_wrapper(tool_name: str, orchestrator) -> GenericTool:
    return GenericTool(orchestrator, tool_name)
