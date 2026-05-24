"""
QAYAMAT — Tool Orchestrator
Central dispatcher for all external security tools with scope enforcement.
"""

import subprocess
import shutil
import os
from pathlib import Path
from typing import List, Optional

from core.policy_engine import PolicyEngine
from core.logger import AuditLogger


class ToolOrchestrator:
    def __init__(self, policy: PolicyEngine, logger: AuditLogger):
        self.policy = policy
        self.logger = logger
        self.install_dir = Path(os.environ.get("QAYAMAT_TOOLS", "/opt/qayamat/tools"))

    def _find_binary(self, tool_name: str) -> Optional[str]:
        """Locate tool binary: install_dir first, then PATH."""
        local = self.install_dir / tool_name
        if local.exists() and os.access(local, os.X_OK):
            return str(local)
        found = shutil.which(tool_name)
        return found

    def run_tool(
        self,
        tool_name: str,
        args: List[str],
        target: Optional[str] = None,
        input_data: Optional[str] = None,
        timeout: int = 300,
        env: Optional[dict] = None,
    ) -> Optional[str]:
        """
        Execute a tool after scope validation.

        target: explicit target to scope-check (if None, scope check is skipped —
                use only for tools that operate on pre-validated data).
        """
        if target and not self.policy.validate_request(f"http://{target}"):
            self.logger.warning(f"Blocked {tool_name}: target '{target}' out of scope")
            return None

        binary = self._find_binary(tool_name)
        if not binary:
            self.logger.error(f"Tool not found: {tool_name}")
            return None

        cmd = [binary] + args
        self.logger.info(f"Running: {' '.join(cmd)}")

        run_env = {**os.environ, **(env or {})}

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                input=input_data,
                timeout=timeout,
                env=run_env,
            )
            if result.returncode != 0 and result.stderr:
                self.logger.warning(f"{tool_name} stderr: {result.stderr[:500]}")
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.error(f"{tool_name} timed out after {timeout}s")
            return None
        except Exception as e:
            self.logger.error(f"{tool_name} execution failed: {e}")
            return None

    def tool_available(self, tool_name: str) -> bool:
        return self._find_binary(tool_name) is not None
