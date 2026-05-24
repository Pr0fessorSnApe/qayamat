"""
QAYAMAT — Base Tool Wrapper
All tool wrappers inherit from this. Uses ToolOrchestrator under the hood.
"""

import os
import shutil
from typing import List, Optional


class ToolWrapper:
    """
    Base class for all tool wrappers.
    Subclasses set `name` and call self.run(args, target=..., timeout=...).
    """
    name: str = ""

    def __init__(self, policy=None, logger=None):
        self.policy = policy
        self.logger = logger
        self._bin_path: Optional[str] = None

    def _find_binary(self) -> Optional[str]:
        if self._bin_path:
            return self._bin_path
        tools_dir = os.environ.get("QAYAMAT_TOOLS", "/opt/qayamat/tools")
        candidates = [
            os.path.join(tools_dir, self.name),
            os.path.expanduser(f"~/go/bin/{self.name}"),
            shutil.which(self.name),
        ]
        for c in candidates:
            if c and os.path.isfile(c) and os.access(c, os.X_OK):
                self._bin_path = c
                return c
        return None

    def available(self) -> bool:
        return self._find_binary() is not None

    def run(
        self,
        args: List[str],
        target: Optional[str] = None,
        input_data: Optional[str] = None,
        timeout: int = 300,
    ) -> str:
        """
        Run the tool synchronously. Returns stdout as string, or "" on failure.
        Scope-checks `target` if policy is provided.
        """
        import subprocess

        # Scope check
        if self.policy and target:
            url = target if target.startswith("http") else f"http://{target}"
            try:
                if not self.policy.validate_request(url):
                    if self.logger:
                        self.logger.warning(f"[{self.name}] Blocked: {target} out of scope")
                    return ""
            except Exception:
                pass  # If policy check fails, proceed

        binary = self._find_binary()
        if not binary:
            if self.logger:
                self.logger.error(f"Tool not found: {self.name}")
            return ""

        cmd = [binary] + args
        if self.logger:
            self.logger.info(f"Running: {' '.join(cmd[:6])}{'...' if len(cmd) > 6 else ''}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                input=input_data,
                timeout=timeout,
                env={**os.environ},
            )
            if result.returncode != 0 and result.stderr and self.logger:
                self.logger.debug(f"{self.name} stderr: {result.stderr[:300]}")
            return result.stdout
        except subprocess.TimeoutExpired:
            if self.logger:
                self.logger.error(f"{self.name} timed out after {timeout}s")
            return ""
        except Exception as e:
            if self.logger:
                self.logger.error(f"{self.name} failed: {e}")
            return ""
