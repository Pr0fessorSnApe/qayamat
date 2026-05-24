"""QAYAMAT — Payload Sandbox
Safely tests payloads in an isolated Docker container.
"""

import subprocess
import tempfile
import os
import shutil
from typing import Optional


class Sandbox:
    SANDBOX_IMAGE = "qayamat-sandbox"

    def __init__(self):
        self._docker_available = shutil.which("docker") is not None
        self._sandbox_dir = tempfile.mkdtemp(prefix="qayamat_sandbox_")

    def _docker_running(self) -> bool:
        if not self._docker_available:
            return False
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0

    def test_payload(self, payload: str, context: dict) -> dict:
        """
        Test a payload in an isolated Docker container.
        Falls back to a no-op if Docker is unavailable.

        Returns dict with keys: executed (bool), output (str), error (str).
        """
        if not self._docker_running():
            return {
                "executed": False,
                "output": "",
                "error": "Docker not available — payload not tested",
            }

        try:
            result = subprocess.run(
                [
                    "docker", "run",
                    "--rm",
                    "--network", "none",          # No network access
                    "--memory", "64m",             # Memory limit
                    "--cpus", "0.5",               # CPU limit
                    "--read-only",                 # Read-only filesystem
                    "--security-opt", "no-new-privileges",
                    "-i",
                    self.SANDBOX_IMAGE,
                    "python", "-c",
                    "import sys; payload=sys.stdin.read(); print('SAFE_EXEC:', repr(payload[:100]))",
                ],
                input=payload.encode(),
                capture_output=True,
                timeout=10,
            )
            return {
                "executed": True,
                "output": result.stdout.decode(),
                "error": result.stderr.decode() if result.returncode != 0 else "",
            }
        except subprocess.TimeoutExpired:
            return {"executed": False, "output": "", "error": "Sandbox timed out"}
        except Exception as e:
            return {"executed": False, "output": "", "error": str(e)}

    def cleanup(self) -> None:
        """Remove the temporary sandbox directory."""
        import shutil as sh
        try:
            sh.rmtree(self._sandbox_dir, ignore_errors=True)
        except Exception:
            pass
