"""QAYAMAT — Active Directory / BloodHound Workflow
Only runs under red_team profile with explicit authorization.
"""

import asyncio
import subprocess
import shutil
from typing import List, Dict, Any

from core.logger import AuditLogger
from core.policy_engine import PolicyEngine
from workflows.recon import ScanProgressUI


class ActiveDirectoryWorkflow:
    def __init__(self, config: dict, policy: PolicyEngine, ai, logger: AuditLogger):
        self.config = config
        self.policy = policy
        self.ai = ai
        self.logger = logger

    async def execute(self, domain: str = "", dc_ip: str = "") -> List[Dict[str, Any]]:
        if not self.policy.requires_explicit_auth():
            self.logger.warning("AD workflow requires red_team profile with explicit auth. Skipping.")
            return []

        ui = ScanProgressUI()
        findings: List[Dict[str, Any]] = []

        try:
            ui.add_phase("BloodHound Collection", 3)
            ui.update_stats(phase="BloodHound Collection")

            # SharpHound / BloodHound-python
            if shutil.which("bloodhound-python"):
                cmd = ["bloodhound-python", "-d", domain, "-u", "guest", "-p", "", "-c", "All"]
                if dc_ip:
                    cmd += ["--dc", dc_ip]
                try:
                    subprocess.run(cmd, capture_output=True, timeout=120)
                    findings.append({
                        "title": "BloodHound data collected",
                        "severity": "Info",
                        "vuln_type": "AD Recon",
                        "url": domain,
                    })
                except Exception as e:
                    self.logger.warning(f"BloodHound collection failed: {e}")
            else:
                self.logger.info("bloodhound-python not installed")

            await asyncio.sleep(0.3)
            ui.update_phase("BloodHound Collection", 3)
            ui.complete_phase("BloodHound Collection")
            ui.stop()

        except Exception as e:
            self.logger.error(f"AD workflow failed: {e}")
            ui.stop()
            raise

        return findings
