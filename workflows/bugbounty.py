"""
QAYAMAT — Bug Bounty enrichment workflow.
"""

from typing import List, Optional

from core.bugbounty.runner import BugBountyRunner
from core.finding_validator import FindingValidator
from core.oos_parser import ParsedExclusions
from core.scan_store import store
from core.scan_control import check_cancelled


class BugBountyWorkflow:
    def __init__(self, config, policy, ai, logger, validator=None, parsed_exclusions=None):
        self.config = config
        self.policy = policy
        self.ai = ai
        self.logger = logger
        self.validator = validator
        self.parsed_exclusions = parsed_exclusions

    async def execute(self, recon_results: dict, scan_id: Optional[int] = None, auth_headers=None) -> List[dict]:
        check_cancelled(scan_id, "bug bounty")
        runner = BugBountyRunner(
            self.config,
            self.policy,
            self.logger,
            validator=self.validator,
            parsed_exclusions=self.parsed_exclusions,
            ai_engine=self.ai,
        )
        findings = await runner.run_all(recon_results, scan_id=scan_id, auth_headers=auth_headers)
        saved = []
        for f in findings:
            entry = store.add_finding(f, scan_id=scan_id)
            if entry:
                saved.append(entry)
                store.add_event(
                    f"[bugbounty] {f.get('title', '')} [{f.get('severity', '')}]",
                    scan_id=scan_id,
                )
        if self.logger:
            self.logger.info(f"Bug bounty workflow: {len(saved)} validated findings")
        return saved
