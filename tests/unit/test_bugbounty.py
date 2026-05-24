"""Tests for bug bounty modules."""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.bugbounty.scanners import (
    parse_program_policy,
    score_report_quality,
    generate_wordlist,
    check_scope_drift,
)
from core.bugbounty.runner import BugBountyRunner
from core.oos_parser import ParsedExclusions


class TestBugBountyScanners:
    def test_report_quality_scorer(self):
        f = score_report_quality({
            "title": "XSS",
            "severity": "High",
            "url": "https://example.com/x",
            "description": "A" * 100,
            "evidence": "B" * 50,
        })
        assert "report_quality_score" in f
        assert f["report_quality_score"] >= 0.5

    def test_wordlist_generator(self):
        wl = generate_wordlist(["https://example.com/api/users?id=1"], [])
        assert isinstance(wl, list)

    def test_policy_parser(self):
        rules = parse_program_policy("Out of scope: test.example.com\nNo automated scanning")
        assert "out_of_scope" in rules

    def test_scope_drift_first_run(self):
        result = check_scope_drift("test-program-unit", ["a.example.com"])
        assert "added" in result


class TestBugBountyRunner:
    def test_exclusion_filter(self):
        policy = MagicMock()
        policy.is_in_scope.return_value = True
        runner = BugBountyRunner(
            {"bugbounty": {"enabled": True, "min_confidence": 0.8}},
            policy,
            parsed_exclusions=ParsedExclusions(
                keywords=["payments"],
                excluded_vuln_types=["dos"],
            ),
        )
        blocked = runner._apply_exclusion_rules({
            "url": "https://payments.example.com/x",
            "title": "Issue",
            "vuln_type": "xss",
        })
        assert blocked is True
