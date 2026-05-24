"""Tests for advanced bug bounty modules."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.bugbounty.bounty_estimator import estimate_bounty, estimate_cvss
from core.bugbounty.nuclei_template_gen import generate_template_yaml, save_templates
from core.bugbounty.submission_api import HackerOneSubmitter, submit_finding


class TestBountyEstimator:
    def test_cvss_high_severity(self):
        r = estimate_cvss({"severity": "Critical", "vuln_type": "SSRF", "title": "SSRF"})
        assert r["cvss_base_score"] >= 8.0

    def test_bounty_range(self):
        r = estimate_bounty({"severity": "High", "title": "IDOR"}, "test-program")
        assert r["bounty_max_usd"] >= r["bounty_min_usd"]


class TestNucleiGen:
    def test_yaml_contains_id(self):
        y = generate_template_yaml("/api/v1/users", severity="high")
        assert "qayamat-custom" in y
        assert "/api/v1/users" in y


class TestSubmission:
    def test_h1_dry_run(self):
        h1 = HackerOneSubmitter(identifier="test", token="test")
        r = h1.submit_report(
            {"title": "Test", "severity": "Medium", "url": "https://example.com", "description": "d", "evidence": "e"},
            team_handle="example",
            dry_run=True,
        )
        assert r["dry_run"] is True
        assert r["platform"] == "hackerone"
