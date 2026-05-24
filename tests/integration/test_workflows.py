"""Integration tests for report generation."""

import json
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


SAMPLE_FINDINGS = [
    {
        "title": "Reflected XSS",
        "severity": "High",
        "url": "https://target.com/search?q=",
        "vuln_type": "XSS",
        "description": "User input reflected without sanitisation.",
        "evidence": "<script>alert(1)</script>",
    },
    {
        "title": "SQL Injection",
        "severity": "Critical",
        "url": "https://target.com/api/login",
        "vuln_type": "SQLi",
        "description": "Boolean-based blind injection in username field.",
    },
    {
        "title": "Missing HSTS",
        "severity": "Low",
        "url": "https://target.com/",
        "vuln_type": "Misconfiguration",
    },
]


class TestReportGenerator:
    def test_generates_json_report(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from workflows.reporting import ReportGenerator
        rg = ReportGenerator(SAMPLE_FINDINGS, {})
        rg.generate()
        report_path = tmp_path / "reports" / "report.json"
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert data["total_findings"] == 3
        assert data["summary"]["Critical"] == 1
        assert data["summary"]["High"] == 1
        assert len(data["findings"]) == 3

    def test_generates_html_report(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from workflows.reporting import ReportGenerator
        rg = ReportGenerator(SAMPLE_FINDINGS, {})
        rg.generate()
        html_path = tmp_path / "reports" / "report.html"
        assert html_path.exists()
        content = html_path.read_text()
        assert "QAYAMAT" in content
        assert "Reflected XSS" in content
        assert "SQL Injection" in content

    def test_empty_findings(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from workflows.reporting import ReportGenerator
        rg = ReportGenerator([], {})
        rg.generate()
        data = json.loads((tmp_path / "reports" / "report.json").read_text())
        assert data["total_findings"] == 0


class TestCorrelationEngine:
    def test_detects_ato_chain(self):
        from core.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        findings = [
            {"type": "secret_leak", "severity": "High"},
            {"type": "exposed_admin", "severity": "High"},
        ]
        chains = engine.build_chains(findings)
        assert len(chains) >= 1
        assert any("Account Takeover" in c["name"] for c in chains)

    def test_no_chains_without_matching_findings(self):
        from core.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        findings = [{"type": "missing_hsts", "severity": "Low"}]
        chains = engine.build_chains(findings)
        assert chains == []

    def test_risk_score_empty(self):
        from core.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        assert engine.calculate_risk_score([]) == 0.0

    def test_risk_score_critical(self):
        from core.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        findings = [{"severity": "Critical"} for _ in range(3)]
        score = engine.calculate_risk_score(findings)
        assert score == 10.0
