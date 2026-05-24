"""Unit tests for PolicyEngine."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def _make_policy():
    from unittest.mock import patch, MagicMock
    import yaml

    config = {
        "general": {"data_dir": "./data", "log_level": "INFO"},
        "ai": {"backend": "openai"},
    }
    logger = MagicMock()

    # Mock the yaml file loads so we don't need real config files
    scope_policy = {"scope_types": ["domain", "ip", "wildcard"]}
    forbidden = {
        "blocked_paths": ["/admin", "/wp-admin"],
        "destructive_patterns": ["DROP TABLE", "rm -rf"],
    }
    profiles = {
        "safe": {"active_probing": True, "max_requests_per_second": 5, "payload_severity": "low"},
        "passive": {"active_probing": False, "max_requests_per_second": 1, "allowed_methods": ["GET", "HEAD"]},
    }

    with patch("builtins.open"), \
         patch("yaml.safe_load", side_effect=[scope_policy, profiles]):
        from core.policy_engine import PolicyEngine
        pe = PolicyEngine(config, logger)

    pe.scope = []
    pe.out_scope = []
    pe.profile = "safe"
    pe.profile_config = profiles["safe"]
    pe.forbidden = forbidden
    return pe


class TestPolicyEngine:
    def test_in_scope_exact_match(self):
        pe = _make_policy()
        pe.scope = ["example.com"]
        assert pe.is_in_scope("example.com") is True

    def test_out_of_scope_blocks(self):
        pe = _make_policy()
        pe.scope = ["example.com"]
        pe.out_scope = ["admin.example.com"]
        assert pe.is_in_scope("admin.example.com") is False

    def test_wildcard_match(self):
        pe = _make_policy()
        pe.scope = ["*.example.com"]
        assert pe.is_in_scope("api.example.com") is True
        assert pe.is_in_scope("evil.com") is False

    def test_unknown_target_blocked(self):
        pe = _make_policy()
        pe.scope = ["example.com"]
        assert pe.is_in_scope("evil.com") is False

    def test_validate_payload_blocks_destructive(self):
        pe = _make_policy()
        assert pe.validate_payload("SELECT * FROM users; DROP TABLE users--") is False

    def test_validate_payload_allows_normal(self):
        pe = _make_policy()
        assert pe.validate_payload("hello world") is True

    def test_get_rate_limit(self):
        pe = _make_policy()
        pe.profile_config = {"max_requests_per_second": 10}
        assert pe.get_rate_limit() == pytest.approx(0.1)


class TestVault:
    def test_encrypt_decrypt_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        key_file = str(tmp_path / "vault.key")
        from core.vault import Vault
        v = Vault(key_file=key_file)
        v.store_secret("test_key", "my_secret_value")
        v2 = Vault(key_file=key_file)
        assert v2.get_secret("test_key") == "my_secret_value"

    def test_missing_secret_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        key_file = str(tmp_path / "vault.key")
        from core.vault import Vault
        v = Vault(key_file=key_file)
        assert v.get_secret("nonexistent") == ""

    def test_has_secret(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        key_file = str(tmp_path / "vault.key")
        from core.vault import Vault
        v = Vault(key_file=key_file)
        assert v.has_secret("x") is False


class TestPayloadEngine:
    def test_xss_payloads_not_empty(self):
        from core.payload_engine import PayloadEngine
        pe = PayloadEngine()
        payloads = pe.generate("xss")
        assert len(payloads) > 0
        assert any("<script>" in p for p in payloads)

    def test_sqli_payloads(self):
        from core.payload_engine import PayloadEngine
        pe = PayloadEngine()
        payloads = pe.generate("sqli")
        assert len(payloads) > 0

    def test_unknown_type_returns_empty(self):
        from core.payload_engine import PayloadEngine
        pe = PayloadEngine()
        assert pe.generate("unknown_vuln_type") == []

    def test_context_aware_xss(self):
        from core.payload_engine import PayloadEngine
        pe = PayloadEngine()
        csp_payloads = pe.generate("xss", context={"csp": True})
        regular_payloads = pe.generate("xss")
        # CSP bypass list should differ from default list
        assert set(csp_payloads) != set(regular_payloads)


class TestFindingValidator:
    def test_rejects_benign_health_endpoint(self):
        from core.finding_validator import FindingValidator
        v = FindingValidator({"validation": {"enabled": True, "use_ai_confirmation": False}})
        ok, reason, _ = v.validate({
            "title": "Exposed API Endpoint: /api/health",
            "severity": "high",
            "vuln_type": "API Exposure",
            "url": "https://example.com/api/health",
            "evidence": '{"status":"ok"}',
            "tool": "api_probe",
        })
        assert ok is False
        assert "benign" in reason.lower()

    def test_accepts_sqlmap_confirmed(self):
        from core.finding_validator import FindingValidator
        v = FindingValidator({"validation": {"enabled": True, "use_ai_confirmation": False}})
        ok, _, _ = v.validate({
            "title": "SQL Injection",
            "severity": "critical",
            "vuln_type": "SQLi",
            "url": "https://example.com?id=1",
            "evidence": "sqlmap identified the following injection point",
            "tool": "sqlmap",
        })
        assert ok is True

    def test_rejects_ffuf_noise_path(self):
        from core.finding_validator import FindingValidator
        v = FindingValidator({"validation": {"enabled": True, "use_ai_confirmation": False}})
        ok, _, _ = v.validate({
            "title": "Hidden endpoint discovered: images",
            "severity": "low",
            "vuln_type": "Discovery",
            "url": "https://example.com/images",
            "tool": "ffuf",
        })
        assert ok is False


class TestReproSteps:
    def test_xss_steps_generated(self):
        from core.repro_steps import generate_reproduction_steps
        steps = generate_reproduction_steps({
            "title": "Cross-Site Scripting",
            "vuln_type": "XSS",
            "url": "https://example.com/search?q=test",
            "severity": "High",
            "tool": "dalfox",
            "evidence": "<script>alert(1)</script>",
        })
        text = "\n".join(steps)
        assert "Steps to reproduce" in text
        assert "example.com" in text
        assert "Remediation" in text
