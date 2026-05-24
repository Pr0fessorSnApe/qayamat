"""Tests for scan pause/resume checkpoints."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.scan_checkpoint import ScanCheckpoint, SCAN_PHASES


class TestScanCheckpoint:
    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.scan_checkpoint.CHECKPOINT_DIR", tmp_path)
        ScanCheckpoint.save(
            99,
            "vuln_scan",
            ["recon", "playwright"],
            {"targets": ["example.com"], "profile": "safe"},
            {"urls": ["https://example.com"], "subdomains": ["www.example.com"]},
        )
        loaded = ScanCheckpoint.load(99)
        assert loaded is not None
        assert loaded["next_phase"] == "vuln_scan"
        assert "recon" in loaded["completed_phases"]

    def test_should_run_skips_completed(self):
        ckpt = {"completed_phases": ["recon", "playwright"], "next_phase": "vuln_scan"}
        assert ScanCheckpoint.should_run("recon", ckpt) is False
        assert ScanCheckpoint.should_run("vuln_scan", ckpt) is True
