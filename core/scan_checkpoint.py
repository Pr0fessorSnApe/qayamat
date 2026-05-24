"""
QAYAMAT — Scan checkpointing for pause / resume.
Persists phase progress and recon state to data/checkpoints/.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

CHECKPOINT_DIR = Path("data/checkpoints")

# Ordered pipeline phases (resume starts at next_phase)
SCAN_PHASES: List[str] = [
    "recon",
    "repo_secrets",
    "playwright",
    "ai_guidance",
    "vuln_scan",
    "oob",
    "api_testing",
    "multi_role",
    "bug_bounty",
    "import_traffic",
    "exploitation",
    "active_directory",
    "correlation",
    "plugins",
    "reporting",
    "submission",
    "snapshot",
]

PHASE_PROGRESS = {
    "recon": 5,
    "repo_secrets": 10,
    "playwright": 15,
    "ai_guidance": 18,
    "vuln_scan": 45,
    "oob": 50,
    "api_testing": 60,
    "multi_role": 65,
    "bug_bounty": 72,
    "import_traffic": 74,
    "exploitation": 78,
    "active_directory": 82,
    "correlation": 88,
    "plugins": 92,
    "reporting": 96,
    "submission": 98,
    "snapshot": 100,
}


class ScanCheckpoint:
    @staticmethod
    def _path(scan_id: int) -> Path:
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        return CHECKPOINT_DIR / f"scan_{scan_id}.json"

    @staticmethod
    def save(
        scan_id: int,
        next_phase: str,
        completed_phases: List[str],
        scan_config: dict,
        recon_results: Optional[dict] = None,
        extra: Optional[dict] = None,
    ) -> None:
        data = {
            "scan_id": scan_id,
            "next_phase": next_phase,
            "completed_phases": completed_phases,
            "scan_config": scan_config,
            "recon_results": recon_results or {},
            "progress": PHASE_PROGRESS.get(next_phase, 0),
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "extra": extra or {},
        }
        ScanCheckpoint._path(scan_id).write_text(
            json.dumps(data, default=str, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def load(scan_id: int) -> Optional[dict]:
        path = ScanCheckpoint._path(scan_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    @staticmethod
    def delete(scan_id: int) -> None:
        ScanCheckpoint._path(scan_id).unlink(missing_ok=True)

    @staticmethod
    def should_run(phase: str, checkpoint: Optional[dict]) -> bool:
        """True if this phase should execute (not already completed on resume)."""
        if not checkpoint:
            return True
        completed = set(checkpoint.get("completed_phases", []))
        if phase in completed:
            return False
        next_phase = checkpoint.get("next_phase", "recon")
        try:
            return SCAN_PHASES.index(phase) >= SCAN_PHASES.index(next_phase)
        except ValueError:
            return True

    @staticmethod
    def mark_completed(checkpoint: dict, phase: str) -> dict:
        completed = list(checkpoint.get("completed_phases", []))
        if phase not in completed:
            completed.append(phase)
        idx = SCAN_PHASES.index(phase) if phase in SCAN_PHASES else -1
        next_phase = SCAN_PHASES[idx + 1] if idx + 1 < len(SCAN_PHASES) else "done"
        checkpoint["completed_phases"] = completed
        checkpoint["next_phase"] = next_phase
        return checkpoint

    @staticmethod
    def phase_index(phase: str) -> int:
        try:
            return SCAN_PHASES.index(phase)
        except ValueError:
            return 0
