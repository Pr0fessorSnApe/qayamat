"""
QAYAMAT — Scan diff / continuous monitoring snapshots.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional


SNAPSHOT_DIR = Path("data/snapshots")


class ScanSnapshot:
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

    def _path(self) -> Path:
        return SNAPSHOT_DIR / f"scan_{self.scan_id}.json"

    def save(self, assets: List[dict], findings: List[dict], urls: List[str]) -> None:
        data = {
            "scan_id": self.scan_id,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "assets": [a.get("url", "") for a in assets],
            "findings_fp": [f.get("fingerprint", f.get("id")) for f in findings],
            "urls": urls,
        }
        self._path().write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def load_previous(scan_id: int) -> Optional[dict]:
        path = SNAPSHOT_DIR / f"scan_{scan_id}.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        # Compare to any prior snapshot for same targets
        prior = sorted(SNAPSHOT_DIR.glob("scan_*.json"), key=lambda p: p.stat().st_mtime)
        if len(prior) >= 2:
            return json.loads(prior[-2].read_text(encoding="utf-8"))
        return None


class ScanDiff:
    @staticmethod
    def compare(current: dict, previous: Optional[dict]) -> Dict[str, Any]:
        if not previous:
            return {
                "new_assets": current.get("assets", []),
                "new_urls": current.get("urls", []),
                "new_findings": current.get("findings_fp", []),
                "is_first_run": True,
            }
        cur_a = set(current.get("assets", []))
        prev_a = set(previous.get("assets", []))
        cur_u = set(current.get("urls", []))
        prev_u = set(previous.get("urls", []))
        cur_f = set(str(x) for x in current.get("findings_fp", []))
        prev_f = set(str(x) for x in previous.get("findings_fp", []))
        return {
            "new_assets": sorted(cur_a - prev_a),
            "removed_assets": sorted(prev_a - cur_a),
            "new_urls": sorted(cur_u - prev_u),
            "new_findings": sorted(cur_f - prev_f),
            "is_first_run": False,
        }
