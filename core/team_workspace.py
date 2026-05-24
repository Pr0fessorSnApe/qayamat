"""
QAYAMAT — Team workspace (shared scans, assignments, audit log).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


TEAM_FILE = Path("data/team.json")


class TeamWorkspace:
    def __init__(self):
        TEAM_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        if TEAM_FILE.exists():
            try:
                return json.loads(TEAM_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"members": [], "assignments": [], "audit_log": []}

    def _save(self) -> None:
        TEAM_FILE.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def add_member(self, name: str, email: str = "", role: str = "hunter") -> dict:
        member = {
            "id": len(self._data["members"]) + 1,
            "name": name,
            "email": email,
            "role": role,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._data["members"].append(member)
        self._audit("member_added", f"{name} ({role})")
        self._save()
        return member

    def list_members(self) -> List[dict]:
        return self._data.get("members", [])

    def assign_finding(self, finding_id: int, member_id: int, scan_id: Optional[int] = None) -> dict:
        assignment = {
            "finding_id": finding_id,
            "member_id": member_id,
            "scan_id": scan_id,
            "status": "assigned",
            "assigned_at": datetime.now(timezone.utc).isoformat(),
        }
        self._data["assignments"].append(assignment)
        self._audit("finding_assigned", f"Finding #{finding_id} → member #{member_id}")
        self._save()
        return assignment

    def get_assignments(self, member_id: Optional[int] = None) -> List[dict]:
        items = self._data.get("assignments", [])
        if member_id is not None:
            items = [a for a in items if a.get("member_id") == member_id]
        return items

    def _audit(self, action: str, detail: str) -> None:
        self._data.setdefault("audit_log", []).insert(0, {
            "action": action,
            "detail": detail,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        self._data["audit_log"] = self._data["audit_log"][:500]

    def audit_log(self, limit: int = 50) -> List[dict]:
        return self._data.get("audit_log", [])[:limit]
