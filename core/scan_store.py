"""
QAYAMAT — Scan Store
────────────────────
Thread-safe singleton that holds ALL scan data in memory + persists to SQLite.
No Docker / PostgreSQL required — uses data/qayamat.db automatically.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any

_lock = threading.Lock()
DB_PATH = Path("data/qayamat.db")


class ScanStore:
    """Thread-safe singleton store for all scan data."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialised = False
        return cls._instance

    def __init__(self):
        if self._initialised:
            return
        self._initialised = True
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._load_into_memory()

    # ── Schema ─────────────────────────────────────────────────────────────────
    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT    NOT NULL,
                targets      TEXT,
                profile      TEXT    DEFAULT 'safe',
                status       TEXT    DEFAULT 'pending',
                progress     REAL    DEFAULT 0.0,
                created_at   TEXT,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER,
                title       TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                vuln_type   TEXT,
                url         TEXT,
                description TEXT,
                evidence    TEXT,
                template    TEXT,
                tool        TEXT,
                tags        TEXT,
                cve         TEXT,
                cvss        TEXT,
                created_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS assets (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      INTEGER,
                url          TEXT    NOT NULL,
                asset_type   TEXT    NOT NULL,
                status       TEXT    DEFAULT 'unknown',
                technologies TEXT,
                open_ports   TEXT,
                created_at   TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER,
                message     TEXT,
                event_type  TEXT    DEFAULT 'info',
                created_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS programs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT UNIQUE NOT NULL,
                config_json  TEXT,
                created_at   TEXT
            );
            CREATE TABLE IF NOT EXISTS monitor_jobs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                program_name    TEXT,
                targets         TEXT,
                interval_hours  REAL DEFAULT 24,
                webhook_url     TEXT,
                last_run        TEXT,
                enabled         INTEGER DEFAULT 1
            );
        """)
        self._conn.commit()
        self._migrate_schema()

    # ── Load SQLite → memory ───────────────────────────────────────────────────
    def _load_into_memory(self) -> None:
        c = self._conn.cursor()

        c.execute("SELECT * FROM findings ORDER BY id")
        self._findings: List[dict] = []
        for row in c.fetchall():
            f = dict(row)
            f["tags"] = self._json_load(f.get("tags"), [])
            f["cve"]  = self._json_load(f.get("cve"),  [])
            f["affected_urls"] = self._json_load(f.get("affected_urls"), [])
            f.setdefault("triage_status", "new")
            f.setdefault("fingerprint", "")
            self._findings.append(f)

        c.execute("SELECT * FROM assets ORDER BY id")
        self._assets: List[dict] = []
        for row in c.fetchall():
            a = dict(row)
            a["technologies"] = self._json_load(a.get("technologies"), [])
            a["open_ports"]   = self._json_load(a.get("open_ports"),   [])
            self._assets.append(a)

        c.execute("SELECT * FROM scans ORDER BY id")
        self._scans: Dict[int, dict] = {}
        for row in c.fetchall():
            s = dict(row)
            s["targets"] = self._json_load(s.get("targets"), [])
            self._scans[s["id"]] = s

        c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 500")
        self._events: List[dict] = [dict(row) for row in c.fetchall()]

        self._id_finding = max((f["id"] for f in self._findings), default=0) + 1
        self._id_asset   = max((a["id"] for a in self._assets),   default=0) + 1
        self._id_scan    = max(self._scans.keys(), default=0) + 1
        self._id_event   = max((e["id"] for e in self._events),   default=0) + 1

    def _migrate_schema(self) -> None:
        """Add new columns to existing DBs without breaking old installs."""
        cols = {
            "findings": [
                ("fingerprint", "TEXT"),
                ("triage_status", "TEXT DEFAULT 'new'"),
                ("triage_notes", "TEXT"),
                ("report_id", "TEXT"),
                ("affected_urls", "TEXT"),
                ("program_name", "TEXT"),
            ],
            "scans": [
                ("program_name", "TEXT"),
                ("diff_json", "TEXT"),
            ],
        }
        for table, fields in cols.items():
            existing = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            for name, typedef in fields:
                if name not in existing:
                    try:
                        self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typedef}")
                    except Exception:
                        pass
        self._conn.commit()

    @staticmethod
    def _json_load(val, default):
        if val is None:
            return default
        if isinstance(val, (list, dict)):
            return val
        try:
            return json.loads(val)
        except Exception:
            return default

    # ── Scans ──────────────────────────────────────────────────────────────────
    def create_scan(self, name: str, targets: List[str], profile: str = "safe") -> dict:
        with _lock:
            now = datetime.now(timezone.utc).isoformat()
            c = self._conn.cursor()
            c.execute(
                "INSERT INTO scans (name, targets, profile, status, progress, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (name, json.dumps(targets), profile, "running", 0.0, now),
            )
            self._conn.commit()
            scan_id = c.lastrowid
            scan = {
                "id": scan_id, "name": name, "targets": targets,
                "profile": profile, "status": "running",
                "progress": 0.0, "created_at": now, "completed_at": None,
            }
            self._scans[scan_id] = scan
            self._id_scan = scan_id + 1
            return scan

    def cancel_scan(self, scan_id: int) -> bool:
        """Mark scan as cancelled and signal running workflows to stop."""
        from core.scan_control import request_cancel
        with _lock:
            if scan_id not in self._scans:
                return False
            request_cancel(scan_id)
            self._scans[scan_id]["status"] = "cancelled"
            self._conn.execute(
                "UPDATE scans SET status=? WHERE id=?",
                ("cancelled", scan_id),
            )
            self._conn.commit()
            self.add_event("Scan cancelled by user", event_type="warning", scan_id=scan_id)
            return True

    def pause_scan(self, scan_id: int) -> bool:
        """Request pause — pipeline saves checkpoint at next phase boundary."""
        from core.scan_control import request_pause
        with _lock:
            if scan_id not in self._scans:
                return False
            if self._scans[scan_id].get("status") not in ("running", "pending"):
                return False
            request_pause(scan_id)
            self.add_event(
                "Pause requested — scan will stop safely at end of current step",
                event_type="warning",
                scan_id=scan_id,
            )
            return True

    def resume_scan(self, scan_id: int) -> bool:
        """Mark scan ready to resume (checkpoint must exist)."""
        from core.scan_control import clear_cancel, clear_pause
        from core.scan_checkpoint import ScanCheckpoint
        with _lock:
            if scan_id not in self._scans:
                return False
            if not ScanCheckpoint.load(scan_id):
                return False
            clear_cancel(scan_id)
            clear_pause(scan_id)
            self._scans[scan_id]["status"] = "running"
            self._conn.execute(
                "UPDATE scans SET status=? WHERE id=?",
                ("running", scan_id),
            )
            self._conn.commit()
            self.add_event("Scan resume started", event_type="info", scan_id=scan_id)
            return True

    def get_paused_scans(self) -> List[dict]:
        with _lock:
            return [s for s in self._scans.values() if s.get("status") == "paused"]

    def update_scan(self, scan_id: int, **kwargs) -> None:
        with _lock:
            if scan_id not in self._scans:
                return
            self._scans[scan_id].update(kwargs)
            sets = ", ".join(f"{k}=?" for k in kwargs)
            vals = list(kwargs.values()) + [scan_id]
            self._conn.execute(f"UPDATE scans SET {sets} WHERE id=?", vals)
            self._conn.commit()

    def get_scans(self) -> List[dict]:
        with _lock:
            return list(self._scans.values())

    def get_scan(self, scan_id: int) -> Optional[dict]:
        with _lock:
            return self._scans.get(scan_id)

    def get_active_scan(self) -> Optional[dict]:
        """Return running, paused, or most recent scan."""
        with _lock:
            for s in reversed(list(self._scans.values())):
                if s.get("status") in ("running", "pending", "paused"):
                    return s
            if self._scans:
                return list(self._scans.values())[-1]
            return None

    # ── Findings ───────────────────────────────────────────────────────────────
    def add_finding(self, finding: dict, scan_id: Optional[int] = None, dedup: bool = True) -> dict:
        with _lock:
            from core.finding_dedup import finding_fingerprint, merge_findings

            fp = finding.get("fingerprint") or finding_fingerprint(finding)
            finding["fingerprint"] = fp

            if dedup:
                for existing in self._findings:
                    if existing.get("fingerprint") == fp and existing.get("scan_id") == scan_id:
                        merged = merge_findings(existing, finding)
                        existing.update(merged)
                        self._update_finding_row(existing)
                        return existing

            now = datetime.now(timezone.utc).isoformat()
            raw_sev = finding.get("severity", "info")
            sev = raw_sev.capitalize()
            affected = finding.get("affected_urls") or ([finding["url"]] if finding.get("url") else [])

            entry = {
                "id":            self._id_finding,
                "scan_id":       scan_id,
                "title":         finding.get("title", "Unknown"),
                "severity":      sev,
                "vuln_type":     finding.get("vuln_type", ""),
                "url":           finding.get("url", ""),
                "description":   finding.get("description", ""),
                "evidence":      str(finding.get("evidence", ""))[:2000],
                "template":      finding.get("template", ""),
                "tool":          finding.get("tool", ""),
                "tags":          finding.get("tags", []),
                "cve":           finding.get("cve", []),
                "cvss":          str(finding.get("cvss", "")),
                "fingerprint":   fp,
                "triage_status": finding.get("triage_status", "new"),
                "triage_notes":  finding.get("triage_notes", ""),
                "report_id":     finding.get("report_id", ""),
                "affected_urls": affected,
                "program_name":  finding.get("program_name", ""),
                "created_at":    now,
            }
            self._findings.append(entry)
            self._id_finding += 1
            self._insert_finding_row(entry)
            self._conn.commit()
            return entry

    def _insert_finding_row(self, entry: dict) -> None:
        self._conn.execute(
            "INSERT INTO findings "
            "(id,scan_id,title,severity,vuln_type,url,description,evidence,"
            "template,tool,tags,cve,cvss,fingerprint,triage_status,triage_notes,"
            "report_id,affected_urls,program_name,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                entry["id"], entry["scan_id"], entry["title"], entry["severity"],
                entry["vuln_type"], entry["url"], entry["description"], entry["evidence"],
                entry["template"], entry["tool"],
                json.dumps(entry["tags"]), json.dumps(entry["cve"]), entry["cvss"],
                entry.get("fingerprint", ""), entry.get("triage_status", "new"),
                entry.get("triage_notes", ""), entry.get("report_id", ""),
                json.dumps(entry.get("affected_urls", [])), entry.get("program_name", ""),
                entry["created_at"],
            ),
        )

    def _update_finding_row(self, entry: dict) -> None:
        self._conn.execute(
            "UPDATE findings SET description=?, evidence=?, affected_urls=?, severity=? WHERE id=?",
            (
                entry.get("description", ""),
                str(entry.get("evidence", ""))[:2000],
                json.dumps(entry.get("affected_urls", [])),
                entry.get("severity", "Info"),
                entry["id"],
            ),
        )
        self._conn.commit()

    def update_finding_triage(
        self,
        finding_id: int,
        status: str,
        notes: str = "",
        report_id: str = "",
    ) -> Optional[dict]:
        with _lock:
            for f in self._findings:
                if f["id"] == finding_id:
                    f["triage_status"] = status
                    f["triage_notes"] = notes
                    if report_id:
                        f["report_id"] = report_id
                    self._conn.execute(
                        "UPDATE findings SET triage_status=?, triage_notes=?, report_id=? WHERE id=?",
                        (status, notes, f.get("report_id", ""), finding_id),
                    )
                    self._conn.commit()
                    return f
            return None

    def get_findings_by_triage(self, status: str, scan_id: Optional[int] = None) -> List[dict]:
        with _lock:
            results = [f for f in self._findings if f.get("triage_status") == status]
            if scan_id is not None:
                results = [f for f in results if f.get("scan_id") == scan_id]
            return list(results)

    def add_monitor_job(self, program_name: str, targets: List[str], interval_hours: float, webhook: str = "") -> dict:
        with _lock:
            now = datetime.now(timezone.utc).isoformat()
            self._conn.execute(
                "INSERT INTO monitor_jobs (program_name, targets, interval_hours, webhook_url, enabled, last_run) "
                "VALUES (?,?,?,?,1,NULL)",
                (program_name, json.dumps(targets), interval_hours, webhook),
            )
            self._conn.commit()
            return {"program_name": program_name, "targets": targets, "interval_hours": interval_hours}

    def list_monitor_jobs(self) -> List[dict]:
        with _lock:
            rows = self._conn.execute(
                "SELECT id, program_name, targets, interval_hours, webhook_url, last_run, enabled FROM monitor_jobs"
            ).fetchall()
            out = []
            for r in rows:
                out.append({
                    "id": r[0], "program_name": r[1],
                    "targets": self._json_load(r[2], []),
                    "interval_hours": r[3], "webhook_url": r[4],
                    "last_run": r[5], "enabled": bool(r[6]),
                })
            return out

    def get_findings(
        self,
        severity: Optional[str] = None,
        scan_id: Optional[int] = None,
        triage_status: Optional[str] = None,
    ) -> List[dict]:
        with _lock:
            results = self._findings
            if severity:
                results = [f for f in results if f["severity"].lower() == severity.lower()]
            if scan_id is not None:
                results = [f for f in results if f.get("scan_id") == scan_id]
            if triage_status:
                results = [f for f in results if f.get("triage_status") == triage_status]
            return list(results)

    def findings_summary(self, scan_id: Optional[int] = None) -> dict:
        with _lock:
            from collections import Counter
            results = self._findings
            if scan_id is not None:
                results = [f for f in results if f.get("scan_id") == scan_id]
            counts = Counter(f["severity"] for f in results)
            return {"total": len(results), "by_severity": dict(counts)}

    def delete_finding(self, finding_id: int) -> bool:
        with _lock:
            before = len(self._findings)
            self._findings = [f for f in self._findings if f["id"] != finding_id]
            if len(self._findings) == before:
                return False
            self._conn.execute("DELETE FROM findings WHERE id=?", (finding_id,))
            self._conn.commit()
            return True

    # ── Assets ─────────────────────────────────────────────────────────────────
    def add_asset(self, asset: dict, scan_id: Optional[int] = None) -> dict:
        with _lock:
            url = asset.get("url", "").strip()
            if not url:
                return {}
            # Deduplicate
            for existing in self._assets:
                if existing["url"] == url:
                    return existing

            now = datetime.now(timezone.utc).isoformat()
            techs = asset.get("technologies", asset.get("tech", []))
            if isinstance(techs, str):
                techs = [techs] if techs else []

            entry = {
                "id":           self._id_asset,
                "scan_id":      scan_id,
                "url":          url,
                "asset_type":   asset.get("asset_type", "subdomain"),
                "status":       asset.get("status", "unknown"),
                "technologies": techs,
                "open_ports":   asset.get("open_ports", []),
                "created_at":   now,
            }
            self._assets.append(entry)
            self._id_asset += 1

            self._conn.execute(
                "INSERT INTO assets "
                "(id,scan_id,url,asset_type,status,technologies,open_ports,created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (entry["id"], entry["scan_id"], entry["url"], entry["asset_type"],
                 entry["status"], json.dumps(entry["technologies"]),
                 json.dumps(entry["open_ports"]), entry["created_at"]),
            )
            self._conn.commit()
            return entry

    def get_assets(
        self,
        asset_type: Optional[str] = None,
        scan_id: Optional[int] = None,
    ) -> List[dict]:
        with _lock:
            results = self._assets
            if asset_type:
                results = [a for a in results if a["asset_type"] == asset_type]
            if scan_id is not None:
                results = [a for a in results if a.get("scan_id") == scan_id]
            return list(results)

    def assets_summary(self, scan_id: Optional[int] = None) -> dict:
        with _lock:
            from collections import Counter
            results = self._assets
            if scan_id is not None:
                results = [a for a in results if a.get("scan_id") == scan_id]
            counts = Counter(a["asset_type"] for a in results)
            return {"total": len(results), "by_type": dict(counts)}

    # ── Live Events (scan log) ─────────────────────────────────────────────────
    def add_event(
        self,
        message: str,
        event_type: str = "info",
        scan_id: Optional[int] = None,
    ) -> dict:
        with _lock:
            now = datetime.now(timezone.utc).isoformat()
            entry = {
                "id":         self._id_event,
                "scan_id":    scan_id,
                "message":    message,
                "event_type": event_type,
                "created_at": now,
            }
            self._events.insert(0, entry)
            self._events = self._events[:500]
            self._id_event += 1
            try:
                self._conn.execute(
                    "INSERT INTO events (scan_id, message, event_type, created_at) "
                    "VALUES (?,?,?,?)",
                    (scan_id, message, event_type, now),
                )
                self._conn.commit()
            except Exception:
                pass
            return entry

    def get_events(self, limit: int = 100, scan_id: Optional[int] = None) -> List[dict]:
        with _lock:
            results = self._events
            if scan_id is not None:
                results = [e for e in results if e.get("scan_id") == scan_id]
            return results[:limit]

    # ── Helpers ────────────────────────────────────────────────────────────────
    def clear_all(self) -> None:
        """Wipe everything — used for fresh scan."""
        with _lock:
            self._findings.clear()
            self._assets.clear()
            self._scans.clear()
            self._events.clear()
            self._id_finding = self._id_asset = self._id_scan = self._id_event = 1
            self._conn.executescript(
                "DELETE FROM findings; DELETE FROM assets; "
                "DELETE FROM scans; DELETE FROM events;"
            )
            self._conn.commit()

    def stats(self) -> dict:
        with _lock:
            from collections import Counter
            sev_counts = Counter(f["severity"] for f in self._findings)
            return {
                "total_findings": len(self._findings),
                "total_assets":   len(self._assets),
                "total_scans":    len(self._scans),
                "by_severity":    dict(sev_counts),
            }


# ── Module-level singleton — import this everywhere ────────────────────────────
store = ScanStore()
