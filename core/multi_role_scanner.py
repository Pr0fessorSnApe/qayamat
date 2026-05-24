"""
QAYAMAT — Multi-role authenticated scanning (anon vs user vs admin).
"""

from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

import requests

from core.session_manager import SessionManager


class MultiRoleScanner:
    ROLES = ("anonymous", "user", "admin")

    def __init__(self, session_mgr: SessionManager, logger=None):
        self.session_mgr = session_mgr
        self.logger = logger

    def setup_roles(self, base_url: str, roles: Dict[str, Dict[str, str]]) -> None:
        """
        roles: {"user": {"Cookie": "..."}, "admin": {"Authorization": "Bearer ..."}}
        """
        self.session_mgr.create_session("anonymous", base_url, headers={})
        for role, headers in roles.items():
            self.session_mgr.create_session(role, base_url, headers=headers)

    def probe_endpoint(
        self,
        path: str,
        method: str = "GET",
        roles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Compare status codes across roles for IDOR / privilege issues."""
        roles = roles or list(self.session_mgr.sessions.keys()) or ["anonymous"]
        results = {}
        for role in roles:
            sess = self.session_mgr.get_session(role)
            if not sess:
                continue
            base = self.session_mgr.sessions[role]["base_url"]
            url = urljoin(base + "/", path.lstrip("/"))
            try:
                resp = sess.request(method, url, timeout=10, verify=False)
                results[role] = {"status": resp.status_code, "len": len(resp.content)}
            except Exception as e:
                results[role] = {"status": 0, "error": str(e)}

        finding = self._analyze_results(path, method, results)
        return {"path": path, "results": results, "finding": finding}

    def _analyze_results(self, path: str, method: str, results: dict) -> Optional[dict]:
        anon = results.get("anonymous", results.get("anon", {}))
        user = results.get("user", {})
        admin = results.get("admin", {})

        anon_st = anon.get("status", 0)
        user_st = user.get("status", 0)
        admin_st = admin.get("status", 0)

        # IDOR: anon blocked, user gets data
        if anon_st in (401, 403) and user_st == 200:
            return {
                "title": f"Broken Access Control (IDOR): {path}",
                "severity": "high",
                "vuln_type": "IDOR",
                "url": path,
                "description": f"Anonymous={anon_st}, User={user_st}, Admin={admin_st}. User can access restricted resource.",
                "evidence": str(results),
                "tool": "multi_role_scanner",
            }

        # Privilege escalation: user same as admin on admin path
        if "admin" in path.lower() and user_st == 200 and admin_st == 200:
            if anon_st in (401, 403):
                return {
                    "title": f"Privilege Escalation: {path}",
                    "severity": "critical",
                    "vuln_type": "Broken Access Control",
                    "url": path,
                    "description": "Standard user can access admin endpoint.",
                    "evidence": str(results),
                    "tool": "multi_role_scanner",
                }
        return None

    def scan_paths(self, paths: List[str], roles_config: Dict[str, Dict]) -> List[dict]:
        findings = []
        if not paths:
            return findings
        base = self.session_mgr.sessions.get("anonymous", {}).get("base_url", "")
        if roles_config and base:
            self.setup_roles(base, roles_config)
        for path in paths[:30]:
            out = self.probe_endpoint(path)
            if out.get("finding"):
                findings.append(out["finding"])
        return findings
