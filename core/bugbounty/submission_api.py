"""
QAYAMAT — One-click HackerOne / Bugcrowd API submission.
Requires user API tokens in .env (authorized programs only).
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from core.repro_steps import enrich_finding_with_steps
from workflows.submission_report import SEVERITY_MAP_H1, SubmissionReportBuilder


class PlatformSubmissionError(Exception):
    pass


class HackerOneSubmitter:
    """HackerOne Hacker API — https://api.hackerone.com/v1/hackers/reports"""

    BASE = "https://api.hackerone.com/v1"

    def __init__(self, identifier: str = "", token: str = ""):
        self.identifier = identifier or os.getenv("HACKERONE_API_IDENTIFIER", "")
        self.token = token or os.getenv("HACKERONE_API_TOKEN", "")

    @property
    def configured(self) -> bool:
        return bool(self.identifier and self.token)

    def _auth_header(self) -> dict:
        raw = f"{self.identifier}:{self.token}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    def submit_report(
        self,
        finding: dict,
        team_handle: str,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        if not self.configured:
            raise PlatformSubmissionError(
                "Set HACKERONE_API_IDENTIFIER and HACKERONE_API_TOKEN in .env"
            )
        if not team_handle:
            raise PlatformSubmissionError("team_handle (program handle) is required")

        f = enrich_finding_with_steps(dict(finding))
        sev = SEVERITY_MAP_H1.get(f.get("severity", "Medium"), "medium")
        body_md = SubmissionReportBuilder([f]).build_markdown(f, "hackerone")

        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": team_handle.strip().lstrip("@"),
                    "title": (f.get("title") or "Security vulnerability")[:250],
                    "vulnerability_information": body_md[:25000],
                    "severity_rating": sev,
                    "weakness_id": None,
                },
            }
        }

        if dry_run:
            return {"dry_run": True, "platform": "hackerone", "payload_preview": payload}

        url = f"{self.BASE}/hackers/reports"
        resp = requests.post(
            url,
            json=payload,
            headers={**self._auth_header(), "Content-Type": "application/json"},
            timeout=60,
        )
        if resp.status_code not in (200, 201):
            raise PlatformSubmissionError(f"HackerOne API {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        report_id = data.get("data", {}).get("id", "")
        return {
            "platform": "hackerone",
            "success": True,
            "report_id": report_id,
            "url": f"https://hackerone.com/reports/{report_id}" if report_id else "",
            "response": data,
        }


class BugcrowdSubmitter:
    """Bugcrowd submission API (v4-style; program code required)."""

    BASE = "https://api.bugcrowd.com"

    def __init__(self, api_token: str = ""):
        self.api_token = api_token or os.getenv("BUGCROWD_API_TOKEN", "")

    @property
    def configured(self) -> bool:
        return bool(self.api_token)

    def _headers(self) -> dict:
        return {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/vnd.bugcrowd+json",
            "Accept": "application/vnd.bugcrowd+json",
        }

    def submit_report(
        self,
        finding: dict,
        program_code: str,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        if not self.configured:
            raise PlatformSubmissionError("Set BUGCROWD_API_TOKEN in .env")
        if not program_code:
            raise PlatformSubmissionError("program_code is required")

        f = enrich_finding_with_steps(dict(finding))
        attrs = SubmissionReportBuilder([f]).build_bugcrowd_json(f)

        payload = {
            "data": {
                "type": "submission",
                "attributes": {
                    "title": attrs["title"][:250],
                    "description": attrs["description"],
                    "severity": attrs["severity"],
                    "vrt_id": "other",
                    "target": {"type": "uri", "uri": attrs.get("url") or "https://example.com"},
                },
                "relationships": {
                    "program": {"data": {"type": "program", "id": program_code}},
                },
            }
        }

        if dry_run:
            return {"dry_run": True, "platform": "bugcrowd", "payload_preview": payload}

        # Bugcrowd API paths vary by account; try common submissions endpoint
        url = f"{self.BASE}/submissions"
        resp = requests.post(url, json=payload, headers=self._headers(), timeout=60)
        if resp.status_code not in (200, 201, 202):
            raise PlatformSubmissionError(f"Bugcrowd API {resp.status_code}: {resp.text[:500]}")

        data = resp.json() if resp.text else {}
        sub_id = data.get("data", {}).get("id", "")
        return {
            "platform": "bugcrowd",
            "success": True,
            "submission_id": sub_id,
            "response": data,
        }


def submit_finding(
    finding: dict,
    platform: str,
    program_ref: str,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    platform: hackerone | bugcrowd
    program_ref: H1 team_handle or Bugcrowd program code
    """
    platform = platform.lower().strip()
    if platform == "hackerone":
        return HackerOneSubmitter().submit_report(finding, program_ref, dry_run=dry_run)
    if platform == "bugcrowd":
        return BugcrowdSubmitter().submit_report(finding, program_ref, dry_run=dry_run)
    raise PlatformSubmissionError(f"Unknown platform: {platform}")


def submission_status() -> dict:
    return {
        "hackerone": HackerOneSubmitter().configured,
        "bugcrowd": BugcrowdSubmitter().configured,
    }
