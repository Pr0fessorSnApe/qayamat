"""
QAYAMAT — Out-of-band (OOB) callback integration (Interactsh-compatible).
"""

import json
import time
import uuid
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests


class OOBServer:
    """Register OOB payloads and poll for blind SSRF/XSS/XXE callbacks."""

    # Interactsh-compatible public server (ProjectDiscovery)
    DEFAULT_SERVER = "https://oast.pro"

    def __init__(self, server: str = "", correlation_id: Optional[str] = None):
        self.server = (server or self.DEFAULT_SERVER).rstrip("/")
        self.correlation_id = correlation_id or uuid.uuid4().hex[:12]
        self._subdomain: Optional[str] = None
        self._token: Optional[str] = None

    def register(self) -> str:
        """Register a new OOB subdomain. Returns full callback host."""
        try:
            resp = requests.post(
                f"{self.server}/register",
                headers={"Content-Type": "application/json"},
                json={},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._subdomain = data.get("data", data.get("domain", ""))
                if isinstance(self._subdomain, dict):
                    self._subdomain = self._subdomain.get("domain", "")
                self._token = data.get("secret", data.get("token", ""))
                if self._subdomain:
                    return self._subdomain
        except Exception:
            pass
        # Fallback: synthetic subdomain for payload tagging (manual correlation)
        self._subdomain = f"{self.correlation_id}.oob.qayamat.local"
        return self._subdomain

    @property
    def callback_host(self) -> str:
        if not self._subdomain:
            self.register()
        return self._subdomain or ""

    def payload_url(self, tag: str = "xss") -> str:
        host = self.callback_host
        return f"http://{tag}.{host}" if "." in host else f"http://{host}/{tag}"

    def poll_interactions(self, timeout: int = 5) -> List[Dict]:
        """Fetch OOB interactions since last poll."""
        if not self._token and not self._subdomain:
            return []
        try:
            headers = {}
            if self._token:
                headers["Authorization"] = self._token
            resp = requests.get(
                f"{self.server}/poll",
                params={"id": self._subdomain, "secret": self._token or ""},
                headers=headers,
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", data.get("interactions", [])) or []
        except Exception:
            pass
        return []

    def correlate_findings(self, scan_id: int, store) -> List[dict]:
        """Create findings from OOB hits."""
        findings = []
        for hit in self.poll_interactions():
            protocol = hit.get("protocol", "http")
            remote = hit.get("remote-address", hit.get("client-ip", ""))
            raw = hit.get("raw-request", hit.get("q", ""))[:500]
            findings.append({
                "title": f"OOB Callback Received ({protocol})",
                "severity": "high",
                "vuln_type": "OOB",
                "url": self.callback_host,
                "description": f"Blind interaction from {remote}. Possible SSRF/XSS/XXE.",
                "evidence": str(raw),
                "tool": "oob_server",
                "tags": ["oob", "blind"],
            })
        return findings
