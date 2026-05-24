"""
QAYAMAT — Session Manager
Manages authenticated HTTP sessions with automatic token refresh.
"""

import time
from typing import Dict, Optional
import requests

from .vault import Vault
from .logger import AuditLogger


class SessionManager:
    def __init__(self, vault: Vault, logger: Optional[AuditLogger] = None):
        self.vault = vault
        self.logger = logger
        self.sessions: Dict[str, dict] = {}

    def create_session(
        self,
        name: str,
        base_url: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
    ) -> requests.Session:
        sess = requests.Session()
        sess.verify = verify_ssl

        if cookies:
            for k, v in cookies.items():
                sess.cookies.set(k, v)

        default_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; QAYAMAT-Scanner/1.0)",
        }
        default_headers.update(headers or {})
        sess.headers.update(default_headers)

        self.sessions[name] = {
            "session": sess,
            "base_url": base_url.rstrip("/"),
            "created_at": time.time(),
            "refresh_token": None,
            "jwt_expires": None,
        }
        if self.logger:
            self.logger.info(f"Session '{name}' created for {base_url}")
        return sess

    def get_session(self, name: str) -> Optional[requests.Session]:
        entry = self.sessions.get(name)
        if not entry:
            return None
        return entry["session"]

    def set_bearer_token(self, name: str, token: str) -> None:
        """Set a JWT/Bearer token on an existing session."""
        entry = self.sessions.get(name)
        if entry:
            entry["session"].headers.update({"Authorization": f"Bearer {token}"})

    def refresh_jwt(
        self,
        name: str,
        refresh_token: str,
        refresh_url: Optional[str] = None,
        token_field: str = "access_token",
    ) -> Optional[str]:
        """
        Perform a token refresh. Posts to refresh_url (or base_url/auth/refresh)
        with the refresh_token and updates the session's Authorization header.
        Returns the new access token, or None on failure.
        """
        entry = self.sessions.get(name)
        if not entry:
            if self.logger:
                self.logger.error(f"Session '{name}' not found for JWT refresh")
            return None

        url = refresh_url or f"{entry['base_url']}/auth/refresh"
        try:
            resp = entry["session"].post(
                url,
                json={"refresh_token": refresh_token},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            new_token = data.get(token_field)
            if new_token:
                self.set_bearer_token(name, new_token)
                entry["refresh_token"] = refresh_token
                if self.logger:
                    self.logger.info(f"JWT refreshed for session '{name}'")
                return new_token
        except Exception as e:
            if self.logger:
                self.logger.error(f"JWT refresh failed for session '{name}': {e}")
        return None

    def close_session(self, name: str) -> None:
        entry = self.sessions.pop(name, None)
        if entry:
            entry["session"].close()

    def close_all(self) -> None:
        for name in list(self.sessions.keys()):
            self.close_session(name)
