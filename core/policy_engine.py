"""
QAYAMAT — Policy Engine
Enforces scope, rate limits, and profile constraints on all operations.
"""

import ipaddress
import re
import yaml
from typing import List, Optional
from urllib.parse import urlparse

from .logger import AuditLogger


class PolicyEngine:
    def __init__(self, config: dict, logger: AuditLogger):
        self.scope: List[str] = []          # in-scope target patterns
        self.out_scope: List[str] = []       # out-of-scope patterns
        self.profile = "passive"
        self.profile_config: dict = {}
        self.logger = logger
        self.config = config

        # ── NEW: flat lists used by recon/vuln_scan workflows ─────────────
        self.targets: List[str] = []         # raw target list from scan_config
        self.out_of_scope: List[str] = []    # raw out-of-scope list
        self._scan_config: dict = {}         # full scan config dict
        self.excluded_vuln_types: List[str] = []
        self.exclusion_keywords: List[str] = []
        self.no_automated_scanning: bool = False

        with open("config/rules/scope_policy.yaml") as f:
            self.rules = yaml.safe_load(f)

        with open("config/rules/forbidden_patterns.yaml") as f:
            self.forbidden = yaml.safe_load(f)

    def update_scope(self, scan_config: dict) -> None:
        # ── Store full config for later access ────────────────────────────
        self._scan_config = scan_config if isinstance(scan_config, dict) else {}

        # ── In-scope / out-of-scope patterns (used by is_in_scope) ────────
        self.scope     = [t.strip() for t in scan_config.get("targets", [])       if t and t.strip()]
        self.out_scope = [o.strip() for o in scan_config.get("out_of_scope", []) if o and o.strip()]

        # ── Parsed exclusions (intelligent OOS text) ─────────────────────
        parsed = scan_config.get("parsed_exclusions") or {}
        if isinstance(parsed, dict):
            self.excluded_vuln_types = list(parsed.get("excluded_vuln_types", []))
            self.exclusion_keywords = list(parsed.get("keywords", []))
            self.no_automated_scanning = bool(parsed.get("no_automated_scanning", False))
            extra_oos = parsed.get("out_of_scope") or []
            for item in extra_oos:
                if item and item not in self.out_scope:
                    self.out_scope.append(item)
        else:
            self.excluded_vuln_types = []
            self.exclusion_keywords = []
            self.no_automated_scanning = False

        # ── Flat target lists (used by recon/vuln_scan workflows) ─────────
        self.targets      = list(self.scope)
        self.out_of_scope = list(self.out_scope)

        # ── Profile ───────────────────────────────────────────────────────
        self.profile = scan_config.get("profile", "passive")

        with open("config/profiles.yaml") as f:
            all_profiles = yaml.safe_load(f)

        if self.profile not in all_profiles:
            self.logger.warning(f"Unknown profile '{self.profile}', defaulting to 'passive'")
            self.profile = "passive"

        self.profile_config = all_profiles[self.profile]
        self.logger.info(f"Scope updated: {len(self.targets)} targets, profile={self.profile}")

    # ── NEW: read-only property so code can also do policy.scan_config ────
    @property
    def scan_config(self) -> dict:
        return self._scan_config

    def _pattern_matches(self, pattern: str, target: str) -> bool:
        """Convert glob-style wildcard pattern to regex and match."""
        regex = re.escape(pattern).replace(r"\*", ".*")
        return bool(re.fullmatch(regex, target, re.IGNORECASE))

    def _is_ip_in_range(self, ip_str: str, cidr: str) -> bool:
        """Check if an IP address falls within a CIDR range."""
        try:
            return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def is_url_excluded(self, url: str) -> bool:
        """Check full URL against path-style out-of-scope patterns."""
        if not url:
            return False
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "/").lower()
            full = f"{host}{path}"
            for pattern in self.out_scope:
                if not pattern:
                    continue
                pat = pattern.lower().strip()
                if pat.startswith("*/") or (pat.startswith("*") and "/" in pat):
                    inner = pat.strip("*")
                    if inner in path or inner in full:
                        return True
                if pat.startswith("/") and pat in path:
                    return True
        except Exception:
            pass
        return False

    def is_in_scope(self, target: str) -> bool:
        """Return True if target is in scope and not excluded."""
        if not target:
            return False

        # Full URL path check
        if "://" in target or target.startswith("/"):
            if self.is_url_excluded(target):
                return False

        # Strip protocol/port if present
        if "://" in target:
            parsed = urlparse(target)
            target = parsed.hostname or target

        # Remove port if still present (e.g. "host:8080")
        if ":" in target and not target.startswith("["):
            target = target.split(":")[0]

        target = target.strip().lower()
        if not target:
            return False

        # Check out-of-scope first
        for pattern in self.out_scope:
            if not pattern:
                continue
            if self._pattern_matches(pattern, target):
                self.logger.info(f"Target {target!r} excluded by out-of-scope rule {pattern!r}")
                return False
            if "/" in pattern:
                try:
                    if self._is_ip_in_range(target, pattern):
                        self.logger.info(f"Target {target!r} excluded by CIDR rule {pattern!r}")
                        return False
                except Exception:
                    pass

        # Check in-scope
        for pattern in self.scope:
            if not pattern:
                continue
            if self._pattern_matches(pattern, target):
                return True
            if "/" in pattern:
                try:
                    if self._is_ip_in_range(target, pattern):
                        return True
                except Exception:
                    pass

        return False

    def validate_request(self, url: str, method: str = "GET") -> bool:
        """Validate a URL is in-scope and the method is allowed."""
        if not url:
            return False

        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False

        if not self.is_in_scope(host):
            self.logger.warning(f"Blocked out-of-scope request to {url}")
            return False

        if self.is_url_excluded(url):
            self.logger.warning(f"Blocked out-of-scope URL path: {url}")
            return False

        # Check method against profile
        allowed_methods = self.profile_config.get("allowed_methods")
        if allowed_methods and method.upper() not in allowed_methods:
            self.logger.warning(f"Method {method} not allowed in profile '{self.profile}'")
            return False

        # Check forbidden paths
        path = parsed.path
        for blocked in self.forbidden.get("blocked_paths", []):
            if path.startswith(blocked):
                self.logger.warning(f"Blocked forbidden path: {path}")
                return False

        return True

    def validate_payload(self, payload: str) -> bool:
        """Check payload against destructive patterns."""
        for pattern in self.forbidden.get("destructive_patterns", []):
            if pattern.lower() in payload.lower():
                self.logger.warning(f"Blocked destructive pattern in payload: {pattern!r}")
                return False
        return True

    def get_rate_limit(self) -> float:
        """Return seconds-per-request delay based on profile."""
        rps = self.profile_config.get("max_requests_per_second", 1)
        return 1.0 / max(rps, 0.01)

    def get_profile(self) -> dict:
        return self.profile_config

    def requires_explicit_auth(self) -> bool:
        return self.profile_config.get("require_explicit_auth", False)
