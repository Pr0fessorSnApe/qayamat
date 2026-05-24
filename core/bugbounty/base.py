"""
Shared helpers for bug bounty scanners — scope-safe HTTP and finding builders.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 12
USER_AGENT = "QAYAMAT-BB-Scanner/1.0 (Authorized-Security-Testing)"


def safe_get(
    url: str,
    policy=None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
) -> Optional[requests.Response]:
    if policy and hasattr(policy, "validate_request"):
        if not policy.validate_request(url, "GET"):
            return None
    try:
        return requests.get(
            url,
            headers={**(headers or {}), "User-Agent": USER_AGENT},
            timeout=timeout,
            verify=False,
            allow_redirects=allow_redirects,
        )
    except requests.RequestException:
        return None


def host_in_scope(host: str, policy) -> bool:
    if not policy:
        return True
    return policy.is_in_scope(host)


def filter_urls(urls: List[str], policy) -> List[str]:
    out = []
    for u in urls:
        try:
            h = urlparse(u if "://" in u else f"https://{u}").hostname
            if h and host_in_scope(h, policy):
                out.append(u if "://" in u else f"https://{u}")
        except Exception:
            pass
    return out


def make_finding(
    title: str,
    severity: str,
    url: str,
    vuln_type: str,
    description: str,
    evidence: str,
    tool: str,
    confidence: float = 0.9,
    extra: Optional[dict] = None,
) -> dict:
    f = {
        "title": title,
        "severity": severity.capitalize() if severity else "Medium",
        "url": url,
        "vuln_type": vuln_type,
        "description": description,
        "evidence": (evidence or "")[:2000],
        "tool": tool,
        "validation_score": confidence,
        "validation_reason": f"{tool} high-confidence signal",
    }
    if extra:
        f.update(extra)
    return f


def extract_hosts(urls: List[str]) -> List[str]:
    hosts = []
    for u in urls:
        try:
            h = urlparse(u if "://" in u else f"https://{u}").hostname
            if h:
                hosts.append(h.lower())
        except Exception:
            pass
    return list(dict.fromkeys(hosts))
