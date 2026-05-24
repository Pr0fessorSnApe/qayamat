"""
QAYAMAT — HTTP request smuggling probes and web cache poisoning detection.
Conservative, scope-safe checks only.
"""

from __future__ import annotations

import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from core.bugbounty.base import make_finding, safe_get

USER_AGENT = "QAYAMAT-AdvancedHTTP/1.0"


def _parse_host_port(url: str) -> Tuple[str, int, bool]:
    p = urlparse(url if "://" in url else f"https://{url}")
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    use_tls = p.scheme == "https" or port == 443
    return host, port, use_tls


def probe_cl_te_smuggling(base_url: str, policy=None) -> Optional[dict]:
    """
    Detect potential CL.TE desync (informational — requires manual confirmation).
    Sends ambiguous Content-Length / Transfer-Encoding; checks for abnormal response.
    """
    try:
        host, port, use_tls = _parse_host_port(base_url)
        if not host:
            return None
        if policy and not policy.is_in_scope(host):
            return None

        path = urlparse(base_url).path or "/"
        smuggle_probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n\r\n"
            f"G"
        )

        sock = socket.create_connection((host, port), timeout=8)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(smuggle_probe.encode())
        data = sock.recv(4096).decode(errors="ignore")
        sock.close()

        if "400" not in data and len(data) > 50:
            if "timeout" in data.lower() or data.count("HTTP/") > 1:
                return make_finding(
                    title="Potential HTTP Request Smuggling (CL.TE)",
                    severity="High",
                    url=base_url,
                    vuln_type="HTTP Smuggling",
                    description=(
                        "Front-end/back-end may disagree on Content-Length vs Transfer-Encoding. "
                        "Manual confirmation required with a trusted smuggling tool."
                    ),
                    evidence=data[:600],
                    tool="http_smuggling",
                    confidence=0.82,
                )
    except Exception:
        pass
    return None


def scan_cache_poisoning(base_urls: List[str], policy=None) -> List[dict]:
    """
    Test unkeyed headers / path normalization for cache poisoning indicators.
    """
    findings = []
    poison_headers = [
        ("X-Forwarded-Host", "evil-cache-poison.example"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Scheme", "nothttps"),
    ]

    for base in base_urls[:12]:
        url = base if base.startswith("http") else f"https://{base}"
        if policy and hasattr(policy, "validate_request"):
            if not policy.validate_request(url, "GET"):
                continue

        try:
            baseline = safe_get(url, policy=policy)
            if not baseline:
                continue
            base_len = len(baseline.content)

            for hdr, val in poison_headers:
                if not policy.validate_request(url, "GET"):
                    break
                try:
                    r = requests.get(
                        url,
                        headers={hdr: val, "User-Agent": USER_AGENT},
                        timeout=12,
                        verify=False,
                        allow_redirects=False,
                    )
                except requests.RequestException:
                    continue

                body = (r.text or "").lower()
                if val.split(".")[0] in body or "evil-cache" in body:
                    findings.append(make_finding(
                        title=f"Web Cache Poisoning Vector ({hdr})",
                        severity="High",
                        url=url,
                        vuln_type="Cache Poisoning",
                        description=(
                            f"Header `{hdr}` reflected in response — may poison shared cache "
                            "if unkeyed by CDN/proxy."
                        ),
                        evidence=(r.text or "")[:600],
                        tool="cache_poison",
                        confidence=0.9,
                    ))
                    break

                # Cache deception: different status/size on path tricks
                for path in ("/%2e%2e/admin", "/..;/admin", "//admin"):
                    test = url.rstrip("/") + path
                    if policy and not policy.validate_request(test, "GET"):
                        continue
                    r2 = safe_get(test, policy=policy)
                    if r2 and r2.status_code == 200 and abs(len(r2.content) - base_len) > 200:
                        if "admin" in (r2.text or "").lower()[:500]:
                            findings.append(make_finding(
                                title="Web Cache Deception (path normalization)",
                                severity="Medium",
                                url=test,
                                vuln_type="Cache Poisoning",
                                description="Normalized path returns privileged content — verify cache key rules.",
                                evidence=f"status={r2.status_code} len={len(r2.content)}",
                                tool="cache_poison",
                                confidence=0.85,
                            ))
                            break
        except Exception:
            pass

    return findings[:8]


def scan_http_smuggling(base_urls: List[str], policy=None) -> List[dict]:
    findings = []
    for base in base_urls[:6]:
        f = probe_cl_te_smuggling(base, policy=policy)
        if f:
            findings.append(f)
    return findings
