"""
QAYAMAT — SSTI (Server-Side Template Injection) auto-verification.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.bugbounty.base import filter_urls, make_finding, safe_get
from core.payload_engine import PayloadEngine

# Confirmed evaluation markers per engine
SSTI_MARKERS = [
    (re.compile(r"\b49\b"), "{{7*7}}", "Jinja2/Twig"),
    (re.compile(r"\b49\b"), "${7*7}", "Freemarker/EL"),
    (re.compile(r"\b49\b"), "<%= 7*7 %>", "ERB"),
    (re.compile(r"7777777"), "{{7*'7'}}", "Jinja2 string mult"),
]

SENSITIVE_PARAMS = (
    "name", "q", "query", "search", "template", "view", "page", "content",
    "message", "body", "title", "text", "render", "layout", "id", "file",
)


def _inject_param(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    new_q = urlencode([(k, v[0] if v else "") for k, v in qs.items()])
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def _urls_with_params(urls: List[str]) -> List[str]:
    out = []
    for u in urls:
        if "?" in u and "=" in u:
            out.append(u)
    return out


def verify_ssti_on_url(url: str, policy=None, timeout: int = 12) -> Optional[dict]:
    p = urlparse(url)
    params = list(parse_qs(p.query).keys())
    if not params:
        return None

    engine = PayloadEngine()
    payloads = engine.generate("ssti") + ["{{7*'7'}}", "${{7*7}}", "#{7*7}"]

    for param in params[:5]:
        if param.lower() not in SENSITIVE_PARAMS and len(params) > 3:
            continue
        for payload in payloads[:8]:
            test_url = _inject_param(url, param, payload)
            if policy and hasattr(policy, "validate_request"):
                if not policy.validate_request(test_url, "GET"):
                    continue
            resp = safe_get(test_url, policy=policy, timeout=timeout)
            if not resp or resp.status_code >= 500:
                continue
            body = resp.text or ""
            for pattern, pl, eng in SSTI_MARKERS:
                if pl == payload or payload in (pl, "{{7*7}}", "${7*7}"):
                    if pattern.search(body) and "49" in body:
                        return make_finding(
                            title=f"SSTI Confirmed ({eng})",
                            severity="Critical",
                            url=test_url,
                            vuln_type="SSTI",
                            description=(
                                f"Parameter `{param}` evaluates template expression. "
                                f"Payload `{payload}` reflected as computed value in response."
                            ),
                            evidence=body[:800],
                            tool="ssti_verifier",
                            confidence=0.94,
                            extra={"parameter": param, "engine": eng, "payload": payload},
                        )
            # Generic: payload echoed with evaluation
            if "49" in body and ("{{" in payload or "${" in payload or "<%" in payload):
                if payload.replace(" ", "")[:6] in body or "{{7*7}}" in payload:
                    return make_finding(
                        title="SSTI Confirmed (template evaluation)",
                        severity="High",
                        url=test_url,
                        vuln_type="SSTI",
                        description=f"Parameter `{param}` may evaluate server-side templates.",
                        evidence=body[:800],
                        tool="ssti_verifier",
                        confidence=0.88,
                        extra={"parameter": param, "payload": payload},
                    )
    return None


def scan_ssti(urls: List[str], policy=None, limit: int = 25, workers: int = 4) -> List[dict]:
    """Run SSTI verification on parameterized URLs."""
    targets = _urls_with_params(filter_urls(urls, policy))[:limit]
    findings = []
    if not targets:
        return findings

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(verify_ssti_on_url, u, policy): u for u in targets}
        for fut in as_completed(futures):
            try:
                f = fut.result()
                if f:
                    findings.append(f)
            except Exception:
                pass
            time.sleep(0.15)

    return findings
