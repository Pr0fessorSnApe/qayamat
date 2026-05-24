"""
QAYAMAT — Business logic race condition tester (parallel request bursts).
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from core.bugbounty.base import filter_urls, make_finding

USER_AGENT = "QAYAMAT-RaceTester/1.0"

# Endpoints likely to have race/logic flaws
RACE_PATH_RE = re.compile(
    r"(?i)(/api/|/v\d+/).*(coupon|redeem|vote|transfer|withdraw|purchase|"
    r"checkout|apply|claim|reward|invite|register|reset|confirm|order|"
    r"balance|credit|points|gift|promo|discount)"
)

SUCCESS_MARKERS = re.compile(
    r"(?i)(success|completed|applied|redeemed|transferred|created|\"ok\"|true)",
)


def _race_probe(
    url: str,
    method: str = "POST",
    headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    threads: int = 8,
    policy=None,
) -> Optional[dict]:
    if policy and hasattr(policy, "validate_request"):
        if not policy.validate_request(url, method):
            return None

    hdrs = {**(headers or {}), "User-Agent": USER_AGENT}
    results = []

    def _one():
        try:
            if method.upper() == "POST":
                r = requests.post(
                    url, headers=hdrs, json=json_body or {}, timeout=15, verify=False
                )
            else:
                r = requests.get(url, headers=hdrs, timeout=15, verify=False)
            return r.status_code, len(r.content), (r.text or "")[:500]
        except requests.RequestException:
            return 0, 0, ""

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_one) for _ in range(threads)]
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass

    if len(results) < 4:
        return None

    success_hits = sum(
        1 for st, _, body in results
        if st == 200 and SUCCESS_MARKERS.search(body)
    )
    statuses = [st for st, _, _ in results]

    # Race: multiple parallel successes when operation should be single-use
    if success_hits >= 3 and 200 in statuses:
        return make_finding(
            title="Potential Race Condition (parallel success)",
            severity="High",
            url=url,
            vuln_type="Business Logic",
            description=(
                f"{success_hits}/{threads} parallel {method} requests returned success-like "
                "responses — verify single-use limits (coupon, transfer, vote, etc.)."
            ),
            evidence=str(results[:5]),
            tool="race_tester",
            confidence=0.84,
            extra={"parallel_success": success_hits, "threads": threads},
        )

    # Inconsistent state: mixed 200/409/500 across burst
    unique_ok = len(set(statuses))
    if success_hits >= 2 and unique_ok >= 3:
        return make_finding(
            title="Inconsistent State Under Parallel Requests",
            severity="Medium",
            url=url,
            vuln_type="Business Logic",
            description="Parallel requests produced inconsistent status codes — possible logic flaw.",
            evidence=str(results[:5]),
            tool="race_tester",
            confidence=0.78,
        )

    return None


def _candidate_urls(urls: List[str]) -> List[str]:
    out = []
    for u in urls:
        path = urlparse(u if "://" in u else f"https://{u}").path
        if RACE_PATH_RE.search(path) or RACE_PATH_RE.search(u):
            out.append(u if "://" in u else f"https://{u}")
    return list(dict.fromkeys(out))[:15]


def scan_race_conditions(
    urls: List[str],
    policy=None,
    auth_headers: Optional[dict] = None,
    profile: str = "safe",
) -> List[dict]:
    """
    Race testing only on balanced+ profiles to reduce accidental load.
    """
    if profile in ("passive", "safe"):
        return []

    targets = _candidate_urls(filter_urls(urls, policy))
    findings = []
    for url in targets:
        for method in ("POST", "GET"):
            f = _race_probe(url, method=method, headers=auth_headers, threads=6, policy=policy)
            if f:
                findings.append(f)
                break
        time.sleep(0.3)

    return findings[:5]
