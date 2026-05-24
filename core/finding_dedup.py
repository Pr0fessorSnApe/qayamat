"""
QAYAMAT — Finding deduplication via stable fingerprints.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode


def normalize_url(url: str) -> str:
    if not url:
        return ""
    try:
        p = urlparse(url.strip())
        host = (p.hostname or "").lower()
        path = re.sub(r"/+", "/", p.path or "/")
        qs = parse_qs(p.query, keep_blank_values=True)
        q = urlencode(sorted((k, v[0] if v else "") for k, v in qs.items()))
        return f"{host}{path}" + (f"?{q}" if q else "")
    except Exception:
        return url.lower().strip()


def finding_fingerprint(finding: dict) -> str:
    """Stable hash: host + path + param keys + vuln class + template."""
    url = finding.get("url", "")
    p = urlparse(url if "://" in url else f"https://{url}")
    param_keys = sorted(parse_qs(p.query).keys()) if p.query else []
    parts = [
        (p.hostname or "").lower(),
        (p.path or "/").rstrip("/") or "/",
        ",".join(param_keys),
        (finding.get("vuln_type") or finding.get("title", "")).lower()[:80],
        (finding.get("template") or "").lower(),
        (finding.get("tool") or "").lower(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def merge_findings(primary: dict, duplicate: dict) -> dict:
    """Merge duplicate into primary with affected_urls list."""
    affected = list(primary.get("affected_urls") or [])
    for u in [primary.get("url"), duplicate.get("url")]:
        if u and u not in affected:
            affected.append(u)
    for u in duplicate.get("affected_urls") or []:
        if u not in affected:
            affected.append(u)
    out = {**primary, "affected_urls": affected}
    if len(affected) > 1:
        out["description"] = (
            f"{primary.get('description', '')}\n\n"
            f"[Merged] {len(affected)} affected URLs."
        ).strip()
    return out


class FindingDedup:
    def __init__(self):
        self._seen: Dict[str, dict] = {}

    def add(self, finding: dict) -> Tuple[bool, dict]:
        """Return (is_new, finding_to_save). False = duplicate merged into existing."""
        fp = finding_fingerprint(finding)
        finding["fingerprint"] = fp
        if fp not in self._seen:
            finding.setdefault("affected_urls", [finding.get("url")] if finding.get("url") else [])
            self._seen[fp] = finding
            return True, finding
        merged = merge_findings(self._seen[fp], finding)
        self._seen[fp] = merged
        return False, merged

    def all_unique(self) -> List[dict]:
        return list(self._seen.values())
