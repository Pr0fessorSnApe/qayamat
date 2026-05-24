"""
Individual bug bounty scanners — conservative, scope-aware, high-confidence only.
"""

from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

from core.bugbounty.base import (
    DEFAULT_TIMEOUT,
    extract_hosts,
    filter_urls,
    make_finding,
    safe_get,
)
from core.oos_parser import IntelligentExclusionsParser

# ─── 1. CT Monitor ───────────────────────────────────────────────────────────

def scan_ct_logs(domains: List[str], policy=None) -> List[dict]:
    """Discover subdomains via crt.sh (passive)."""
    findings = []
    assets = []
    for domain in domains[:5]:
        if not policy or not policy.is_in_scope(domain):
            continue
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            import requests
            r = requests.get(url, timeout=20, headers={"User-Agent": "QAYAMAT"})
            if r.status_code != 200:
                continue
            data = r.json() if r.text.strip().startswith("[") else []
            seen = set()
            for entry in data[:200]:
                name = (entry.get("name_value") or "").split("\n")[0].lower().strip()
                if not name or name in seen or "*" in name:
                    continue
                seen.add(name)
                if policy and policy.is_in_scope(name):
                    assets.append({"host": name, "source": "ct_log"})
        except Exception:
            pass
    if assets:
        findings.append(make_finding(
            title=f"CT Log Discovery ({len(assets)} in-scope hosts)",
            severity="Info",
            url=f"https://{domains[0]}" if domains else "",
            vuln_type="Attack Surface",
            description=f"Certificate transparency revealed {len(assets)} in-scope hostnames.",
            evidence=json.dumps(assets[:30]),
            tool="ct_monitor",
            confidence=0.95,
        ))
    return findings


# ─── 2. Asset Priority Scorer ────────────────────────────────────────────────

def score_assets(urls: List[str], live_hosts: List[dict], findings: List[dict]) -> List[dict]:
    """Return prioritized asset list (metadata only, no vuln)."""
    scores = []
    finding_hosts = {urlparse(f.get("url", "")).hostname for f in findings if f.get("url")}
    for url in urls[:500]:
        try:
            p = urlparse(url if "://" in url else f"https://{url}")
            host, path = p.hostname or "", (p.path or "/").lower()
            score = 0.0
            if any(k in path for k in ("/api", "/admin", "/graphql", "/oauth", "/auth", "/login")):
                score += 3.0
            if "?" in url:
                score += 1.5
            if host in finding_hosts:
                score += 2.0
            if any(k in host for k in ("api", "admin", "staging", "dev", "internal")):
                score += 1.0
            scores.append({"url": url, "priority_score": round(score, 2)})
        except Exception:
            pass
    scores.sort(key=lambda x: -x["priority_score"])
    if scores[:10]:
        return [make_finding(
            title="Asset Priority Ranking",
            severity="Info",
            url=scores[0]["url"],
            vuln_type="Scan Note",
            description="Top targets for manual review based on path and prior signals.",
            evidence=json.dumps(scores[:15]),
            tool="asset_scorer",
            confidence=0.99,
        )]
    return []


# ─── 3. JS Bundle Miner ───────────────────────────────────────────────────────

JS_ENDPOINT_RE = re.compile(
    r'["\'](/api/[^"\']+|/v\d+/[^"\']+)["\']|'
    r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
    re.I,
)
SECRET_IN_JS_RE = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|aws_access|private_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"
)


def scan_js_bundles(urls: List[str], policy=None, limit: int = 15) -> List[dict]:
    findings = []
    checked = 0
    for page_url in filter_urls(urls, policy):
        if checked >= limit:
            break
        if not any(page_url.endswith(ext) for ext in (".js", "")) and ".js" not in page_url:
            # Fetch HTML pages for script src
            resp = safe_get(page_url, policy=policy)
            if not resp or resp.status_code != 200:
                continue
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)', resp.text, re.I)
        else:
            scripts = [page_url]
        for script_url in scripts[:5]:
            if script_url.startswith("/"):
                script_url = urljoin(page_url, script_url)
            if checked >= limit:
                break
            checked += 1
            r = safe_get(script_url, policy=policy)
            if not r or r.status_code != 200 or len(r.content) < 50:
                continue
            body = r.text[:500000]
            endpoints = list(set(JS_ENDPOINT_RE.findall(body)))[:20]
            if endpoints:
                flat = [e[0] if isinstance(e, tuple) else e for e in endpoints]
                findings.append(make_finding(
                    title=f"Hidden API Endpoints in JavaScript",
                    severity="Medium",
                    url=script_url,
                    vuln_type="Attack Surface",
                    description=f"Discovered {len(flat)} API paths in JS bundle.",
                    evidence=json.dumps(flat[:15]),
                    tool="js_miner",
                    confidence=0.88,
                ))
            for m in SECRET_IN_JS_RE.finditer(body):
                findings.append(make_finding(
                    title="Hardcoded Secret in JavaScript",
                    severity="Critical",
                    url=script_url,
                    vuln_type="Secret Leak",
                    description=f"Potential {m.group(1)} in client-side bundle.",
                    evidence=f"{m.group(1)}=[REDACTED len={len(m.group(2))}]",
                    tool="js_miner",
                    confidence=0.92,
                ))
                break
    return findings


# ─── 4. Ghost Endpoints (archive vs live) ─────────────────────────────────────

def scan_ghost_endpoints(archive_urls: List[str], live_urls: Set[str], policy=None) -> List[dict]:
    findings = []
    live_paths = {urlparse(u).path.rstrip("/") for u in live_urls if u}
    ghosts = []
    for url in archive_urls[:300]:
        if not policy:
            continue
        try:
            p = urlparse(url)
            if not policy.is_in_scope(p.hostname or ""):
                continue
            path = p.path.rstrip("/") or "/"
            if path not in live_paths and len(path) > 3:
                sensitive = any(s in path.lower() for s in (
                    "admin", "backup", "debug", "internal", "api/v", "config", ".git"
                ))
                if sensitive:
                    ghosts.append(url)
        except Exception:
            pass
    for ghost in ghosts[:5]:
        r = safe_get(ghost, policy=policy)
        if r and r.status_code == 200 and len(r.content) > 100:
            findings.append(make_finding(
                title="Archived Endpoint Still Live",
                severity="Medium",
                url=ghost,
                vuln_type="Discovery",
                description="Historical URL responds with 200 — may be forgotten attack surface.",
                evidence=f"HTTP {r.status_code}, length={len(r.content)}",
                tool="ghost_endpoints",
                confidence=0.85,
            ))
    return findings


# ─── 5. OpenAPI Discovery ────────────────────────────────────────────────────

OPENAPI_PATHS = (
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/api/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
)


def scan_openapi(base_urls: List[str], policy=None) -> List[dict]:
    findings = []
    seen = set()
    for base in base_urls[:20]:
        try:
            p = urlparse(base if "://" in base else f"https://{base}")
            origin = f"{p.scheme}://{p.netloc}"
            if origin in seen:
                continue
            seen.add(origin)
            for path in OPENAPI_PATHS:
                url = origin + path
                r = safe_get(url, policy=policy)
                if not r or r.status_code != 200:
                    continue
                try:
                    doc = r.json()
                except Exception:
                    continue
                if "openapi" in doc or "swagger" in doc:
                    paths_count = len(doc.get("paths", {}))
                    findings.append(make_finding(
                        title="Exposed OpenAPI/Swagger Specification",
                        severity="Medium",
                        url=url,
                        vuln_type="API Exposure",
                        description=f"Public API spec with {paths_count} paths — review for sensitive operations.",
                        evidence=json.dumps(list(doc.get("paths", {}).keys())[:20]),
                        tool="openapi_discovery",
                        confidence=0.9,
                    ))
                    break
        except Exception:
            pass
    return findings


# ─── 6. IDOR / BOLA (extends multi-role patterns) ────────────────────────────

ID_PATTERNS = re.compile(r"(/users?/|/accounts?/|/orders?/|/invoices?/)(\d+)", re.I)


def scan_idor_urls(urls: List[str], policy=None, session_headers: Optional[dict] = None) -> List[dict]:
    findings = []
    tested = set()
    headers = session_headers or {}
    for url in filter_urls(urls, policy):
        m = ID_PATTERNS.search(url)
        if not m or url in tested:
            continue
        tested.add(url)
        base_id = m.group(2)
        alt_id = str(int(base_id) + 1) if base_id.isdigit() else "1"
        alt_url = url.replace(f"/{base_id}", f"/{alt_id}", 1)
        r1 = safe_get(url, policy=policy, headers=headers)
        r2 = safe_get(alt_url, policy=policy, headers=headers)
        if not r1 or not r2:
            continue
        if r1.status_code == 200 and r2.status_code == 200:
            if abs(len(r1.content) - len(r2.content)) < 50 and len(r1.content) > 200:
                findings.append(make_finding(
                    title="Potential IDOR (Predictable Object ID)",
                    severity="High",
                    url=url,
                    vuln_type="IDOR",
                    description=f"Swapping ID {base_id}→{alt_id} returns similar 200 responses — verify authorization.",
                    evidence=f"url1={r1.status_code} len={len(r1.content)} | url2={r2.status_code} len={len(r2.content)}",
                    tool="idor_tester",
                    confidence=0.82,
                ))
    return findings[:10]


# ─── 7. OAuth / OIDC ───────────────────────────────────────────────────────────

def scan_oauth(urls: List[str], policy=None) -> List[dict]:
    findings = []
    oauth_urls = [u for u in filter_urls(urls, policy) if "oauth" in u.lower() or "authorize" in u.lower()]
    for url in oauth_urls[:10]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        redirect = (qs.get("redirect_uri") or qs.get("redirect") or [""])[0]
        if redirect and redirect.startswith("http"):
            # Test open redirect via redirect_uri
            evil = "https://evil.example.com/callback"
            test_qs = dict(qs)
            test_qs["redirect_uri"] = [evil]
            from urllib.parse import urlencode
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_qs, doseq=True)}"
            r = safe_get(test_url, policy=policy, allow_redirects=False)
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.example" in loc:
                    findings.append(make_finding(
                        title="OAuth redirect_uri Not Validated",
                        severity="High",
                        url=url,
                        vuln_type="OAuth",
                        description="Authorization endpoint reflects arbitrary redirect_uri.",
                        evidence=f"Location: {loc[:200]}",
                        tool="oauth_tester",
                        confidence=0.9,
                    ))
    return findings


# ─── 8. CORS Hunter ──────────────────────────────────────────────────────────

def scan_cors(base_urls: List[str], policy=None) -> List[dict]:
    findings = []
    origins = ["https://evil-attacker.example", "null"]
    for base in base_urls[:15]:
        try:
            p = urlparse(base if "://" in base else f"https://{base}")
            url = f"{p.scheme}://{p.netloc}/"
            if not policy or not policy.is_in_scope(p.hostname or ""):
                continue
            for origin in origins:
                import requests
                if not policy.validate_request(url, "GET"):
                    continue
                try:
                    r = requests.get(
                        url, headers={"Origin": origin}, timeout=DEFAULT_TIMEOUT, verify=False
                    )
                except requests.RequestException:
                    continue
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == origin or (acao == "*" and origin != "null"):
                    sev = "High" if acac == "true" else "Medium"
                    findings.append(make_finding(
                        title="CORS Misconfiguration",
                        severity=sev,
                        url=url,
                        vuln_type="CORS",
                        description=f"Reflects Origin {origin!r} with ACAO={acao!r}, credentials={acac}.",
                        evidence=f"ACAO={acao}, ACAC={acac}",
                        tool="cors_hunter",
                        confidence=0.92,
                    ))
                    break
        except Exception:
            pass
    return findings


# ─── 9. SSRF Verifier ────────────────────────────────────────────────────────

SSRF_PARAMS = ("url", "uri", "path", "dest", "redirect", "next", "target", "rurl", "return")


def scan_ssrf_candidates(urls: List[str], policy=None, oob_host: str = "") -> List[dict]:
    findings = []
    for url in filter_urls([u for u in urls if "?" in u], policy)[:30]:
        try:
            p = urlparse(url)
            qs = parse_qs(p.query)
            for param in SSRF_PARAMS:
                if param not in qs:
                    continue
                # Only report if internal/metadata pattern in response — not blind noise
                test_url = re.sub(
                    rf"({param}=)[^&]+",
                    rf"\g<1>http://127.0.0.1/",
                    url,
                    count=1,
                    flags=re.I,
                )
                r = safe_get(test_url, policy=policy, allow_redirects=False)
                if not r:
                    continue
                body = (r.text or "")[:3000].lower()
                indicators = (
                    "ami-id", "instance-id", "compute.internal",
                    "metadata.google", "169.254.169.254",
                )
                if any(ind in body for ind in indicators):
                    findings.append(make_finding(
                        title="SSRF — Cloud Metadata Exposure",
                        severity="Critical",
                        url=url,
                        vuln_type="SSRF",
                        description=f"Parameter {param} may reach internal/cloud metadata.",
                        evidence=body[:500],
                        tool="ssrf_verifier",
                        confidence=0.95,
                    ))
                    break
        except Exception:
            pass
    return findings


# ─── 10. Host Header / Password Reset ────────────────────────────────────────

def scan_host_header(base_urls: List[str], policy=None) -> List[dict]:
    findings = []
    for base in base_urls[:8]:
        try:
            p = urlparse(base if "://" in base else f"https://{base}")
            url = f"{p.scheme}://{p.netloc}/"
            for path in ("/forgot-password", "/reset-password", "/password/reset", "/api/password/reset"):
                test_url = urljoin(url, path)
                if not policy or not policy.validate_request(test_url, "GET"):
                    continue
                import requests
                try:
                    r = requests.get(
                        test_url,
                        headers={"Host": "evil.example.com", "X-Forwarded-Host": "evil.example.com"},
                        timeout=DEFAULT_TIMEOUT,
                        verify=False,
                        allow_redirects=False,
                    )
                except requests.RequestException:
                    continue
                if r.status_code in (200, 302) and "evil.example" in (r.text or "").lower():
                    findings.append(make_finding(
                        title="Host Header Injection on Password Reset",
                        severity="High",
                        url=test_url,
                        vuln_type="Host Header",
                        description="Password reset flow reflects attacker-controlled Host header.",
                        evidence=f"status={r.status_code}",
                        tool="host_header_tester",
                        confidence=0.88,
                    ))
                    break
        except Exception:
            pass
    return findings


# ─── 11. WAF Detector ────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "cloudflare": ("cf-ray", "cloudflare"),
    "akamai": ("akamai",),
    "aws": ("x-amzn-requestid", "awselb"),
    "imperva": ("incapsula", "visid_incap"),
}


def detect_waf(base_urls: List[str], policy=None) -> List[dict]:
    notes = []
    for base in base_urls[:5]:
        r = safe_get(base if "://" in base else f"https://{base}", policy=policy)
        if not r:
            continue
        hdrs = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower()
        for waf, sigs in WAF_SIGNATURES.items():
            if any(s in hdrs for s in sigs):
                notes.append({"url": base, "waf": waf})
                break
    if notes:
        return [make_finding(
            title="WAF Detected",
            severity="Info",
            url=notes[0]["url"],
            vuln_type="Scan Note",
            description="Adjust scan rate and payloads for WAF presence.",
            evidence=json.dumps(notes),
            tool="waf_detector",
            confidence=0.99,
        )]
    return []


# ─── 12. Policy Parser ───────────────────────────────────────────────────────

def parse_program_policy(rules_text: str) -> dict:
    from core.oos_parser import IntelligentExclusionsParser
    parsed = IntelligentExclusionsParser().parse(rules_text)
    return {
        "out_of_scope": parsed.to_out_of_scope_list(),
        "excluded_vuln_types": parsed.excluded_vuln_types,
        "no_automated_scanning": parsed.no_automated_scanning,
        "max_rps": parsed.max_requests_per_second,
        "keywords": parsed.keywords,
    }


# ─── 13. Scope Drift ─────────────────────────────────────────────────────────

def check_scope_drift(program_name: str, current_targets: List[str]) -> dict:
    path = Path("data/scope_snapshots") / f"{program_name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    current = set(t.lower() for t in current_targets)
    previous = set()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            previous = set(data.get("targets", []))
        except Exception:
            pass
    added = sorted(current - previous)
    removed = sorted(previous - current)
    path.write_text(json.dumps({"targets": sorted(current)}, indent=2), encoding="utf-8")
    return {"added": added, "removed": removed, "changed": bool(added or removed)}


# ─── 14. Duplicate Checker (local fingerprint DB) ─────────────────────────────

def check_local_duplicates(finding: dict, known_fps: Set[str]) -> Optional[str]:
    from core.finding_dedup import finding_fingerprint
    fp = finding_fingerprint(finding)
    if fp in known_fps:
        return "duplicate_local"
    return None


# ─── 15. Wordlist Generator ──────────────────────────────────────────────────

def generate_wordlist(urls: List[str], js_paths: List[str]) -> List[str]:
    words = set()
    for url in urls:
        p = urlparse(url)
        for part in (p.path or "").split("/"):
            if 2 < len(part) < 40 and part.isascii():
                words.add(part)
        for k in parse_qs(p.query):
            words.add(k)
    for path in js_paths:
        words.add(path.strip("/"))
    return sorted(words)[:5000]


# ─── 16. Report Quality Scorer ───────────────────────────────────────────────

def score_report_quality(finding: dict) -> dict:
    score = 0.0
    if finding.get("description") and len(finding["description"]) > 80:
        score += 0.25
    if finding.get("evidence") and len(str(finding["evidence"])) > 40:
        score += 0.25
    if finding.get("url"):
        score += 0.15
    if finding.get("reproduction_markdown") or "steps" in str(finding.get("description", "")).lower():
        score += 0.2
    if finding.get("severity", "").lower() in ("critical", "high", "medium"):
        score += 0.15
    finding["report_quality_score"] = round(min(score, 1.0), 2)
    finding["submission_ready"] = score >= 0.75
    return finding


# ─── 17–19. Bounty tracker / submission stubs (data layer) ───────────────────

def load_bounty_tracker() -> dict:
    path = Path("data/bounty_tracker.json")
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"programs": {}, "totals": {"submitted": 0, "accepted": 0, "paid": 0}}


def save_bounty_entry(program: str, status: str, amount: float = 0) -> dict:
    data = load_bounty_tracker()
    prog = data["programs"].setdefault(program, {"submitted": 0, "accepted": 0, "paid": 0, "earnings": 0})
    if status in prog:
        prog[status] = prog.get(status, 0) + 1
    if amount:
        prog["earnings"] = prog.get("earnings", 0) + amount
    path = Path("data/bounty_tracker.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


# ─── 20. Attack Chain Builder (enhanced) ─────────────────────────────────────

def build_enhanced_chains(findings: List[dict]) -> List[dict]:
    from core.correlation_engine import CorrelationEngine
    chains = CorrelationEngine().build_chains(findings)
    # Promote chains to findings only when 2+ high-confidence vulns linked
    promoted = []
    for chain in chains:
        if chain.get("severity", "").lower() in ("critical", "high"):
            promoted.append(make_finding(
                title=f"Attack Chain: {chain['name']}",
                severity=chain["severity"],
                url="",
                vuln_type="Attack Chain",
                description="\n".join(chain.get("steps", [])),
                evidence=json.dumps(chain.get("linked_findings", [])),
                tool="attack_chain_builder",
                confidence=0.9,
                extra={"chain": chain},
            ))
    return promoted[:5]
