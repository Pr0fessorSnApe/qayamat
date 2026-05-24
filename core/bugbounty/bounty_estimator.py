"""
QAYAMAT — CVSS estimation and bounty payout range per program profile.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.program_profiles import ProgramProfileLoader

# Default payout ranges (USD) when program YAML has no table
DEFAULT_PAYOUTS = {
    "critical": {"min": 2000, "max": 15000, "cvss_base": 9.0},
    "high": {"min": 500, "max": 5000, "cvss_base": 7.5},
    "medium": {"min": 100, "max": 1500, "cvss_base": 5.5},
    "low": {"min": 50, "max": 500, "cvss_base": 3.5},
    "info": {"min": 0, "max": 0, "cvss_base": 0.0},
}


def _norm_sev(severity: str) -> str:
    s = (severity or "medium").lower().strip()
    if s in DEFAULT_PAYOUTS:
        return s
    return "medium"


def estimate_cvss(finding: dict) -> Dict[str, Any]:
    """
    Heuristic CVSS 3.1 base score from finding metadata.
    For manual programs, override with finding['cvss'] if set.
    """
    if finding.get("cvss"):
        try:
            score = float(finding["cvss"])
            return {
                "cvss_base_score": score,
                "cvss_vector": finding.get("cvss_vector", "N/A"),
                "source": "scanner",
            }
        except (TypeError, ValueError):
            pass

    sev = _norm_sev(finding.get("severity", ""))
    vuln = (finding.get("vuln_type") or "").lower()
    title = (finding.get("title") or "").lower()

    base = DEFAULT_PAYOUTS[sev]["cvss_base"]

    # Adjust within severity band
    if any(x in vuln + title for x in ("rce", "sqli", "takeover", "auth bypass", "ssrf", "metadata")):
        base = min(10.0, base + 1.0)
    if any(x in vuln + title for x in ("idor", "xss", "cors", "oauth")):
        base = min(9.0, max(base, 6.5))
    if "info" in sev or "scan note" in title:
        base = 0.0

    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    if base >= 9:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    elif base >= 7:
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    elif base >= 4:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"

    return {
        "cvss_base_score": round(base, 1),
        "cvss_vector": vector,
        "source": "qayamat_heuristic",
    }


def load_program_payouts(program_name: str) -> Dict[str, dict]:
    if not program_name:
        return dict(DEFAULT_PAYOUTS)
    prog = ProgramProfileLoader().load(program_name)
    table = prog.get("bounty_payouts") or prog.get("payouts") or {}
    out = {}
    for sev in DEFAULT_PAYOUTS:
        if sev in table:
            out[sev] = {**DEFAULT_PAYOUTS[sev], **table[sev]}
        else:
            out[sev] = dict(DEFAULT_PAYOUTS[sev])
    return out


def estimate_bounty(finding: dict, program_name: str = "") -> Dict[str, Any]:
    """Return CVSS + estimated USD range for a finding."""
    cvss = estimate_cvss(finding)
    sev = _norm_sev(finding.get("severity", ""))
    payouts = load_program_payouts(program_name)
    band = payouts.get(sev, DEFAULT_PAYOUTS["medium"])

    # Scale within band by CVSS position
    score = cvss["cvss_base_score"]
    if score >= 9:
        pct = 0.95
    elif score >= 7:
        pct = 0.75
    elif score >= 4:
        pct = 0.5
    else:
        pct = 0.25

    est_min = band["min"]
    est_max = band["max"]
    if est_max > est_min:
        est_mid = est_min + (est_max - est_min) * pct
    else:
        est_mid = est_min

    return {
        **cvss,
        "severity_normalized": sev,
        "bounty_min_usd": est_min,
        "bounty_max_usd": est_max,
        "bounty_estimated_usd": round(est_mid, 2),
        "program": program_name or "default",
        "currency": "USD",
    }


def estimate_scan_portfolio(findings: List[dict], program_name: str = "") -> Dict[str, Any]:
    """Aggregate bounty estimate for all accepted findings."""
    total_min = 0.0
    total_max = 0.0
    total_est = 0.0
    per_finding = []
    for f in findings:
        if f.get("triage_status") in ("false_positive", "duplicate", "rejected"):
            continue
        est = estimate_bounty(f, program_name)
        per_finding.append({"finding_id": f.get("id"), "title": f.get("title"), **est})
        total_min += est["bounty_min_usd"]
        total_max += est["bounty_max_usd"]
        total_est += est["bounty_estimated_usd"]
    return {
        "program": program_name,
        "finding_count": len(per_finding),
        "total_bounty_min_usd": round(total_min, 2),
        "total_bounty_max_usd": round(total_max, 2),
        "total_bounty_estimated_usd": round(total_est, 2),
        "findings": per_finding,
    }
