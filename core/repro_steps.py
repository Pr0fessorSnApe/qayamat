"""
QAYAMAT — Detailed steps-to-reproduce generator for reports and submissions.
"""

from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs, urlencode


def _parse_url(url: str) -> dict:
    if not url or "://" not in url:
        url = f"https://{url}" if url else ""
    p = urlparse(url)
    params = parse_qs(p.query)
    return {
        "scheme": p.scheme or "https",
        "host": p.hostname or "",
        "path": p.path or "/",
        "params": params,
        "full": url,
    }


def generate_reproduction_steps(finding: dict) -> List[str]:
    """Build clear, platform-ready reproduction steps for any finding."""
    title = (finding.get("title") or "").lower()
    vuln = (finding.get("vuln_type") or "").lower()
    url = finding.get("url", "")
    tool = finding.get("tool", "qayamat")
    evidence = str(finding.get("evidence", ""))[:500]
    parsed = _parse_url(url)
    param_names = list(parsed["params"].keys())
    first_param = param_names[0] if param_names else "q"

    steps: List[str] = []

    # ── Shared preamble ─────────────────────────────────────────────────────
    steps.append(f"**Target:** `{parsed['full'] or url}`")
    steps.append(f"**Detected by:** {tool or 'QAYAMAT scanner'}")

    if "xss" in vuln or "xss" in title or "cross-site" in title:
        payload = evidence[:120] if evidence else "<script>alert(1)</script>"
        steps.extend([
            "",
            "### Steps to reproduce (XSS)",
            f"1. Open a browser and navigate to: `{parsed['full']}`",
            f"2. Identify the vulnerable parameter: `{first_param}` (or inject into the reflected input field).",
            f"3. Submit the following payload in that parameter:",
            f"   ```",
            f"   {payload}",
            f"   ```",
            "4. Observe the server response — the payload should execute or reflect without proper encoding.",
            "5. Confirm impact: script execution in browser context, or HTML injection proving lack of output encoding.",
            "",
            "### Expected result",
            "Browser executes attacker-controlled JavaScript or renders unsanitized HTML.",
            "",
            "### Actual result",
            evidence or "Payload reflected/executed as described in scanner evidence.",
        ])

    elif "sqli" in vuln or "sql" in title:
        steps.extend([
            "",
            "### Steps to reproduce (SQL Injection)",
            f"1. Send an HTTP request to: `{parsed['full']}`",
            f"2. Modify parameter `{first_param}` with a SQL metacharacter probe, e.g. `'` or `1' OR '1'='1`.",
            "3. Compare response to baseline — look for SQL errors, boolean differences, or time delays.",
            "4. Optional: run sqlmap in safe mode: `sqlmap -u \"URL\" -p param --batch --level=1 --risk=1`",
            "",
            "### Expected result",
            "Database error messages, authentication bypass, or confirmed injectable parameter.",
            "",
            "### Actual result",
            evidence or "sqlmap/scanner confirmed injectable parameter.",
        ])

    elif "ssrf" in vuln or "ssrf" in title:
        steps.extend([
            "",
            "### Steps to reproduce (SSRF)",
            f"1. Locate a URL/host parameter on `{parsed['host']}{parsed['path']}`",
            "2. Replace its value with an internal or OOB callback URL (e.g. `http://169.254.169.254/` or your collaborator).",
            "3. Send the request and monitor for outbound callbacks or internal content in the response.",
            "",
            "### Expected result",
            "Server performs a request to attacker-controlled or internal destination.",
            "",
            "### Actual result",
            evidence or "OOB callback or internal resource access observed.",
        ])

    elif "idor" in vuln or "access control" in title or "broken access" in title:
        steps.extend([
            "",
            "### Steps to reproduce (Broken Access Control / IDOR)",
            f"1. Authenticate as a **low-privilege** user (or remain unauthenticated).",
            f"2. Request: `{parsed['full']}`",
            "3. Compare HTTP status and response body to the same request as admin/another user.",
            "4. Note if restricted data or actions are accessible without proper authorization.",
            "",
            "### Expected result",
            "HTTP 403/401 for unauthorized access.",
            "",
            "### Actual result",
            evidence or "200 OK with sensitive data for unauthorized role.",
        ])

    elif "takeover" in vuln or "takeover" in title:
        steps.extend([
            "",
            "### Steps to reproduce (Subdomain Takeover)",
            f"1. Resolve DNS for host: `{parsed['host']}`",
            "2. Inspect CNAME — it points to an unclaimed third-party service.",
            "3. Register the dangling service and claim the hostname.",
            "4. Serve proof content on the subdomain.",
            "",
            "### Expected result",
            "Subdomain should not be claimable by third parties.",
            "",
            "### Actual result",
            evidence or "Dangling CNAME allows external party to host content on trusted domain.",
        ])

    elif "api" in vuln or "api" in title:
        steps.extend([
            "",
            "### Steps to reproduce (API Exposure)",
            f"1. Send unauthenticated `GET` request to: `{parsed['full']}`",
            "2. Include header: `Accept: application/json`",
            "3. Review JSON body for sensitive fields (credentials, PII, config).",
            "",
            "### Expected result",
            "Authentication required; no sensitive data without valid session.",
            "",
            "### Actual result",
            evidence or "Sensitive JSON returned without authentication.",
        ])

    elif "secret" in vuln or "leak" in title:
        steps.extend([
            "",
            "### Steps to reproduce (Secret Exposure)",
            "1. Clone or browse the indicated repository/path.",
            "2. Search for API keys, tokens, or passwords in source/history.",
            "3. Verify the secret is active (without exfiltrating data beyond PoC).",
            "",
            "### Expected result",
            "No live credentials in version control or public assets.",
            "",
            "### Actual result",
            evidence or "Valid-format secret identified in disclosed location.",
        ])

    else:
        steps.extend([
            "",
            "### Steps to reproduce",
            f"1. Navigate to or send a request to: `{parsed['full']}`",
            f"2. Review the finding: **{finding.get('title', 'Security issue')}**",
            f"3. Description: {finding.get('description', 'See evidence below.')}",
            "",
            "### Evidence",
            f"```",
            evidence or "See attached scanner output.",
            f"```",
        ])

    steps.extend([
        "",
        "### Impact",
        _impact_line(finding),
        "",
        "### Remediation",
        *_remediation_lines(finding),
    ])
    return steps


def _impact_line(finding: dict) -> str:
    sev = (finding.get("severity") or "Medium").lower()
    if sev == "critical":
        return "Critical impact — may lead to full compromise, data breach, or account takeover."
    if sev == "high":
        return "High impact — significant confidentiality, integrity, or availability risk."
    if sev == "medium":
        return "Medium impact — exploitable under realistic conditions with user interaction or weak config."
    return "Low/informational impact — defense-in-depth improvement recommended."


def _remediation_lines(finding: dict) -> List[str]:
    vuln = (finding.get("vuln_type") or "").lower()
    lines = []
    if "xss" in vuln:
        lines = [
            "- Encode all user output contextually (HTML, JS, URL).",
            "- Deploy Content-Security-Policy (CSP).",
            "- Use framework auto-escaping.",
        ]
    elif "sqli" in vuln:
        lines = [
            "- Use parameterized queries / ORM bindings.",
            "- Deny list SQL metacharacters at WAF layer as defense-in-depth.",
            "- Least-privilege DB accounts.",
        ]
    else:
        lines = [
            "- Patch affected component to latest secure version.",
            "- Restrict access per principle of least privilege.",
            "- Re-test after fix deployment.",
        ]
    return lines


def enrich_finding_with_steps(finding: dict) -> dict:
    """Add reproduction_steps and formatted markdown to a finding dict."""
    steps = generate_reproduction_steps(finding)
    finding = {**finding}
    finding["reproduction_steps"] = steps
    finding["reproduction_markdown"] = "\n".join(steps)
    return finding
