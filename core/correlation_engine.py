"""
QAYAMAT — Correlation Engine
Links individual findings into multi-step attack chains.
"""

from typing import List, Dict, Any, Set


# Map vuln_type / tags / title keywords → chain requirement tokens
VULN_TYPE_MAP = {
    "xss": "stored_xss",
    "stored xss": "stored_xss",
    "reflected xss": "stored_xss",
    "sqli": "sqli",
    "sql injection": "sqli",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "secret": "secret_leak",
    "secret leak": "secret_leak",
    "exposed credentials": "secret_leak",
    "subdomain takeover": "subdomain_takeover",
    "takeover": "subdomain_takeover",
    "open redirect": "open_redirect",
    "idor": "idor",
    "broken access control": "idor",
    "missing security header": "missing_httponly",
    "cookie": "missing_httponly",
    "admin panel": "exposed_admin",
    "default login": "exposed_admin",
    "default-login": "exposed_admin",
    "open port": "open_port",
    "port": "open_port",
}


class CorrelationEngine:
    """
    Analyzes findings and constructs multi-step attack chains
    from correlated vulnerability types.
    """

    CHAIN_RULES = [
        {
            "name": "Account Takeover via Leaked Credentials",
            "requires": ["secret_leak", "exposed_admin"],
            "steps": [
                "Discover exposed secret / API key in JavaScript or commit history",
                "Access admin panel using leaked credentials",
                "Escalate privileges to full account takeover",
            ],
            "severity": "Critical",
        },
        {
            "name": "Blind SSRF to Internal Service Enumeration",
            "requires": ["ssrf", "open_port"],
            "steps": [
                "Trigger SSRF via user-controlled URL parameter",
                "Enumerate internal network via response timing / DNS callbacks",
                "Access internal services (metadata endpoints, Redis, etc.)",
            ],
            "severity": "High",
        },
        {
            "name": "Stored XSS to Session Hijacking",
            "requires": ["stored_xss", "missing_httponly"],
            "steps": [
                "Inject stored XSS payload via vulnerable input field",
                "Payload executes in victim's browser session",
                "Exfiltrate session cookie (HttpOnly not set)",
            ],
            "severity": "High",
        },
        {
            "name": "Subdomain Takeover to Phishing",
            "requires": ["subdomain_takeover"],
            "steps": [
                "Identify dangling DNS CNAME pointing to unclaimed service",
                "Register the service and claim the subdomain",
                "Host convincing phishing page on trusted domain",
            ],
            "severity": "High",
        },
        {
            "name": "SQL Injection to Data Exfiltration",
            "requires": ["sqli"],
            "steps": [
                "Exploit SQL injection on user-controlled parameter",
                "Extract database schema and sensitive records",
                "Escalate to authentication bypass or RCE if DB privileges allow",
            ],
            "severity": "Critical",
        },
    ]

    def _extract_types(self, finding: Any) -> Set[str]:
        """Normalize a finding into a set of chain-relevant type tokens."""
        types: Set[str] = set()

        if isinstance(finding, dict):
            raw_type = (finding.get("type") or finding.get("vuln_type") or "").lower()
            title = (finding.get("title") or "").lower()
            tags = finding.get("tags") or []
            template = (finding.get("template") or "").lower()
            tool = (finding.get("tool") or "").lower()
        else:
            raw_type = (getattr(finding, "type", "") or getattr(finding, "vuln_type", "")).lower()
            title = (getattr(finding, "title", "") or "").lower()
            tags = getattr(finding, "tags", []) or []
            template = (getattr(finding, "template", "") or "").lower()
            tool = (getattr(finding, "tool", "") or "").lower()

        if raw_type:
            types.add(raw_type)
            if raw_type in VULN_TYPE_MAP:
                types.add(VULN_TYPE_MAP[raw_type])

        for key, token in VULN_TYPE_MAP.items():
            if key in title or key in raw_type:
                types.add(token)

        if isinstance(tags, str):
            tags = [tags]
        for tag in tags:
            t = str(tag).lower().replace("-", "_")
            types.add(t)
            if t in VULN_TYPE_MAP:
                types.add(VULN_TYPE_MAP[t])

        if "takeover" in template or "takeover" in title:
            types.add("subdomain_takeover")
        if tool == "nuclei" and "ssrf" in title:
            types.add("ssrf")
        if "secret" in title or "api key" in title or "credential" in title:
            types.add("secret_leak")
        if "xss" in title or "cross-site" in title:
            types.add("stored_xss")
        if "sql" in title and "inject" in title:
            types.add("sqli")

        return types

    def build_chains(self, findings: List[Any]) -> List[Dict]:
        finding_types: Set[str] = set()
        for f in findings:
            finding_types |= self._extract_types(f)

        chains = []
        for rule in self.CHAIN_RULES:
            required = set(r.lower() for r in rule["requires"])
            if not required.issubset(finding_types):
                continue

            involved = []
            for f in findings:
                if self._extract_types(f) & required:
                    involved.append(f)

            chains.append({
                "name": rule["name"],
                "steps": rule["steps"],
                "severity": rule["severity"],
                "involved_findings": involved,
            })

        return chains

    def calculate_risk_score(self, findings: List[Any]) -> float:
        """Weighted risk score normalized to 0.0–10.0."""
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        if not findings:
            return 0.0
        total = 0.0
        for f in findings:
            sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "info"))
            total += weights.get((sev or "info").lower(), 0)
        return min(10.0, total / len(findings))
