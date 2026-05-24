"""
QAYAMAT — Subdomain takeover verification (claimability check).
"""

import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

# Fingerprints indicating unclaimed services
UNCLAIMED_FINGERPRINTS = [
    (r"github\.io", ["There isn't a GitHub Pages site here", "404 - File not found"]),
    (r"herokuapp\.com", ["no such app", "heroku"]),
    (r"azurewebsites\.net", ["404 Web Site not found", "Microsoft Azure"]),
    (r"cloudfront\.net", ["ERROR: The request could not be satisfied"]),
    (r"fastly\.net", ["Fastly error"]),
    (r"shopify\.com", ["Sorry, this shop is currently unavailable"]),
    (r"surge\.sh", ["project not found"]),
    (r"bitbucket\.io", ["Repository not found"]),
    (r"ghost\.io", ["The thing you were looking for is no longer here"]),
    (r"zendesk\.com", ["Help Center Closed"]),
    (r"readme\.io", ["Project doesnt exist"]),
    (r"cargo\.site", ["404"]),
    (r"statuspage\.io", ["You are being", "redirected"]),
]


class TakeoverVerifier:
    def verify(self, url: str, cname_hint: str = "") -> Dict:
        """
        Returns {verified: bool, claimable: bool, service: str, evidence: str}
        """
        host = urlparse(url if "://" in url else f"https://{url}").hostname or url
        cnames = []
        if cname_hint:
            cnames = [cname_hint]
        else:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(host, "CNAME")
                cnames = [str(r.target).rstrip(".") for r in answers]
            except Exception:
                try:
                    _, _, cnames_raw = socket.gethostbyname_ex(host)
                    cnames = cnames_raw
                except Exception:
                    cnames = []

        body, status = "", 0
        try:
            resp = requests.get(
                f"https://{host}",
                timeout=8,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "QAYAMAT-Takeover-Verify/1.0"},
            )
            body = resp.text[:5000]
            status = resp.status_code
        except Exception as e:
            return {"verified": False, "claimable": False, "service": "", "evidence": str(e)}

        for cname in cnames:
            cname_low = cname.lower()
            for pattern, markers in UNCLAIMED_FINGERPRINTS:
                if re.search(pattern, cname_low):
                    if any(m.lower() in body.lower() for m in markers) or status in (404, 403):
                        return {
                            "verified": True,
                            "claimable": True,
                            "service": pattern.replace("\\", "").strip("r"),
                            "cname": cname,
                            "evidence": body[:400],
                        }

        # Generic NX-style / unclaimed page
        if status == 404 and any(
            x in body.lower() for x in ("not found", "doesn't exist", "no such", "unavailable")
        ):
            return {
                "verified": True,
                "claimable": True,
                "service": "unknown",
                "cname": cnames[0] if cnames else "",
                "evidence": body[:400],
            }

        return {"verified": True, "claimable": False, "service": "", "evidence": f"HTTP {status}"}

    def verify_batch(self, candidates: List[dict]) -> List[dict]:
        """Input nuclei-style takeover candidates; return verified findings only."""
        verified = []
        for c in candidates:
            url = c.get("url", "")
            result = self.verify(url)
            if result.get("claimable"):
                verified.append({
                    **c,
                    "title": f"Verified Subdomain Takeover: {urlparse(url).hostname}",
                    "severity": "high",
                    "vuln_type": "Subdomain Takeover",
                    "description": (
                        f"Takeover appears claimable. Service: {result.get('service','?')} "
                        f"CNAME: {result.get('cname','?')}"
                    ),
                    "evidence": result.get("evidence", ""),
                    "tool": "takeover_verifier",
                    "verified": True,
                })
        return verified
