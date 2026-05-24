"""
QAYAMAT — Intelligent out-of-scope / exclusions text parser.
Parses natural-language bug bounty exclusion lists into enforceable rules.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# Common section headers in program policies
OOS_SECTION_HEADERS = re.compile(
    r"(?im)^\s*(out\s*of\s*scope|excluded|not\s+in\s+scope|prohibited|"
    r"do\s+not\s+test|ineligible|restrictions?|limitations?)\s*[:\-]?\s*$"
)

DOMAIN_RE = re.compile(
    r"(?i)\b(?:\*\.)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)\b"
)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
URL_RE = re.compile(r"https?://[^\s\]>\"']+", re.I)
PATH_RE = re.compile(r"(?i)(?:^|\s)(/[a-z0-9_\-./{}*]+)")

VULN_EXCLUSION_PHRASES = {
    "denial of service": "dos",
    "dos": "dos",
    "ddos": "dos",
    "rate limit": "dos",
    "social engineering": "social_engineering",
    "phishing": "social_engineering",
    "physical": "physical",
    "spam": "spam",
    "brute force": "brute_force",
    "credential stuffing": "brute_force",
    "self-xss": "self_xss",
    "self xss": "self_xss",
    "missing security header": "missing_headers",
    "clickjacking without impact": "clickjacking_low",
    "outdated software": "outdated_software",
    "tabnabbing": "tabnabbing",
    "autocomplete": "autocomplete",
    "logout csrf": "logout_csrf",
    "email enumeration": "email_enumeration",
    "open redirect without impact": "open_redirect_low",
}

RATE_HINT_RE = re.compile(
    r"(?i)(\d+)\s*(?:req(?:uest)?s?)?\s*(?:per|/)\s*(?:second|sec|minute|min|hour|hr)"
)


@dataclass
class ParsedExclusions:
    """Structured exclusions from free-form text."""
    domains: List[str] = field(default_factory=list)
    wildcards: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    cidrs: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    excluded_vuln_types: List[str] = field(default_factory=list)
    max_requests_per_second: Optional[float] = None
    no_automated_scanning: bool = False
    raw_lines: List[str] = field(default_factory=list)
    confidence: float = 1.0

    def to_out_of_scope_list(self) -> List[str]:
        """Flat list for PolicyEngine.out_of_scope."""
        out = []
        out.extend(self.domains)
        out.extend(self.wildcards)
        out.extend(self.ips)
        out.extend(self.cidrs)
        for p in self.paths:
            if p.startswith("/"):
                out.append(f"*{p}*")
            else:
                out.append(p)
        return list(dict.fromkeys(o.strip().lower() for o in out if o.strip()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IntelligentExclusionsParser:
    """
    Parse pasted exclusion text (HackerOne policy snippets, Bugcrowd rules, etc.)
    into domains, paths, IPs, and testing constraints.
    """

    def __init__(self, ai_parse: Optional[Any] = None):
        self._ai_parse = ai_parse

    def parse(self, text: str, in_scope_hints: Optional[List[str]] = None) -> ParsedExclusions:
        text = (text or "").strip()
        if not text:
            return ParsedExclusions()

        # Comma-only short list → treat as domain list
        if "\n" not in text and "," in text and len(text) < 500:
            parts = [p.strip() for p in text.split(",") if p.strip()]
            if all(self._looks_like_target(p) for p in parts):
                result = ParsedExclusions(raw_lines=parts)
                for p in parts:
                    self._add_target(result, p)
                return result

        result = ParsedExclusions(raw_lines=text.splitlines())

        # Optional AI enrichment for messy prose
        if self._ai_parse and len(text) > 80:
            try:
                ai_data = self._ai_parse(text)
                if ai_data:
                    self._merge_ai(result, ai_data)
            except Exception:
                pass

        self._parse_lines(text, result, in_scope_hints or [])
        self._dedupe(result)
        return result

    def _parse_lines(self, text: str, result: ParsedExclusions, in_scope: List[str]) -> None:
        in_oos_section = False
        for line in text.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            if OOS_SECTION_HEADERS.match(raw):
                in_oos_section = True
                continue

            low = raw.lower()
            if any(p in low for p in ("no automated", "no automation", "manual testing only")):
                result.no_automated_scanning = True
            if "do not test" in low or "out of scope" in low or "excluded" in low:
                in_oos_section = True

            for phrase, vtype in VULN_EXCLUSION_PHRASES.items():
                if phrase in low:
                    result.excluded_vuln_types.append(vtype)

            m = RATE_HINT_RE.search(raw)
            if m:
                n = float(m.group(1))
                if "minute" in low or "min" in low:
                    result.max_requests_per_second = n / 60.0
                elif "hour" in low or "hr" in low:
                    result.max_requests_per_second = n / 3600.0
                else:
                    result.max_requests_per_second = n

            # Bullet / numbered list items
            cleaned = re.sub(r"^[\-\*•\d\.\)]\s*", "", raw).strip()
            if not cleaned:
                continue

            for url in URL_RE.findall(cleaned):
                self._add_url(result, url)

            for cidr in CIDR_RE.findall(cleaned):
                result.cidrs.append(cidr)

            for ip in IP_RE.findall(cleaned):
                if "/" not in ip and ip not in result.ips:
                    try:
                        ipaddress.ip_address(ip)
                        result.ips.append(ip)
                    except ValueError:
                        pass

            for dom in DOMAIN_RE.findall(cleaned):
                if dom.lower() in ("example.com", "test.com"):
                    continue
                if self._is_in_scope_domain(dom, in_scope) and not in_oos_section:
                    continue
                self._add_target(result, dom)

            for path in PATH_RE.findall(cleaned):
                if len(path) > 2:
                    result.paths.append(path.rstrip("/") or path)

            # Wildcard lines like *.staging.example.com
            if "*" in cleaned:
                w = cleaned.replace(" ", "")
                if self._looks_like_target(w):
                    result.wildcards.append(w.lower())

            # Keyword exclusions (third-party, production payment, etc.)
            if in_oos_section and not DOMAIN_RE.search(cleaned) and len(cleaned) < 80:
                kw = cleaned.lower()
                if kw and kw not in result.keywords:
                    result.keywords.append(kw)

    def _merge_ai(self, result: ParsedExclusions, data: dict) -> None:
        for k in ("domains", "wildcards", "paths", "ips", "cidrs", "keywords", "excluded_vuln_types"):
            for item in data.get(k, []) or []:
                getattr(result, k).append(str(item))
        if data.get("no_automated_scanning"):
            result.no_automated_scanning = True
        if data.get("max_requests_per_second"):
            result.max_requests_per_second = float(data["max_requests_per_second"])
        result.confidence = min(result.confidence, float(data.get("confidence", 0.85)))

    def _add_url(self, result: ParsedExclusions, url: str) -> None:
        try:
            p = urlparse(url if "://" in url else f"https://{url}")
            if p.hostname:
                self._add_target(result, p.hostname)
            if p.path and p.path != "/":
                result.paths.append(p.path)
        except Exception:
            pass

    def _add_target(self, result: ParsedExclusions, target: str) -> None:
        t = target.strip().lower()
        if not t:
            return
        if t.startswith("*."):
            result.wildcards.append(t)
        elif t.startswith("*"):
            result.wildcards.append(t)
        elif "/" in t and not t.startswith("http"):
            result.paths.append(t)
        elif re.match(r"^\d", t):
            if "/" in t:
                result.cidrs.append(t)
            else:
                result.ips.append(t)
        else:
            result.domains.append(t)

    def _looks_like_target(self, s: str) -> bool:
        s = s.strip().lower()
        if not s or " " in s:
            return False
        return bool(DOMAIN_RE.search(s) or s.startswith("*.") or "/" in s or IP_RE.match(s))

    def _is_in_scope_domain(self, dom: str, in_scope: List[str]) -> bool:
        dom = dom.lower()
        for t in in_scope:
            t = t.lower().strip()
            if dom == t or dom.endswith("." + t.lstrip("*.")):
                return True
        return False

    def _dedupe(self, result: ParsedExclusions) -> None:
        for attr in ("domains", "wildcards", "paths", "ips", "cidrs", "keywords", "excluded_vuln_types"):
            seen = set()
            unique = []
            for item in getattr(result, attr):
                key = item.lower().strip()
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            setattr(result, attr, unique)

    @staticmethod
    def matches_keyword_exclusion(url: str, title: str, keywords: List[str]) -> bool:
        """True if finding should be suppressed by keyword rule."""
        blob = f"{url} {title}".lower()
        for kw in keywords:
            if kw and kw in blob:
                return True
        return False

    @staticmethod
    def is_vuln_type_excluded(vuln_type: str, title: str, excluded: List[str]) -> bool:
        if not excluded:
            return False
        blob = f"{vuln_type} {title}".lower()
        for ex in excluded:
            ex = ex.replace("_", " ")
            if ex in blob:
                return True
            if ex == "dos" and any(x in blob for x in ("denial of service", "ddos")):
                return True
            if ex == "missing_headers" and "security header" in blob:
                return True
        return False


def parse_exclusions_text(
    text: str,
    in_scope: Optional[List[str]] = None,
    ai_parse: Optional[Any] = None,
) -> Tuple[List[str], ParsedExclusions]:
    """Convenience: returns (out_of_scope_list, full parsed object)."""
    parser = IntelligentExclusionsParser(ai_parse=ai_parse)
    parsed = parser.parse(text, in_scope_hints=in_scope)
    return parsed.to_out_of_scope_list(), parsed
