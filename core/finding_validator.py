"""
QAYAMAT — Finding Validator
Filters false positives using heuristics and optional AI confirmation.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Paths that commonly return 200 JSON but are not vulnerabilities
BENIGN_API_PATHS = {
    "/api/health", "/health", "/healthz", "/ready", "/live", "/metrics",
    "/api/v1/health", "/status", "/ping", "/version", "/api/version",
}

SENSITIVE_JSON_KEYS = (
    "password", "secret", "api_key", "apikey", "token", "private_key",
    "access_token", "refresh_token", "aws_secret", "connectionstring",
    "authorization", "bearer", "credential", "ssn", "credit_card",
)

XSS_DANGEROUS_RE = re.compile(
    r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=)",
    re.IGNORECASE,
)

CRLF_MARKERS = ("\r\n", "%0d%0d", "%0a%0a", "set-cookie:", "location:")


class FindingValidator:
  """Score and accept/reject findings before they enter the report."""

  def __init__(
      self,
      config: Optional[dict] = None,
      ai_validate: Optional[Callable[[dict], dict]] = None,
  ):
      cfg = (config or {}).get("validation", {})
      self.enabled = cfg.get("enabled", True)
      self.min_score = float(cfg.get("min_heuristic_score", 0.65))
      self.use_ai = cfg.get("use_ai_confirmation", True)
      self.ai_min_confidence = float(cfg.get("ai_min_confidence", 0.72))
      self._ai_validate = ai_validate

  def validate(self, finding: dict) -> Tuple[bool, str, dict]:
      """
      Returns (accepted, reason, finding).
      Rejected findings are not stored; accepted ones may have adjusted severity.
      """
      if not self.enabled:
          return True, "validation disabled", finding

      score, reason = self._heuristic_score(finding)
      finding = {**finding, "validation_score": round(score, 3), "validation_reason": reason}

      if score < self.min_score:
          return False, f"heuristic reject: {reason}", finding

      if self.use_ai and self._ai_validate and score < 0.95:
          ai_result = self._ai_validate(finding)
          if ai_result:
              finding["ai_validation"] = ai_result
              if not ai_result.get("confirmed", True):
                  return False, f"AI reject: {ai_result.get('reason', '')}", finding
              conf = float(ai_result.get("confidence", 1.0))
              if conf < self.ai_min_confidence:
                  return False, f"AI low confidence ({conf:.2f})", finding

      return True, reason, finding

  def filter_findings(self, findings: List[dict]) -> Tuple[List[dict], List[dict]]:
      accepted, rejected = [], []
      for f in findings:
          ok, reason, updated = self.validate(f)
          if ok:
              accepted.append(updated)
          else:
              rejected.append({**f, "rejected_reason": reason})
      return accepted, rejected

  # ── Heuristics ────────────────────────────────────────────────────────────

  def _heuristic_score(self, finding: dict) -> Tuple[float, str]:
      tool = (finding.get("tool") or "").lower()
      vuln = (finding.get("vuln_type") or "").lower()
      severity = (finding.get("severity") or "info").lower()
      url = finding.get("url") or ""
      evidence = str(finding.get("evidence", ""))
      title = (finding.get("title") or "").lower()

      if tool == "nuclei":
          return self._score_nuclei(finding, severity)

      if vuln in ("xss",) or tool in ("dalfox", "waf_bypass"):
          return self._score_xss(evidence, title)

      if vuln in ("sqli", "sql injection") or tool == "sqlmap":
          return self._score_sqli(evidence, title)

      if vuln == "crlf" or tool == "crlfuzz":
          return self._score_crlf(url, evidence)

      if vuln == "discovery" or tool == "ffuf":
          return self._score_discovery(title, url)

      if vuln == "anomaly" or tool == "anomaly_detector":
          return self._score_anomaly(finding)

      if vuln in ("api exposure", "parameter discovery") or tool in ("api_probe", "arjun"):
          return self._score_api(finding, url, evidence, title)

      if vuln == "graphql" or tool == "graphql_analyzer":
          return self._score_graphql(title, evidence)

      if vuln in ("evidence", "scan note", "attack surface"):
          return 0.2, "informational browser note"

      if tool == "playwright" and "screenshot" in title:
          return 0.15, "screenshot artifact only"

      if tool == "playwright" and "dom-based xss" in title:
          return 0.88, "playwright confirmed DOM XSS"

      if tool in ("trufflehog", "gitleaks", "repo_scanner"):
          return 0.92, "verified secret scanner output"

      if vuln in ("cors",) or tool == "cors_hunter":
          return self._score_cors(evidence)

      if vuln in ("ssrf",) or tool == "ssrf_verifier":
          return self._score_ssrf(evidence, title)

      if vuln in ("idor", "broken access control") or tool in ("idor_tester", "multi_role_scanner"):
          return self._score_idor(evidence, title)

      if vuln in ("oauth",) or tool == "oauth_tester":
          return 0.9, "oauth misconfiguration with evidence"

      if tool == "host_header_tester":
          return 0.88, "host header injection confirmed in response"

      if tool == "js_miner" and "secret" in title:
          return 0.9, "hardcoded secret pattern in JS"

      if tool == "js_miner":
          return 0.55, "JS endpoint discovery — verify manually"

      if tool == "ghost_endpoints":
          return 0.85, "archived URL confirmed live with body"

      if tool == "openapi_discovery":
          return 0.88, "valid OpenAPI document exposed"

      if tool in ("ct_monitor", "asset_scorer", "waf_detector"):
          return 0.99, "informational recon metadata"

      if tool == "attack_chain_builder":
          return 0.85, "correlated multi-step chain"

      if vuln in ("ssti", "template injection") or tool == "ssti_verifier":
          return self._score_ssti(evidence, title)

      if vuln in ("http smuggling",) or tool == "http_smuggling":
          return 0.88, "smuggling probe anomaly — confirm manually"

      if vuln in ("cache poisoning",) or tool == "cache_poison":
          if "reflected" in (finding.get("description") or "").lower():
              return 0.9, "cache poison header reflected"
          return 0.8, "cache path normalization issue"

      if tool == "race_tester":
          if "parallel success" in title.lower():
              return 0.88, "multiple parallel successes"
          return 0.75, "race inconsistency — verify manually"

      if vuln in ("attack surface", "scan note"):
          return 0.2, "informational attack surface note"

      # Default: medium trust for unknown tools
      if severity in ("critical", "high"):
          return 0.65, "unclassified high-severity — needs strong evidence"
      if severity == "info":
          return 0.3, "informational finding"
      return 0.55, "default — borderline, prefer manual validation"

  def _score_nuclei(self, finding: dict, severity: str) -> Tuple[float, str]:
      template = (finding.get("template") or "").lower()
      tags = finding.get("tags") or []
      if isinstance(tags, str):
          tags = [tags]
      tag_str = " ".join(str(t).lower() for t in tags)

      # Noisy template families
      noisy = ("tech-detect", "fingerpr", "waf-detect", "dns-waf", "ssl", "tls", "dns")
      if any(n in template or n in tag_str for n in noisy):
          return 0.25, "fingerprinting/noise template"

      if severity == "info":
          return 0.4, "nuclei info severity"
      if finding.get("cve"):
          return 0.95, "nuclei CVE match"
      return 0.85, "nuclei confirmed template"

  def _score_xss(self, evidence: str, title: str) -> Tuple[float, str]:
      ev = html.unescape(evidence)
      if XSS_DANGEROUS_RE.search(ev) or XSS_DANGEROUS_RE.search(title):
          return 0.9, "XSS dangerous context in evidence"
      if "waf_bypass" in title and "confirmed" not in title:
          return 0.35, "reflection-only XSS candidate"
      if re.search(r"&lt;|&#x3c;|%3c", evidence, re.I) and "<" not in ev:
          return 0.2, "payload appears encoded — not exploitable"
      if len(evidence) < 8:
          return 0.3, "insufficient XSS evidence"
      return 0.75, "XSS reported by specialized scanner"

  def _score_sqli(self, evidence: str, title: str) -> Tuple[float, str]:
      ev = evidence.lower()
      strong = ("is vulnerable", "sqlmap identified", "injectable", "sql injection")
      if any(s in ev for s in strong):
          return 0.95, "sqlmap confirmed injection"
      if "sql" in title and len(evidence) > 20:
          return 0.8, "SQLi indicators present"
      return 0.4, "weak SQLi signal"

  def _score_crlf(self, url: str, evidence: str) -> Tuple[float, str]:
      ev = (evidence or url).lower()
      if any(m in ev for m in CRLF_MARKERS):
          return 0.85, "CRLF injection markers present"
      if url.startswith("http") and "\n" not in evidence and "\r" not in evidence:
          return 0.15, "URL-only CRLF match — likely false positive"
      return 0.5, "possible CRLF — needs verification"

  def _score_discovery(self, title: str, url: str) -> Tuple[float, str]:
      sensitive = ("admin", "backup", ".git", "config", "env", "passwd", "id_rsa", "wp-config")
      path = urlparse(url).path.lower()
      if any(s in path or s in title for s in sensitive):
          return 0.65, "sensitive path discovered"
      return 0.3, "directory discovery — informational only"

  def _score_anomaly(self, finding: dict) -> Tuple[float, str]:
      score = finding.get("anomaly_score")
      if score is not None and float(score) < -0.45:
          return 0.55, "statistical anomaly"
      return 0.2, "weak anomaly signal — suppressed"

  def _score_api(self, finding: dict, url: str, evidence: str, title: str) -> Tuple[float, str]:
      path = urlparse(url).path.rstrip("/").lower() or "/"
      if path in BENIGN_API_PATHS or path.endswith("/health"):
          return 0.15, "benign health/status endpoint"

      if "parameter discovery" in title or finding.get("vuln_type") == "Parameter Discovery":
          return 0.45, "parameter discovery — informational"

      body = evidence.lower()
      if any(k in body for k in SENSITIVE_JSON_KEYS):
          return 0.88, "sensitive data in API response"
      if any(k in path for k in ("admin", "config", "actuator/env", "debug", "trace")):
          if len(body) > 50:
              return 0.8, "sensitive admin/config endpoint with body"
          return 0.5, "sensitive path — empty or short response"

      if "exposed api" in title and len(body) < 30:
          return 0.25, "empty JSON response — likely false positive"
      return 0.35, "API probe without sensitive content"

  def _score_cors(self, evidence: str) -> Tuple[float, str]:
      ev = (evidence or "").lower()
      if "acao=" in ev and ("credentials=true" in ev or "acac=true" in ev):
          return 0.95, "CORS with credentials — high impact"
      if "acao=" in ev:
          return 0.9, "CORS misconfiguration confirmed in headers"
      return 0.4, "weak CORS signal"

  def _score_ssrf(self, evidence: str, title: str) -> Tuple[float, str]:
      ev = (evidence or "").lower()
      if any(x in ev for x in ("ami-id", "metadata", "169.254", "compute.internal")):
          return 0.95, "SSRF with cloud metadata in response"
      if "ssrf" in title and len(evidence) > 30:
          return 0.75, "SSRF indicator — verify callback"
      return 0.35, "unconfirmed SSRF"

  def _score_idor(self, evidence: str, title: str) -> Tuple[float, str]:
      ev = evidence.lower()
      if "anonymous=401" in ev or "anonymous=403" in ev:
          if "user=200" in ev or "user_st=200" in ev:
              return 0.92, "role-based access control bypass"
      if "predictable object" in title.lower() and "200" in ev:
          return 0.82, "IDOR candidate with matching responses"
      if "privilege escalation" in title.lower():
          return 0.9, "privilege escalation pattern"
      return 0.45, "weak IDOR signal — likely false positive"

  def _score_ssti(self, evidence: str, title: str) -> Tuple[float, str]:
      ev = evidence or ""
      if "49" in ev and ("{{" in ev or "${" in ev or "7*7" in title.lower()):
          return 0.95, "SSTI evaluation confirmed in body"
      if "ssti" in title.lower() and len(ev) > 40:
          return 0.85, "SSTI indicators in response"
      return 0.4, "weak SSTI signal"

  def _score_graphql(self, title: str, evidence: str) -> Tuple[float, str]:
      t = title.lower()
      if "introspection" in t:
          return 0.55, "GraphQL introspection enabled (config issue)"
      if "depth" in t or "no query depth" in t:
          return 0.7, "GraphQL depth limit issue"
      if "disabled" in t or "unreachable" in t:
          return 0.2, "GraphQL not confirmed"
      return 0.6, "GraphQL security note"
