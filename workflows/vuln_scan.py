"""
QAYAMAT — Vulnerability Scanning Workflow v3
"""

import asyncio
import html
import json
import os
import re
import shutil
import tempfile
import requests as _requests
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse, urlencode, parse_qs

from core.policy_engine import PolicyEngine
from core.ai_engine import AIEngine
from core.logger import AuditLogger
from core.anomaly_detector import AnomalyDetector
from core.finding_validator import FindingValidator, XSS_DANGEROUS_RE
from core.payload_engine import PayloadEngine
from core.waf_bypass import WAFBypassGenetic
from core.correlation_engine import CorrelationEngine
from core.takeover_verifier import TakeoverVerifier
from core.nuclei_manager import NucleiTemplateManager
from core.scan_store import store
from core.scan_control import check_cancelled, ScanCancelledError
from tools.orchestrator import ToolOrchestrator
from tools.wrappers.base import ToolWrapper
from workflows.recon import ScanProgressUI, _broadcast, _write_tmp, _tool_path


# ── Inline wrapper helper ─────────────────────────────────────────────────────
class _W(ToolWrapper):
    def __init__(self, name: str, policy=None, logger=None):
        super().__init__(policy=policy, logger=logger)
        self.name = name


async def _wrap(name: str, args: List[str], policy=None, logger=None,
                target: str = None, timeout: int = 300) -> str:
    w = _W(name, policy=policy, logger=logger)
    return await asyncio.to_thread(w.run, args, target=target, timeout=timeout)


async def _run(cmd: List[str], timeout: int = 300) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="ignore").strip()
    except asyncio.TimeoutError:
        try: proc.kill()
        except: pass
        return ""
    except Exception: return ""


def _urls_with_params(urls: List[str]) -> List[str]:
    return [u for u in urls if "?" in u and "=" in u]


def _sev(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s.lower(), 5)


# ── Nuclei ────────────────────────────────────────────────────────────────────
async def run_nuclei(targets: List[str], severity: str = "low,medium,high,critical",
                     tags: Optional[str] = None, policy=None, logger=None,
                     extra_args: Optional[List[str]] = None) -> List[Dict]:
    if not targets: return []
    tmp = _write_tmp(targets)
    args = ["-l", tmp, "-silent", "-jsonl", "-severity", severity,
            "-rate-limit", "100", "-bulk-size", "25", "-concurrency", "10",
            "-timeout", "10", "-retries", "1"]
    if tags: args += ["-tags", tags]
    if extra_args: args += extra_args
    findings = []
    try:
        out = await _wrap("nuclei", args, policy=policy, logger=logger, timeout=600)
        for line in out.splitlines():
            line = line.strip()
            if not line: continue
            try:
                d = json.loads(line)
                findings.append({
                    "title":       d.get("info", {}).get("name", "Unknown"),
                    "severity":    d.get("info", {}).get("severity", "info"),
                    "vuln_type":   "nuclei",
                    "url":         d.get("matched-at", d.get("host", "")),
                    "template":    d.get("template-id", ""),
                    "description": d.get("info", {}).get("description", ""),
                    "evidence":    str(d.get("extracted-results", d.get("request", "")))[:1000],
                    "tags":        d.get("info", {}).get("tags", []),
                    "cve":         d.get("info", {}).get("classification", {}).get("cve-id", []),
                    "cvss":        d.get("info", {}).get("classification", {}).get("cvss-score", ""),
                    "tool":        "nuclei",
                })
            except json.JSONDecodeError: pass
        return findings
    finally:
        try: os.unlink(tmp)
        except: pass


# ── Dalfox ────────────────────────────────────────────────────────────────────
async def run_dalfox(urls: List[str], policy=None, logger=None) -> List[Dict]:
    param_urls = _urls_with_params(urls)
    if not param_urls: return []
    tmp = _write_tmp(param_urls)
    args = ["file", tmp, "--silence", "--no-color", "--format", "json",
            "--timeout", "10", "--delay", "100", "--worker", "5"]
    findings = []
    try:
        out = await _wrap("dalfox", args, policy=policy, logger=logger, timeout=300)
        for line in out.splitlines():
            line = line.strip()
            if not line: continue
            try:
                d = json.loads(line)
                findings.append({
                    "title":       "Cross-Site Scripting (XSS)",
                    "severity":    "high", "vuln_type": "XSS",
                    "url":         d.get("url", ""),
                    "description": f"XSS via dalfox. Type: {d.get('type','reflected')}",
                    "evidence":    str(d.get("poc", d.get("payload", "")))[:500],
                    "tool":        "dalfox",
                })
            except json.JSONDecodeError:
                if any(k in line for k in ["[V]", "[POC]", "XSS"]):
                    m = re.search(r"https?://\S+", line)
                    findings.append({
                        "title": "Cross-Site Scripting (XSS)", "severity": "high",
                        "vuln_type": "XSS", "url": m.group(0) if m else "",
                        "description": "XSS confirmed by dalfox", "evidence": line[:500], "tool": "dalfox",
                    })
        return findings
    finally:
        try: os.unlink(tmp)
        except: pass


# ── Sqlmap ────────────────────────────────────────────────────────────────────
async def run_sqlmap(urls: List[str], policy=None, logger=None) -> List[Dict]:
    sqlmap_bin = _tool_path("sqlmap")
    if not sqlmap_bin:
        py = os.path.expanduser("~/sqlmap/sqlmap.py")
        sqlmap_bin = f"python3 {py}" if os.path.isfile(py) else None
    if not sqlmap_bin: return []

    param_urls = _urls_with_params(urls)
    if not param_urls: return []
    findings = []
    for url in param_urls[:5]:
        cmd = sqlmap_bin.split() + [
            "-u", url, "--batch", "--silent", "--level=1", "--risk=1",
            "--technique=B", "--no-cast", "--output-dir=/tmp/sqlmap_qayamat",
            "--timeout=10", "--retries=1",
        ]
        out = await _run(cmd, timeout=180)
        if out and any(k in out.lower() for k in ["is vulnerable", "sqlmap identified", "injectable", "sql injection"]):
            pm = re.search(r"Parameter: (\S+)", out, re.IGNORECASE)
            dm = re.search(r"back-end DBMS: (\S+)", out, re.IGNORECASE)
            findings.append({
                "title": "SQL Injection", "severity": "critical", "vuln_type": "SQLi",
                "url": url,
                "description": f"SQL injection on param '{pm.group(1) if pm else '?'}'. DBMS: {dm.group(1) if dm else '?'}.",
                "evidence": out[:500], "tool": "sqlmap",
            })
    return findings


# ── Crlfuzz ───────────────────────────────────────────────────────────────────
async def run_crlfuzz(urls: List[str], policy=None, logger=None) -> List[Dict]:
    if not urls: return []
    tmp = _write_tmp(urls[:20])
    findings = []
    try:
        out = await _wrap("crlfuzz", ["-l", tmp, "-s"], policy=policy, logger=logger, timeout=120)
        for line in out.splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            low = line.lower()
            if not any(m in low for m in ("crlf", "%0d", "%0a", "set-cookie", "location:")):
                continue
            findings.append({
                "title": "CRLF Injection", "severity": "medium", "vuln_type": "CRLF",
                "url": line.split()[0] if " " in line else line,
                "description": "CRLF injection indicators in crlfuzz output.",
                "evidence": line[:500], "tool": "crlfuzz",
            })
        return findings
    finally:
        try: os.unlink(tmp)
        except: pass


# ── Arjun parameter discovery ─────────────────────────────────────────────────
async def run_arjun(urls: List[str], policy=None, logger=None) -> Dict[str, List[str]]:
    """Discover hidden parameters. Returns {url: [param, ...]}."""
    results: Dict[str, List[str]] = {}
    out_file = "/tmp/arjun_qayamat.json"
    for url in urls[:10]:
        out = await _wrap("arjun", ["-u", url, "-oJ", out_file, "-q"],
                           policy=policy, logger=logger, target=url, timeout=120)
        try:
            if os.path.isfile(out_file):
                with open(out_file) as f:
                    data = json.load(f)
                # arjun JSON: {url: [params]}
                for u, params in data.items():
                    if isinstance(params, list):
                        results[u] = params
                os.unlink(out_file)
        except Exception: pass
    return results


# ── Ffuf directory fuzzing ────────────────────────────────────────────────────
async def run_ffuf(base_urls: List[str], policy=None, logger=None) -> List[Dict]:
    """Fuzz for hidden directories/endpoints (JSON output, sensitive paths only)."""
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/opt/SecLists/Discovery/Web-Content/common.txt",
        os.path.expanduser("~/wordlists/common.txt"),
    ]
    wordlist = next((w for w in wordlists if os.path.isfile(w)), None)
    if not wordlist:
        return []

    sensitive_hints = (
        "admin", "backup", "config", "env", ".git", "debug", "internal",
        "swagger", "actuator", "phpmyadmin", "wp-config", "secret",
    )
    findings = []
    for base in base_urls[:3]:
        url = base.rstrip("/") + "/FUZZ"
        out = await _wrap(
            "ffuf",
            ["-u", url, "-w", wordlist, "-mc", "200,201,301,302,403",
             "-s", "-t", "50", "-timeout", "5", "-of", "json"],
            policy=policy, logger=logger, target=base, timeout=300,
        )
        results = []
        try:
            data = json.loads(out)
            results = data.get("results", [])
        except json.JSONDecodeError:
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("{") and len(line) < 80:
                    results.append({"input": {"FUZZ": line}})

        for item in results:
            path = (
                (item.get("input") or {}).get("FUZZ")
                or (item.get("words") or {}).get("name", "")
                or ""
            ).strip()
            if not path or not any(h in path.lower() for h in sensitive_hints):
                continue
            findings.append({
                "title":       f"Sensitive path discovered: /{path}",
                "severity":    "info",
                "vuln_type":   "Discovery",
                "url":         base.rstrip("/") + "/" + path.lstrip("/"),
                "description": f"ffuf found potentially sensitive path /{path}",
                "evidence":    json.dumps(item)[:500],
                "tool":        "ffuf",
            })
    return findings


# ── WAF-bypass enhanced XSS/SQLi ─────────────────────────────────────────────
async def run_waf_bypass_xss(urls: List[str], policy=None) -> List[Dict]:
    """Use PayloadEngine + WAFBypassGenetic to test XSS with evolved payloads."""
    param_urls = _urls_with_params(urls)
    if not param_urls: return []

    engine = PayloadEngine()
    findings = []

    for url in param_urls[:5]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in list(params.keys())[:3]:
            base_payloads = engine.generate("xss")

            # Quick WAF probe: does the server reflect content?
            def _fitness(payload: str) -> float:
                """Return 1.0 only if payload appears in an exploitable XSS context."""
                try:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                    resp = _requests.get(test_url, timeout=5, verify=False, allow_redirects=True)
                    body = html.unescape(resp.text)
                    if payload not in body:
                        return 0.0
                    if "&lt;" in resp.text and "<" not in body[: body.find(payload[:20]) + 50 if payload[:20] in body else 0]:
                        return 0.0
                    if XSS_DANGEROUS_RE.search(body):
                        return 1.0
                    return 0.0
                except Exception:
                    return 0.0

            # Evolve payload variants using genetic algorithm
            ga = WAFBypassGenetic(fitness_func=_fitness, population_size=10, generations=5)
            for base_payload in base_payloads[:3]:
                try:
                    best = await asyncio.to_thread(ga.evolve, base_payload)
                    # Test the best evolved payload
                    score = await asyncio.to_thread(_fitness, best)
                    if score >= 1.0:
                        findings.append({
                            "title":       "XSS Confirmed (WAF Bypass)",
                            "severity":    "high",
                            "vuln_type":   "XSS",
                            "url":         url,
                            "description": f"XSS in executable context after WAF bypass on param '{param_name}'",
                            "evidence":    best[:300],
                            "tool":        "waf_bypass",
                        })
                        break
                except Exception:
                    pass

    return findings


# ── Anomaly scan ──────────────────────────────────────────────────────────────
async def scan_anomalies(live_hosts: List[Dict], detector: AnomalyDetector) -> List[Dict]:
    """Check live hosts for anomalous HTTP behaviour (requires real response metrics)."""
    if not detector.fitted:
        return []
    findings = []
    for h in live_hosts:
        size = h.get("content_length") or h.get("content-length") or 0
        if not size:
            continue
        response_data = {
            "status": h.get("status_code", 200),
            "size": int(size),
            "time": float(h.get("response_time", 0.3) or 0.3),
            "redirects": int(h.get("redirects", 0) or 0),
        }
        if not detector.is_anomaly(response_data):
            continue
        score = detector.anomaly_score(response_data)
        if score > -0.35:
            continue
        findings.append({
            "title":       f"Anomalous HTTP Response: {h.get('url','')}",
            "severity":    "low",
            "vuln_type":   "Anomaly",
            "url":         h.get("url", ""),
            "description": f"Response deviates from baseline (anomaly score: {score:.3f})",
            "evidence":    str(response_data),
            "anomaly_score": score,
            "tool":        "anomaly_detector",
        })
    return findings


# ── Vuln Scan Workflow ─────────────────────────────────────────────────────────
class VulnScanWorkflow:
    def __init__(self, config: dict, policy: PolicyEngine, ai: AIEngine,
                 logger: AuditLogger, recon_results: Dict[str, Any]):
        self.config = config
        self.policy = policy
        self.ai = ai
        self.logger = logger
        self.recon_results = recon_results
        self.anomaly_detector = AnomalyDetector(contamination=0.08)
        self.payload_engine = PayloadEngine()
        self.correlation = CorrelationEngine()
        self.orchestrator = ToolOrchestrator(policy, logger)
        self.validator = FindingValidator(
            config,
            ai_validate=ai.validate_finding if ai else None,
        )
        self._scan_id: Optional[int] = recon_results.get("scan_id")
        self._rejected_count = 0

    def _event(self, msg: str, event_type: str = "info") -> None:
        self.logger.info(msg)
        store.add_event(msg, event_type=event_type, scan_id=self._scan_id)

    def _save(self, finding: dict) -> Optional[dict]:
        ok, reason, updated = self.validator.validate(finding)
        if not ok:
            self._rejected_count += 1
            self.logger.debug(f"Finding rejected ({reason}): {finding.get('title', '')[:60]}")
            return None
        entry = store.add_finding(updated, scan_id=self._scan_id)
        self._event(
            f"[{updated.get('severity','?').upper()}] {updated.get('title','')} → {updated.get('url','')[:80]}",
            event_type=updated.get("severity", "info").lower(),
        )
        asyncio.create_task(_broadcast(
            "new_finding",
            {"finding": entry, "total": store.findings_summary()["total"]},
            self._scan_id,
        ))
        return entry

    async def execute(self) -> List[dict]:
        ui = ScanProgressUI()

        live_hosts: List[Dict] = self.recon_results.get("live_hosts", [])
        all_urls:   List[str]  = self.recon_results.get("urls", [])
        known_params: Set[str] = self.recon_results.get("params", set())
        profile = getattr(self.policy, "profile", "safe")

        live_urls  = [h.get("url","") for h in live_hosts if h.get("url")]
        scan_urls  = list(set(live_urls + [u for u in all_urls if u.startswith("http")]))
        param_urls = _urls_with_params(scan_urls)

        if not scan_urls:
            self._event("No live hosts — vuln scan skipped.", "warning")
            ui.stop(); return []

        self._event(f"Vuln scan | live={len(live_hosts)} urls={len(scan_urls)} params={len(param_urls)} known_params={len(known_params)}")

        try:
            check_cancelled(self._scan_id, "vuln scan start")
            # ── Baseline (train anomaly detector) ─────────────────────────
            ui.add_phase("Baseline Profiling", 1)
            ui.update_stats(phase="Baseline Profiling")
            baseline = []
            for h in live_hosts[:25]:
                size = h.get("content_length") or h.get("content-length")
                if size:
                    baseline.append({
                        "status": h.get("status_code", 200),
                        "size": int(size),
                        "time": float(h.get("response_time", 0.3) or 0.3),
                        "redirects": 0,
                    })
            if len(baseline) >= 10:
                self.anomaly_detector.train(baseline)
            else:
                self.logger.info("Skipping anomaly detection — insufficient response metrics from httpx")
            ui.complete_phase("Baseline Profiling")
            store.update_scan(self._scan_id, progress=5.0) if self._scan_id else None

            # ── Parameter Discovery (Arjun) ───────────────────────────────
            ui.add_phase("Parameter Discovery", 1)
            ui.update_stats(phase="Parameter Discovery")
            self._event(f"arjun discovering parameters on {min(len(live_urls),10)} endpoints...")
            arjun_params = await run_arjun(live_urls[:10], policy=self.policy, logger=self.logger)
            total_new_params = sum(len(v) for v in arjun_params.values())
            if total_new_params:
                self._event(f"Arjun discovered {total_new_params} hidden parameters")
                # Build parameterized URLs from discovered params
                for url, params in arjun_params.items():
                    for p in params:
                        param_url = f"{url}?{p}=test"
                        if param_url not in param_urls:
                            param_urls.append(param_url)
            ui.complete_phase("Parameter Discovery")
            store.update_scan(self._scan_id, progress=10.0) if self._scan_id else None

            # ── Directory Fuzzing (Ffuf) ──────────────────────────────────
            ui.add_phase("Directory Fuzzing", 1)
            ui.update_stats(phase="Directory Fuzzing")
            self._event(f"ffuf fuzzing {min(len(live_urls),3)} base URLs...")
            ffuf_findings = await run_ffuf(live_urls[:3], policy=self.policy, logger=self.logger)
            for f in ffuf_findings: self._save(f)
            ui.complete_phase("Directory Fuzzing")
            self._event(f"Directory fuzzing: {len(ffuf_findings)} endpoints found")
            store.update_scan(self._scan_id, progress=15.0) if self._scan_id else None

            # ── Nuclei Full Scan ──────────────────────────────────────────
            ui.add_phase("Nuclei Scan", 1)
            ui.update_stats(phase="Nuclei Scan")
            self._event(f"nuclei scanning {len(scan_urls)} targets...")
            for f in await run_nuclei(scan_urls, policy=self.policy, logger=self.logger):
                self._save(f)
            ui.complete_phase("Nuclei Scan")
            ui.update_stats(vulns=store.findings_summary()["total"])
            store.update_scan(self._scan_id, progress=30.0) if self._scan_id else None

            # ── CVE Templates ─────────────────────────────────────────────
            ui.add_phase("CVE Scan", 1)
            ui.update_stats(phase="CVE Scan")
            self._event("nuclei CVE templates...")
            for f in await run_nuclei(scan_urls, severity="medium,high,critical", tags="cve",
                                       policy=self.policy, logger=self.logger):
                self._save(f)
            ui.complete_phase("CVE Scan")
            store.update_scan(self._scan_id, progress=45.0) if self._scan_id else None

            # ── XSS (Dalfox) ──────────────────────────────────────────────
            ui.add_phase("XSS Detection", 1)
            ui.update_stats(phase="XSS Detection")
            self._event(f"dalfox XSS on {len(param_urls)} parameterized URLs...")
            for f in await run_dalfox(param_urls, policy=self.policy, logger=self.logger):
                self._save(f)
            ui.complete_phase("XSS Detection")
            store.update_scan(self._scan_id, progress=55.0) if self._scan_id else None

            # ── WAF Bypass XSS ────────────────────────────────────────────
            if profile in ("balanced", "aggressive", "red_team"):
                ui.add_phase("WAF Bypass", 1)
                ui.update_stats(phase="WAF Bypass XSS")
                self._event("WAF bypass genetic evolution on parameterized URLs...")
                for f in await run_waf_bypass_xss(param_urls, policy=self.policy):
                    self._save(f)
                ui.complete_phase("WAF Bypass")
                store.update_scan(self._scan_id, progress=60.0) if self._scan_id else None

            # ── SQL Injection ─────────────────────────────────────────────
            ui.add_phase("SQL Injection", 1)
            ui.update_stats(phase="SQL Injection")
            self._event(f"sqlmap on {min(len(param_urls),5)} parameterized URLs...")
            for f in await run_sqlmap(param_urls, policy=self.policy, logger=self.logger):
                self._save(f)
            ui.complete_phase("SQL Injection")
            store.update_scan(self._scan_id, progress=70.0) if self._scan_id else None

            # ── CRLF ──────────────────────────────────────────────────────
            ui.add_phase("CRLF Injection", 1)
            ui.update_stats(phase="CRLF Injection")
            self._event("crlfuzz scanning...")
            for f in await run_crlfuzz(scan_urls, policy=self.policy, logger=self.logger):
                self._save(f)
            ui.complete_phase("CRLF Injection")
            store.update_scan(self._scan_id, progress=75.0) if self._scan_id else None

            # ── Misconfiguration (nuclei) ─────────────────────────────────
            ui.add_phase("Misconfiguration", 1)
            ui.update_stats(phase="Misconfiguration")
            self._event("nuclei misconfiguration/exposure templates...")
            nuclei_mgr = NucleiTemplateManager()
            prog_cfg = self.config.get("program", {})
            extra_nuclei = nuclei_mgr.build_args(prog_cfg)
            takeover_candidates = []
            for f in await run_nuclei(
                scan_urls, severity="low,medium,high,critical",
                tags="misconfig,exposure,takeover,config,default-login",
                policy=self.policy, logger=self.logger, extra_args=extra_nuclei,
            ):
                saved = self._save(f)
                if saved and "takeover" in (f.get("title", "") + f.get("template", "")).lower():
                    takeover_candidates.append(f)
            if self.config.get("scan", {}).get("takeover_verify", True) and takeover_candidates:
                self._event(f"Verifying {len(takeover_candidates)} takeover candidates...")
                verifier = TakeoverVerifier()
                for vf in verifier.verify_batch(takeover_candidates):
                    self._save(vf)
            ui.complete_phase("Misconfiguration")
            store.update_scan(self._scan_id, progress=85.0) if self._scan_id else None

            # ── Anomaly Detection ─────────────────────────────────────────
            ui.add_phase("Anomaly Detection", 1)
            ui.update_stats(phase="Anomaly Detection")
            self._event("Anomaly detection on live host responses...")
            for f in await scan_anomalies(live_hosts, self.anomaly_detector):
                self._save(f)
            ui.complete_phase("Anomaly Detection")
            store.update_scan(self._scan_id, progress=90.0) if self._scan_id else None

            # ── Correlation: Build Attack Chains ──────────────────────────
            ui.add_phase("Correlation", 1)
            ui.update_stats(phase="Building Attack Chains")
            all_findings = store.get_findings(scan_id=self._scan_id)
            chains = self.correlation.build_chains(all_findings)
            risk = self.correlation.calculate_risk_score(all_findings)
            for chain in chains:
                self._event(
                    f"ATTACK CHAIN: {chain['name']} [{chain['severity']}]",
                    event_type="critical",
                )
            self._event(f"Risk score: {risk:.1f}/10 | {len(chains)} attack chains")
            ui.complete_phase("Correlation")
            store.update_scan(self._scan_id, progress=100.0, status="complete") if self._scan_id else None

            # ── Summary ───────────────────────────────────────────────────
            summary = store.findings_summary()
            self._event(
                f"Vuln scan complete | total={summary['total']} | "
                f"filtered={self._rejected_count} false positives | "
                + " | ".join(f"{k}={v}" for k, v in summary.get("by_severity", {}).items())
            )
            await _broadcast("scan_complete", {"total_findings": summary["total"], "risk_score": risk}, self._scan_id)
            ui.update_stats(vulns=summary["total"], phase="Complete")
            ui.stop()
            return store.get_findings(scan_id=self._scan_id)

        except ScanCancelledError:
            self._event("Vuln scan cancelled by user", "warning")
            store.update_scan(self._scan_id, status="cancelled") if self._scan_id else None
            ui.stop()
            raise
        except Exception as e:
            self._event(f"Vuln scan failed: {e}", "error")
            store.update_scan(self._scan_id, status="failed") if self._scan_id else None
            ui.stop(); raise
