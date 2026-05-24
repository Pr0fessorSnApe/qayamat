"""
Orchestrates all bug bounty scanners with validation and exclusion filtering.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Set

from core.bugbounty import scanners
from core.bugbounty.advanced_http import scan_cache_poisoning, scan_http_smuggling
from core.bugbounty.nuclei_template_gen import generate_from_scan
from core.bugbounty.race_tester import scan_race_conditions
from core.bugbounty.ssti_verifier import scan_ssti
from core.bugbounty.bounty_estimator import estimate_bounty
from core.bugbounty.base import filter_urls
from core.finding_dedup import finding_fingerprint
from core.finding_validator import FindingValidator
from core.oos_parser import IntelligentExclusionsParser, ParsedExclusions


class BugBountyRunner:
    """Run bug bounty enrichment phases after recon."""

    def __init__(
        self,
        config: dict,
        policy,
        logger=None,
        validator: Optional[FindingValidator] = None,
        parsed_exclusions: Optional[ParsedExclusions] = None,
        ai_engine=None,
    ):
        self.config = config
        self.policy = policy
        self.logger = logger
        self.validator = validator
        self.ai = ai_engine
        self.parsed_exclusions = parsed_exclusions or ParsedExclusions()
        sc = getattr(policy, "scan_config", None) or {}
        self.profile = sc.get("profile", "safe") if isinstance(sc, dict) else "safe"
        self._known_fps: Set[str] = set()
        bb_cfg = config.get("bugbounty", {})
        self.enabled = bb_cfg.get("enabled", True)
        self.min_confidence = float(bb_cfg.get("min_confidence", 0.8))

    def _apply_exclusion_rules(self, finding: dict) -> bool:
        """Return True if finding should be dropped by exclusion rules."""
        pe = self.parsed_exclusions
        if IntelligentExclusionsParser.matches_keyword_exclusion(
            finding.get("url", ""),
            finding.get("title", ""),
            pe.keywords,
        ):
            return True
        if IntelligentExclusionsParser.is_vuln_type_excluded(
            finding.get("vuln_type", ""),
            finding.get("title", ""),
            pe.excluded_vuln_types,
        ):
            return True
        url = finding.get("url", "")
        if url and self.policy and not self.policy.is_in_scope(
            __import__("urllib.parse").urlparse(url if "://" in url else f"https://{url}").hostname or ""
        ):
            return True
        return False

    def _accept(self, finding: dict) -> Optional[dict]:
        if self._apply_exclusion_rules(finding):
            return None
        fp = finding_fingerprint(finding)
        if fp in self._known_fps:
            return None
        conf = float(finding.get("validation_score", 0.85))
        if conf < self.min_confidence:
            return None
        if self.validator:
            ok, reason, updated = self.validator.validate(finding)
            if not ok:
                if self.logger:
                    self.logger.debug(f"BB finding rejected: {reason}")
                return None
            finding = updated
        scanners.score_report_quality(finding)
        try:
            prog = (self.policy.scan_config.get("program") if self.policy else "") or ""
            finding["bounty_estimate"] = estimate_bounty(finding, prog)
        except Exception:
            pass
        self._known_fps.add(finding_fingerprint(finding))
        return finding

    async def run_all(
        self,
        recon_results: dict,
        scan_id: Optional[int] = None,
        auth_headers: Optional[dict] = None,
    ) -> List[dict]:
        if not self.enabled:
            return []

        urls = recon_results.get("urls", [])
        live_hosts = recon_results.get("live_hosts", [])
        subdomains = recon_results.get("subdomains", [])
        archive_urls = recon_results.get("archive_urls", urls)
        domains = list({d for d in subdomains + self.policy.targets})

        base_urls = [h.get("url") for h in live_hosts if h.get("url")]
        if not base_urls:
            base_urls = [u for u in urls if u.startswith("http")][:30]

        live_set = set(urls)
        accepted: List[dict] = []

        loop = asyncio.get_event_loop()

        phase_calls = [
            ("ct_monitor", lambda: scanners.scan_ct_logs(domains, self.policy)),
            ("asset_scorer", lambda: scanners.score_assets(urls, live_hosts, accepted)),
            ("js_miner", lambda: scanners.scan_js_bundles(urls[:100], self.policy)),
            ("ghost_endpoints", lambda: scanners.scan_ghost_endpoints(archive_urls, live_set, self.policy)),
            ("openapi", lambda: scanners.scan_openapi(base_urls, self.policy)),
            ("idor", lambda: scanners.scan_idor_urls(urls, self.policy, auth_headers)),
            ("oauth", lambda: scanners.scan_oauth(urls, self.policy)),
            ("cors", lambda: scanners.scan_cors(base_urls, self.policy)),
            ("ssrf", lambda: scanners.scan_ssrf_candidates(urls, self.policy)),
            ("host_header", lambda: scanners.scan_host_header(base_urls, self.policy)),
            ("waf", lambda: scanners.detect_waf(base_urls, self.policy)),
        ]
        bb = self.config.get("bugbounty", {})
        if bb.get("ssti_verify", True):
            phase_calls.append(("ssti", lambda: scan_ssti(urls, self.policy)))
        if bb.get("http_smuggling", True):
            phase_calls.append(("http_smuggling", lambda: scan_http_smuggling(base_urls, self.policy)))
        if bb.get("cache_poison", True):
            phase_calls.append(("cache_poison", lambda: scan_cache_poisoning(base_urls, self.policy)))
        if bb.get("race_tester", True):
            phase_calls.append(
                ("race", lambda: scan_race_conditions(urls, self.policy, auth_headers, self.profile))
            )

        for name, fn in phase_calls:
            try:
                raw = await loop.run_in_executor(None, fn)
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Bug bounty phase {name} failed: {e}")
                raw = []

            for f in raw:
                entry = self._accept(f)
                if entry:
                    accepted.append(entry)

        # Attack chains from accumulated findings
        chain_raw = await loop.run_in_executor(
            None, lambda: scanners.build_enhanced_chains(accepted)
        )
        for f in chain_raw:
            entry = self._accept(f)
            if entry:
                accepted.append(entry)

        # Wordlist artifact (event only)
        wl = scanners.generate_wordlist(urls, [])
        if wl and self.logger:
            self.logger.info(f"Generated custom wordlist: {len(wl)} entries")

        if not self.config.get("bugbounty", {}).get("nuclei_template_gen", True):
            return accepted

        # AI / heuristic Nuclei templates from JS findings
        try:
            prog = ""
            if self.policy and getattr(self.policy, "scan_config", None):
                prog = self.policy.scan_config.get("program", "") or ""
            gen = generate_from_scan(accepted, program=prog, ai_engine=self.ai)
            if gen.get("template_paths") and self.logger:
                self.logger.info(
                    f"Nuclei templates: {len(gen.get('template_paths', []))} files — {gen.get('nuclei_run_hint', '')}"
                )
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Nuclei template generation failed: {e}")

        return accepted
