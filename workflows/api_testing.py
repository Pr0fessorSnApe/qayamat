"""
QAYAMAT — API Testing Workflow v3
"""

import asyncio
import json
import os
import re
from typing import List, Dict, Any, Optional

import requests as _requests

from core.graphql_analyzer import GraphQLAnalyzer
from core.finding_validator import FindingValidator, BENIGN_API_PATHS, SENSITIVE_JSON_KEYS
from core.logger import AuditLogger
from core.scan_store import store
from tools.wrappers.base import ToolWrapper
from workflows.recon import ScanProgressUI, _broadcast, _write_tmp


class _W(ToolWrapper):
    def __init__(self, name, policy=None, logger=None):
        super().__init__(policy=policy, logger=logger)
        self.name = name


async def _wrap(name, args, policy=None, logger=None, target=None, timeout=120):
    w = _W(name, policy=policy, logger=logger)
    return await asyncio.to_thread(w.run, args, target=target, timeout=timeout)


class APITestingWorkflow:
    def __init__(self, config: dict, policy, ai, logger: AuditLogger):
        self.config = config
        self.policy = policy
        self.ai = ai
        self.logger = logger
        self.validator = FindingValidator(
            config,
            ai_validate=ai.validate_finding if ai else None,
        )

    def _event(self, msg: str, scan_id: Optional[int] = None) -> None:
        self.logger.info(msg)
        store.add_event(msg, scan_id=scan_id)

    def _save(self, f: dict, scan_id: Optional[int] = None) -> Optional[dict]:
        ok, reason, updated = self.validator.validate(f)
        if not ok:
            self.logger.debug(f"API finding rejected: {reason}")
            return None
        entry = store.add_finding(updated, scan_id=scan_id)
        self._event(
            f"[{updated.get('severity','?').upper()}] API: {updated.get('title','')} → {updated.get('url','')[:80]}",
            scan_id=scan_id,
        )
        return entry

    # ── REST endpoint probing ──────────────────────────────────────────────────
    async def _probe_rest(self, endpoints: List[str], scan_id: Optional[int]) -> List[Dict]:
        findings = []
        sensitive_paths = [
            "/api/v1/users", "/api/users", "/api/admin", "/api/config",
            "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
            "/api-docs", "/.well-known/openapi", "/api/health",
            "/actuator", "/actuator/env", "/actuator/beans",
            "/debug", "/trace", "/metrics",
        ]
        for ep in endpoints[:20]:
            base = ep.rstrip("/")
            for path in sensitive_paths:
                url = base + path
                try:
                    resp = await asyncio.to_thread(
                        lambda u=url: _requests.get(u, timeout=5, verify=False,
                                                     allow_redirects=True, headers={"Accept": "application/json"})
                    )
                    path_norm = path.rstrip("/").lower() or "/"
                    if path_norm in BENIGN_API_PATHS:
                        continue
                    if resp.status_code not in (200, 201) or not resp.content:
                        continue
                    ct = resp.headers.get("content-type", "")
                    if "json" not in ct and resp.content[:1] not in (b"{", b"["):
                        continue
                    body_lower = resp.text[:2000].lower()
                    sensitive = any(k in body_lower for k in SENSITIVE_JSON_KEYS)
                    sensitive_path = any(
                        k in path for k in ("admin", "config", "actuator/env", "debug", "trace", "secret")
                    )
                    if not sensitive and not sensitive_path:
                        continue
                    if sensitive_path and len(resp.text) < 40:
                        continue
                    findings.append({
                        "title":       f"Exposed API Endpoint: {path}",
                        "severity":    "high" if sensitive or "admin" in path else "medium",
                        "vuln_type":   "API Exposure",
                        "url":         url,
                        "description": f"API endpoint returned data without auth. Status: {resp.status_code}",
                        "evidence":    resp.text[:300],
                        "tool":        "api_probe",
                    })
                    self._event(f"Exposed API: {url} [{resp.status_code}]", scan_id=scan_id)
                except Exception:
                    pass
        return findings

    # ── GraphQL analysis ──────────────────────────────────────────────────────
    async def _probe_graphql(self, endpoints: List[str], scan_id: Optional[int]) -> List[Dict]:
        findings = []
        for ep in endpoints:
            try:
                # graphql-cop CLI when installed
                cop_out = await _wrap("graphql-cop", ["-t", ep], policy=self.policy,
                                      logger=self.logger, target=ep, timeout=90)
                for line in cop_out.splitlines():
                    line = line.strip()
                    if not line or "PASS" in line.upper():
                        continue
                    findings.append({
                        "title":       f"GraphQL-cop: {line[:120]}",
                        "severity":    "medium",
                        "vuln_type":   "GraphQL",
                        "url":         ep,
                        "description": line,
                        "tool":        "graphql-cop",
                    })

                analyzer = GraphQLAnalyzer(ep)
                schema   = await asyncio.to_thread(analyzer.fetch_schema)
                issues   = await asyncio.to_thread(analyzer.detect_issues)
                depth    = await asyncio.to_thread(analyzer.check_depth_limit)

                for issue in issues:
                    f = {
                        "title":       f"GraphQL: {issue.get('message','')}",
                        "severity":    issue.get("severity", "low"),
                        "vuln_type":   "GraphQL",
                        "url":         ep,
                        "description": issue.get("message", ""),
                        "tool":        "graphql_analyzer",
                    }
                    findings.append(f)
                    self._save(f, scan_id=scan_id)

                if depth:
                    f = {
                        "title":       f"GraphQL: {depth.get('message','')}",
                        "severity":    depth.get("severity", "medium"),
                        "vuln_type":   "GraphQL",
                        "url":         ep,
                        "description": depth.get("message", ""),
                        "tool":        "graphql_analyzer",
                    }
                    findings.append(f)
                    self._save(f, scan_id=scan_id)

                if schema and any(
                    t.get("name", "").lower() in ("user", "admin", "account", "password")
                    for t in (schema.get("types") or [])
                    if isinstance(t, dict)
                ):
                    f = {
                        "title":       "GraphQL Introspection Exposes Sensitive Types",
                        "severity":    "medium",
                        "vuln_type":   "GraphQL",
                        "url":         ep,
                        "description": "Introspection enabled with sensitive object types in schema.",
                        "evidence":    str(schema)[:300],
                        "tool":        "graphql_analyzer",
                    }
                    findings.append(f)
                    self._save(f, scan_id=scan_id)

            except Exception as e:
                self.logger.debug(f"GraphQL probe failed on {ep}: {e}")
        return findings

    # ── Arjun parameter discovery ─────────────────────────────────────────────
    async def _discover_params(self, endpoints: List[str], scan_id: Optional[int]) -> List[Dict]:
        findings = []
        out_file = "/tmp/arjun_api.json"
        for url in endpoints[:5]:
            try:
                out = await _wrap("arjun", ["-u", url, "-oJ", out_file, "-q"],
                                   policy=self.policy, logger=self.logger, target=url, timeout=120)
                if os.path.isfile(out_file):
                    with open(out_file) as f:
                        data = json.load(f)
                    for u, params in data.items():
                        if isinstance(params, list) and params:
                            findings.append({
                                "title":       f"Hidden API Parameters Discovered: {url}",
                                "severity":    "low",
                                "vuln_type":   "Parameter Discovery",
                                "url":         u,
                                "description": f"Arjun discovered {len(params)} hidden params: {', '.join(params[:10])}",
                                "evidence":    str(params),
                                "tool":        "arjun",
                            })
                            self._event(f"Arjun: {url} → {len(params)} params: {', '.join(params[:5])}", scan_id=scan_id)
                    os.unlink(out_file)
            except Exception as e:
                self.logger.debug(f"Arjun failed on {url}: {e}")
        return findings

    # ── Main execute ──────────────────────────────────────────────────────────
    async def execute(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        ui = ScanProgressUI()
        findings: List[Dict[str, Any]] = []

        # Get scan_id from active scan
        active = store.get_active_scan()
        scan_id = active["id"] if active else None

        try:
            # Phase 1: REST endpoint discovery
            ui.add_phase("REST API Discovery", 1)
            ui.update_stats(phase="REST API Discovery")
            self._event(f"REST API probing {len(endpoints)} endpoints...", scan_id=scan_id)
            rest_findings = await self._probe_rest(endpoints, scan_id)
            for f in rest_findings: self._save(f, scan_id=scan_id)
            findings.extend(rest_findings)
            ui.complete_phase("REST API Discovery")
            self._event(f"REST scan: {len(rest_findings)} findings", scan_id=scan_id)

            # Phase 2: GraphQL
            graphql_eps = [ep for ep in endpoints if any(k in ep.lower() for k in ["graphql", "gql", "graph"])]
            if graphql_eps:
                ui.add_phase("GraphQL Analysis", len(graphql_eps))
                ui.update_stats(phase="GraphQL Analysis")
                self._event(f"GraphQL analysis on {len(graphql_eps)} endpoints...", scan_id=scan_id)
                gql_findings = await self._probe_graphql(graphql_eps, scan_id)
                findings.extend(gql_findings)
                ui.complete_phase("GraphQL Analysis")
                self._event(f"GraphQL: {len(gql_findings)} findings", scan_id=scan_id)

            # Phase 3: Parameter discovery
            ui.add_phase("Parameter Discovery", 1)
            ui.update_stats(phase="Parameter Discovery")
            param_findings = await self._discover_params(endpoints, scan_id)
            for f in param_findings: self._save(f, scan_id=scan_id)
            findings.extend(param_findings)
            ui.complete_phase("Parameter Discovery")

            await _broadcast("api_test_complete", {"total": len(findings)}, scan_id)
            self._event(f"API testing complete: {len(findings)} findings", scan_id=scan_id)
            ui.stop()

        except Exception as e:
            self.logger.error(f"API testing failed: {e}")
            ui.stop()
            raise

        return findings
