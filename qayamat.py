#!/usr/bin/env python3
"""
QAYAMAT — Autonomous AI-Powered Offensive Security OS v3
"""

import asyncio
import importlib
import inspect
import json
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from config.loader import load_config
from core.policy_engine import PolicyEngine
from core.ai_engine import AIEngine
from core.vault import Vault
from core.logger import AuditLogger
from core.session_manager import SessionManager
from core.correlation_engine import CorrelationEngine
from core.scan_store import store
from workflows.recon import ReconWorkflow
from workflows.vuln_scan import VulnScanWorkflow
from workflows.exploitation import ExploitationWorkflow
from workflows.api_testing import APITestingWorkflow
from workflows.reporting import ReportGenerator
from workflows.active_directory import ActiveDirectoryWorkflow
from api.main import app as fastapi_app
from agents.manager import AgentManager
from tools.installer import ToolInstaller
from plugins.base_plugin import BasePlugin
from core.repo_scanner import RepoSecretScanner
from core.finding_validator import FindingValidator
from core.scope_import import ScopeImporter
from core.program_profiles import ProgramProfileLoader
from core.oos_parser import parse_exclusions_text
from workflows.bugbounty import BugBountyWorkflow
from core.oob_server import OOBServer
from core.multi_role_scanner import MultiRoleScanner
from core.burp_import import TrafficImporter
from workflows.submission_report import SubmissionReportBuilder
from workflows.scan_diff import ScanSnapshot, ScanDiff
from core.notifications import NotificationManager
from core.scan_control import (
    check_interrupt,
    ScanCancelledError,
    ScanPausedError,
    clear_cancel,
    on_phase_complete,
)
from core.scan_checkpoint import ScanCheckpoint, ScanCheckpoint as _SC
from core.playwright_scanner import PlaywrightScanner
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
import uvicorn

BANNER = r"""
  ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ███╗ █████╗ ████████╗
 ██╔═══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝
 ██║   ██║███████║ ╚████╔╝ ███████║██╔████╔██║███████║   ██║
 ██║▄▄ ██║██╔══██║  ╚██╔╝  ██╔══██║██║╚██╔╝██║██╔══██║   ██║
 ╚██████╔╝██║  ██║   ██║   ██║  ██║██║ ╚═╝ ██║██║  ██║   ██║
  ╚══▀▀═╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝
"""

console = Console()

# Profile ordering for capability gating
PROFILE_ORDER = ["passive", "safe", "balanced", "aggressive", "red_team"]


def _profile_gte(current: str, minimum: str) -> bool:
    """Return True if current profile >= minimum in aggressiveness."""
    try:
        return PROFILE_ORDER.index(current) >= PROFILE_ORDER.index(minimum)
    except ValueError:
        return False


class QAYAMAT:
    def __init__(self, config_path: str = "config/qayamat.yaml"):
        self.config = load_config(config_path)
        self.vault = Vault()
        self.logger = AuditLogger()
        self.policy = PolicyEngine(self.config, self.logger)
        self.vault.load_env_secrets()
        self.ai = AIEngine(self.config, self.vault, self.logger)
        self.session_mgr = SessionManager(self.vault, self.logger)
        self.scan_config: dict = {}
        self._auth_headers: dict = {}

    def _print_banner(self) -> None:
        console.print(Text(BANNER, style="bold red"))
        console.print(
            Panel.fit(
                "[bold cyan]The End of Days for Vulnerabilities[/bold cyan]\n"
                "[dim]Crafted by Pr0fessor_SnApe  •  Authorized testing only[/dim]",
                border_style="red",
            )
        )

    def _print_scope_summary(self) -> None:
        table = Table(title="Scan Configuration", border_style="cyan", show_header=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Targets",      ", ".join(self.scan_config.get("targets", [])))
        table.add_row("Out of Scope", ", ".join(self.scan_config.get("out_of_scope", [])) or "None")
        table.add_row("Profile",      self.scan_config.get("profile", "passive"))
        table.add_row("Auth",         "Provided" if self.scan_config.get("auth") else "None")
        console.print(table)

    # ── Interactive / CLI setup ────────────────────────────────────────────────
    async def interactive_setup(self) -> None:
        self._print_banner()
        console.print("\n[bold yellow]⚠  LEGAL NOTICE:[/bold yellow] Only test systems you own or have explicit written authorization to test.\n")

        if not Confirm.ask("[cyan]I confirm I have authorization to test the specified targets[/cyan]", default=False):
            console.print("[red]Aborted. Authorization required.[/red]")
            sys.exit(0)

        targets_raw = Prompt.ask("\n[cyan]In-scope targets[/cyan] (comma-separated: domains, IPs, CIDR, wildcards)")
        targets = [t.strip() for t in targets_raw.split(",") if t.strip()]
        if not targets:
            console.print("[red]No targets provided. Exiting.[/red]")
            sys.exit(1)

        console.print(
            "[dim]Out-of-scope: paste comma-separated targets OR full exclusion text "
            "(domains, paths, 'do not test' rules, vuln types).[/dim]"
        )
        out_scope_raw = Prompt.ask(
            "[cyan]Out-of-scope / exclusions[/cyan] (comma-separated or multi-line paste)",
            default="",
        )
        out_scope, parsed_exclusions = self._parse_out_of_scope(out_scope_raw, targets)
        rules = Prompt.ask("[cyan]Bug bounty / safe harbor rules[/cyan]", default="Standard responsible disclosure")
        profile = Prompt.ask(
            "[cyan]Testing profile[/cyan]",
            choices=["passive", "safe", "balanced", "aggressive", "red_team"],
            default="safe",
        )
        if parsed_exclusions.no_automated_scanning and profile not in ("passive",):
            console.print("[yellow]Policy indicates no automated scanning — switching profile to passive.[/yellow]")
            profile = "passive"
        if profile == "red_team":
            if not Confirm.ask("[bold red]red_team profile will perform active exploitation. Continue?[/bold red]", default=False):
                profile = "aggressive"

        auth = Prompt.ask("[cyan]Authentication (cookies/token, or leave blank)[/cyan]", default="")
        self.scan_config = {
            "targets": targets,
            "out_of_scope": out_scope,
            "parsed_exclusions": parsed_exclusions.to_dict(),
            "rules": rules,
            "profile": profile,
            "auth": auth,
        }
        self._parsed_exclusions = parsed_exclusions
        self._print_scope_summary()

        if not Confirm.ask("\n[green]Start scan with above configuration?[/green]", default=True):
            console.print("[yellow]Scan cancelled.[/yellow]")
            sys.exit(0)

        self.policy.update_scope(self.scan_config)
        self._setup_auth_session()
        self.logger.info("Scan configured", **self.scan_config)

    async def setup_from_args(self, args: argparse.Namespace) -> None:
        self._print_banner()
        oos_raw = getattr(args, "out_of_scope", "") or ""
        targets_list = [t.strip() for t in args.targets.split(",") if t.strip()] if args.targets else []
        out_scope, parsed_exclusions = self._parse_out_of_scope(oos_raw, targets_list)
        self.scan_config = {
            "targets": targets_list,
            "out_of_scope": out_scope,
            "parsed_exclusions": parsed_exclusions.to_dict(),
            "rules": "CLI launch",
            "profile": args.profile,
            "auth": "",
        }
        self._parsed_exclusions = parsed_exclusions
        if not self.scan_config["targets"]:
            console.print("[red]--targets required in non-interactive mode.[/red]")
            sys.exit(1)
        self.policy.update_scope(self.scan_config)
        self._setup_auth_session()
        self._print_scope_summary()

    def _parse_out_of_scope(self, raw: str, in_scope: list):
        """Parse exclusions text intelligently or fall back to comma-separated list."""
        from core.oos_parser import ParsedExclusions
        if not raw or not raw.strip():
            return [], ParsedExclusions()
        ai_fn = None
        if hasattr(self, "ai") and self.ai and self.ai.is_available:
            ai_fn = getattr(self.ai, "parse_exclusions", None)
        oos_list, parsed = parse_exclusions_text(raw, in_scope=in_scope, ai_parse=ai_fn)
        if oos_list:
            console.print(f"[green]Parsed {len(oos_list)} exclusion rule(s) from text[/green]")
        if parsed.excluded_vuln_types:
            console.print(f"[dim]Excluded vuln types: {', '.join(parsed.excluded_vuln_types)}[/dim]")
        return oos_list, parsed

    def _setup_auth_session(self) -> None:
        """Configure authenticated scanning when user provides cookies or tokens."""
        auth = (self.scan_config.get("auth") or "").strip()
        if not auth:
            return
        headers = {}
        if auth.lower().startswith("bearer "):
            headers["Authorization"] = auth if auth.lower().startswith("bearer") else f"Bearer {auth}"
        elif "=" in auth and not auth.startswith("http"):
            headers["Cookie"] = auth
        else:
            headers["Authorization"] = f"Bearer {auth}"
        self._auth_headers = headers
        for target in self.scan_config.get("targets", [])[:1]:
            base = target if target.startswith("http") else f"https://{target}"
            self.session_mgr.create_session("default", base, headers=headers)
        self.logger.info("Authenticated session configured for scanning")

    async def _run_repo_secret_scan(self, scan_id: int) -> list:
        """Scan git repository targets for leaked secrets (trufflehog/gitleaks)."""
        repo_targets = [
            t for t in self.scan_config.get("targets", [])
            if "github.com" in t or t.endswith(".git") or t.startswith("git@")
        ]
        if not repo_targets:
            return []

        console.print(f"\n[bold cyan]Phase 1b: Repository Secret Scan ({len(repo_targets)} repos)[/bold cyan]")
        scanner = RepoSecretScanner(self.vault, self.logger)
        validator = FindingValidator(
            self.config,
            ai_validate=self.ai.validate_finding if self.ai.is_available else None,
        )
        findings = []
        for repo in repo_targets:

            def _scan():
                return scanner.scan(repo)

            result = await asyncio.to_thread(_scan)
            for item in result.get("findings", []):
                finding = {
                    "title":       f"Leaked Secret ({item.get('secret_type', 'unknown')})",
                    "severity":    "critical",
                    "vuln_type":   "Secret Leak",
                    "url":         repo,
                    "description": f"Secret found in {item.get('file', '?')} (line {item.get('line', '?')})",
                    "evidence":    item.get("raw_value", ""),
                    "tool":        item.get("source_tool", "repo_scanner"),
                }
                ok, _, updated = validator.validate(finding)
                if ok:
                    entry = store.add_finding(updated, scan_id=scan_id)
                    findings.append(entry)
        self.logger.info(f"Repo secret scan: {len(findings)} confirmed leaks")
        return findings

    # ── Plugin loader ─────────────────────────────────────────────────────────
    def _load_plugins(self) -> list:
        """Discover and instantiate all plugins in plugins/"""
        plugins = []
        plugin_dir = Path("plugins")
        for py_file in plugin_dir.rglob("*.py"):
            if py_file.name.startswith("_") or py_file.name == "base_plugin.py":
                continue
            module_path = ".".join(py_file.with_suffix("").parts)
            try:
                mod = importlib.import_module(module_path)
                for _, cls in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(cls, BasePlugin) and cls is not BasePlugin:
                        instance = cls()
                        if instance.validate():
                            plugins.append(instance)
                            self.logger.info(f"Plugin loaded: {cls.name} v{cls.version}")
            except Exception as e:
                self.logger.warning(f"Plugin load failed ({py_file}): {e}")
        return plugins

    async def _run_plugins(self, recon_results: dict, scan_id: int) -> list:
        """Run all discovered plugins and save their findings to the store."""
        plugins = self._load_plugins()
        if not plugins:
            return []

        console.print(f"\n[bold cyan]Phase 6: Plugins ({len(plugins)} loaded)[/bold cyan]")
        all_plugin_findings = []
        context = {
            "targets":      self.policy.targets,
            "profile":      self.policy.profile,
            "policy":       self.policy,
            "logger":       self.logger,
            "recon_results": recon_results,
        }
        for plugin in plugins:
            try:
                self.logger.info(f"Running plugin: {plugin.name}")
                findings = await asyncio.to_thread(plugin.run, context)
                validator = FindingValidator(
                    self.config,
                    ai_validate=self.ai.validate_finding if self.ai.is_available else None,
                )
                for f in findings:
                    ok, _, updated = validator.validate(f)
                    if not ok:
                        continue
                    entry = store.add_finding(updated, scan_id=scan_id)
                    all_plugin_findings.append(entry)
                    store.add_event(f"[plugin:{plugin.name}] {f.get('title','')} [{f.get('severity','')}]", scan_id=scan_id)
                self.logger.info(f"Plugin {plugin.name}: {len(findings)} findings")
            except Exception as e:
                self.logger.warning(f"Plugin {plugin.name} failed: {e}")
        return all_plugin_findings

    # ── Main scan pipeline ────────────────────────────────────────────────────
    def _apply_program_and_scope(self, args: argparse.Namespace) -> None:
        if getattr(args, "scope_file", None):
            scope = ScopeImporter.auto_detect(args.scope_file)
            self.scan_config.update({
                "targets": scope.get("targets", self.scan_config.get("targets", [])),
                "out_of_scope": scope.get("out_of_scope", []),
                "rules": scope.get("rules", self.scan_config.get("rules", "")),
                "profile": scope.get("profile", self.scan_config.get("profile", "safe")),
                "program": scope.get("program", ""),
            })
            self.policy.update_scope(self.scan_config)
            console.print(f"[green]Scope imported: {scope.get('program')} — {len(scope.get('targets', []))} targets[/green]")

        if getattr(args, "program", None):
            loader = ProgramProfileLoader()
            self.config = loader.merge_with_config(self.config, args.program)
            prog = self.config.get("program", {})
            if prog.get("targets"):
                self.scan_config["targets"] = prog["targets"]
            if prog.get("out_of_scope"):
                self.scan_config["out_of_scope"] = prog["out_of_scope"]
            if prog.get("profile"):
                self.scan_config["profile"] = prog["profile"]
            self.scan_config["program"] = args.program
            self.policy.update_scope(self.scan_config)
            console.print(f"[green]Program profile loaded: {args.program}[/green]")

    async def _run_playwright_phase(self, scan_id: int, recon_results: dict) -> list:
        live_urls = [h.get("url") for h in recon_results.get("live_hosts", []) if h.get("url")]
        if not live_urls:
            return []
        pw = PlaywrightScanner()
        if not pw.available:
            self.logger.warning(
                "Playwright unavailable — run: pip install playwright && python -m playwright install chromium"
            )
            store.add_event("Playwright skipped — install Chromium browser", event_type="warning", scan_id=scan_id)
            return []
        console.print(f"\n[bold cyan]Phase 1c: Playwright Browser Testing ({min(len(live_urls), 8)} URLs)[/bold cyan]")
        check_cancelled(scan_id, "playwright")
        validator = FindingValidator(
            self.config,
            ai_validate=self.ai.validate_finding if self.ai.is_available else None,
        )
        findings = await asyncio.to_thread(pw.scan_urls, live_urls, 8)
        saved = []
        for f in findings:
            ok, _, updated = validator.validate(f)
            if ok:
                saved.append(store.add_finding(updated, scan_id=scan_id))
        self._event(f"Playwright: {len(saved)} validated findings")
        return saved

    async def _run_oob_phase(self, scan_id: int, recon_results: dict) -> list:
        if not self.config.get("oob", {}).get("enabled", True):
            return []
        console.print("\n[bold cyan]Phase 2b: OOB Callback Monitoring[/bold cyan]")
        oob = OOBServer(server=self.config.get("oob", {}).get("server", ""))
        host = oob.register()
        self.logger.info(f"OOB callback host: {host}")
        store.add_event(f"OOB server registered: {host}", scan_id=scan_id)
        payloads = [oob.payload_url("xss"), oob.payload_url("ssrf")]
        store.add_event(f"OOB payloads ready: {', '.join(payloads[:2])}", scan_id=scan_id)
        await asyncio.sleep(2)
        findings = oob.correlate_findings(scan_id, store)
        saved = []
        validator = FindingValidator(self.config, ai_validate=self.ai.validate_finding if self.ai.is_available else None)
        for f in findings:
            ok, _, updated = validator.validate(f)
            if ok:
                saved.append(store.add_finding(updated, scan_id=scan_id))
        return saved

    async def _run_multi_role_scan(self, scan_id: int, recon_results: dict) -> list:
        roles_cfg = self.scan_config.get("roles", {})
        if not roles_cfg and not self.config.get("scan", {}).get("multi_role_enabled"):
            return []
        if not roles_cfg:
            return []
        console.print("\n[bold cyan]Phase 3b: Multi-Role Access Control Testing[/bold cyan]")
        scanner = MultiRoleScanner(self.session_mgr, self.logger)
        paths = []
        for url in recon_results.get("urls", [])[:20]:
            if "/api/" in url or "admin" in url.lower():
                from urllib.parse import urlparse
                paths.append(urlparse(url).path or "/")
        base = recon_results.get("live_hosts", [{}])[0].get("url", "")
        if not base:
            return []
        findings = await asyncio.to_thread(scanner.scan_paths, paths, roles_cfg)
        saved = []
        for f in findings:
            saved.append(store.add_finding(f, scan_id=scan_id))
        return saved

    async def _import_traffic(self, path: str, scan_id: int) -> None:
        if not path:
            return
        console.print(f"\n[bold cyan]Importing traffic from {path}[/bold cyan]")
        data = await asyncio.to_thread(TrafficImporter.auto_import, path)
        for url in data.get("urls", []):
            store.add_asset({"url": url, "asset_type": "imported", "status": "discovered"}, scan_id=scan_id)
        self.logger.info(f"Imported {len(data.get('urls', []))} URLs from {data.get('source', '?')}")

    def _notify_scan_complete(self, summary: dict, diff: dict) -> None:
        webhook = (
            self.config.get("monitor", {}).get("webhook_url")
            or self.config.get("notifications", {}).get("discord_webhook")
            or self.config.get("notifications", {}).get("slack_webhook")
        )
        if not webhook:
            return
        msg = (
            f"QAYAMAT scan complete — {summary.get('total', 0)} findings | "
            f"New assets: {len(diff.get('new_assets', []))} | "
            f"New URLs: {len(diff.get('new_urls', []))}"
        )
        notify_webhook(webhook, msg)

    def _notify_scan_complete(self, scan_id: int, summary: dict, diff: dict, risk_score: float) -> None:
        manager = NotificationManager(self.config, self.logger)
        if not manager.has_destinations():
            return

        by_severity = summary.get("by_severity", {})
        targets = ", ".join(self.scan_config.get("targets", [])[:3]) or "n/a"
        msg = "\n".join(
            [
                f"QAYAMAT scan #{scan_id} complete",
                f"Targets: {targets}",
                f"Findings: {summary.get('total', 0)} | Critical: {by_severity.get('Critical', 0)} | High: {by_severity.get('High', 0)}",
                f"Risk score: {risk_score:.1f}/10",
                f"New assets: {len(diff.get('new_assets', []))} | New URLs: {len(diff.get('new_urls', []))}",
            ]
        )
        manager.send(msg)

    async def run(self, args: argparse.Namespace) -> None:
        if getattr(args, "resume", None):
            ckpt = ScanCheckpoint.load(int(args.resume))
            if not ckpt:
                console.print(f"[red]No checkpoint found for scan #{args.resume}. Cannot resume.[/red]")
                sys.exit(1)
            self.scan_config = dict(ckpt.get("scan_config") or {})
            self._parsed_exclusions = None
            self.policy.update_scope(self.scan_config)
            console.print(f"[green]Loaded checkpoint for scan #{args.resume}[/green]")
        elif args.targets:
            await self.setup_from_args(args)
        else:
            await self.interactive_setup()

        if not getattr(args, "resume", None):
            self._apply_program_and_scope(args)

        self.vault.load_env_secrets()
        self.ai = AIEngine(self.config, self.vault, self.logger)

        installer = ToolInstaller()
        installer.setup_directories()

        manager = AgentManager(self.config, self.logger)
        await manager.start()

        profile = self.scan_config.get("profile", "safe")

        scan_id = getattr(args, "resume", None)
        if scan_id:
            scan_id = int(scan_id)
        chains = []
        risk_score = 0.0
        completed_phases: list = []
        recon_results: dict = {}
        checkpoint = ScanCheckpoint.load(scan_id) if scan_id else None

        if checkpoint:
            self.scan_config.update(checkpoint.get("scan_config", {}))
            self.policy.update_scope(self.scan_config)
            recon_results = checkpoint.get("recon_results") or {}
            completed_phases = list(checkpoint.get("completed_phases", []))
            console.print(
                f"[green]Resuming scan #{scan_id} from phase "
                f"'{checkpoint.get('next_phase', 'recon')}' "
                f"({len(completed_phases)} steps already done)[/green]"
            )
            store.resume_scan(scan_id)
        else:
            scan_id = None

        try:
            clear_cancel(scan_id)

            def _ctx():
                return {
                    "scan_config": self.scan_config,
                    "recon_results": recon_results,
                    "completed_phases": completed_phases,
                }

            # ── Phase 1: Reconnaissance ───────────────────────────────────────
            if _SC.should_run("recon", checkpoint):
                check_interrupt(scan_id, "recon", **_ctx())
                console.print("\n[bold cyan]Phase 1: Reconnaissance[/bold cyan]")
                recon = ReconWorkflow(self.config, self.policy, self.ai, self.logger)
                recon_results = await recon.execute()
                scan_id = recon_results.get("scan_id") or scan_id
                completed_phases = on_phase_complete(
                    scan_id, "recon", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            # ── Phase 1b: Repository secret scanning ─────────────────────────
            if scan_id and _SC.should_run("repo_secrets", checkpoint):
                check_interrupt(scan_id, "repo_secrets", **_ctx())
                await self._run_repo_secret_scan(scan_id)
                completed_phases = on_phase_complete(
                    scan_id, "repo_secrets", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            # ── Phase 1c: Playwright browser testing ───────────────────────────
            if scan_id and _SC.should_run("playwright", checkpoint):
                check_interrupt(scan_id, "playwright", **_ctx())
                await self._run_playwright_phase(scan_id, recon_results)
                completed_phases = on_phase_complete(
                    scan_id, "playwright", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            if scan_id and _SC.should_run("ai_guidance", checkpoint) and self.ai.is_available and recon_results.get("live_hosts"):
                suggestion = await asyncio.to_thread(self.ai.suggest_next_steps, {
                    "subdomains": len(recon_results.get("subdomains", [])),
                    "live_hosts": len(recon_results.get("live_hosts", [])),
                    "urls": len(recon_results.get("urls", [])),
                })
                store.add_event(f"AI recon guidance: {suggestion[:200]}...", scan_id=scan_id)
                completed_phases = on_phase_complete(
                    scan_id, "ai_guidance", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            findings = store.get_findings(scan_id=scan_id) if scan_id else []

            if scan_id and _SC.should_run("vuln_scan", checkpoint):
                check_interrupt(scan_id, "vuln scan", **_ctx())
                console.print("\n[bold cyan]Phase 2: Vulnerability Scanning[/bold cyan]")
                vuln = VulnScanWorkflow(self.config, self.policy, self.ai, self.logger, recon_results)
                findings = await vuln.execute()
                completed_phases = on_phase_complete(
                    scan_id, "vuln_scan", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            if scan_id and _SC.should_run("oob", checkpoint):
                check_interrupt(scan_id, "oob", **_ctx())
                oob_findings = await self._run_oob_phase(scan_id, recon_results)
                findings.extend(oob_findings)
                completed_phases = on_phase_complete(
                    scan_id, "oob", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            # ── Phase 3: API Testing ──────────────────────────────────────────
            all_urls = recon_results.get("urls", [])
            api_endpoints = [u for u in all_urls if any(k in u.lower() for k in [
                "api", "graphql", "gql", "/v1/", "/v2/", "/v3/", "rest", "json", "swagger"
            ])]
            if scan_id and _SC.should_run("api_testing", checkpoint) and api_endpoints and _profile_gte(profile, "safe"):
                check_interrupt(scan_id, "api testing", **_ctx())
                console.print(f"\n[bold cyan]Phase 3: API Testing ({len(api_endpoints)} endpoints)[/bold cyan]")
                api_wf = APITestingWorkflow(self.config, self.policy, self.ai, self.logger)
                api_findings = await api_wf.execute(api_endpoints)
                for f in api_findings:
                    entry = store.add_finding(f, scan_id=scan_id)
                    findings.append(entry)
                self.logger.info(f"API testing: {len(api_findings)} findings")
                completed_phases = on_phase_complete(
                    scan_id, "api_testing", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)
            elif not api_endpoints:
                console.print("\n[dim]Phase 3: API Testing — skipped (no API endpoints detected)[/dim]")

            if scan_id and _SC.should_run("multi_role", checkpoint):
                check_interrupt(scan_id, "multi role", **_ctx())
                role_findings = await self._run_multi_role_scan(scan_id, recon_results)
                findings.extend(role_findings)
                completed_phases = on_phase_complete(
                    scan_id, "multi_role", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            # ── Phase 3c: Bug Bounty Enrichment ─────────────────────────────
            if (
                scan_id
                and _SC.should_run("bug_bounty", checkpoint)
                and self.config.get("bugbounty", {}).get("enabled", True)
                and _profile_gte(profile, "safe")
            ):
                console.print("\n[bold cyan]Phase 3c: Bug Bounty Enrichment[/bold cyan]")
                check_interrupt(scan_id, "bug bounty", **_ctx())
                validator = FindingValidator(
                    self.config,
                    ai_validate=self.ai.validate_finding if self.ai.is_available else None,
                )
                parsed = getattr(self, "_parsed_exclusions", None)
                bb_wf = BugBountyWorkflow(
                    self.config, self.policy, self.ai, self.logger,
                    validator=validator,
                    parsed_exclusions=parsed,
                )
                bb_findings = await bb_wf.execute(
                    recon_results, scan_id=scan_id, auth_headers=getattr(self, "_auth_headers", None)
                )
                findings.extend(bb_findings)
                completed_phases = on_phase_complete(
                    scan_id, "bug_bounty", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            if scan_id and _SC.should_run("import_traffic", checkpoint) and getattr(args, "import_traffic", None):
                check_interrupt(scan_id, "import traffic", **_ctx())
                await self._import_traffic(args.import_traffic, scan_id)
                completed_phases = on_phase_complete(
                    scan_id, "import_traffic", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            # ── Phase 4: Safe PoC Generation + AI Analysis ────────────────────
            if scan_id and _SC.should_run("exploitation", checkpoint) and findings and _profile_gte(profile, "balanced"):
                check_interrupt(scan_id, "exploitation", **_ctx())
                console.print(f"\n[bold cyan]Phase 4: PoC Generation + AI Analysis ({len(findings)} findings)[/bold cyan]")
                exploit_wf = ExploitationWorkflow(self.config, self.policy, self.ai, self.logger)
                enriched = await exploit_wf.execute(findings)
                for ef in enriched:
                    if ef.get("poc_payloads") or ef.get("ai_analysis"):
                        store.add_event(
                            f"PoC generated for: {ef.get('title','')} | "
                            f"payloads={len(ef.get('poc_payloads',[]))}",
                            scan_id=scan_id,
                        )
                findings = enriched
                completed_phases = on_phase_complete(
                    scan_id, "exploitation", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)
            else:
                console.print("\n[dim]Phase 4: PoC Generation — skipped (profile < balanced)[/dim]")

            # ── Phase 4b: Active Directory (red_team only) ────────────────────
            if scan_id and _SC.should_run("active_directory", checkpoint) and profile == "red_team":
                check_interrupt(scan_id, "active directory", **_ctx())
                console.print("\n[bold cyan]Phase 4b: Active Directory Assessment[/bold cyan]")
                ad_wf = ActiveDirectoryWorkflow(self.config, self.policy, self.ai, self.logger)
                for domain in self.scan_config.get("targets", []):
                    if "." in domain and not domain.replace(".", "").isdigit():
                        ad_findings = await ad_wf.execute(domain=domain)
                        for f in ad_findings:
                            entry = store.add_finding(f, scan_id=scan_id)
                            findings.append(entry)
                completed_phases = on_phase_complete(
                    scan_id, "active_directory", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            # ── Phase 5: Correlation Engine ───────────────────────────────────
            if scan_id and _SC.should_run("correlation", checkpoint):
                check_interrupt(scan_id, "correlation", **_ctx())
            console.print("\n[bold cyan]Phase 5: Correlation & Risk Analysis[/bold cyan]")
            all_findings_for_corr = store.get_findings(scan_id=scan_id)
            correlation = CorrelationEngine()
            chains = correlation.build_chains(all_findings_for_corr)
            risk_score = correlation.calculate_risk_score(all_findings_for_corr)

            if chains:
                console.print(f"  [bold red]Attack chains identified: {len(chains)}[/bold red]")
                for chain in chains:
                    console.print(f"  [yellow]→[/yellow] {chain['name']} [{chain['severity']}]")
                    store.add_event(
                        f"ATTACK CHAIN: {chain['name']} [{chain['severity']}] — "
                        + " → ".join(chain["steps"][:2]),
                        event_type="critical",
                        scan_id=scan_id,
                    )
            console.print(f"  [bold]Risk Score: [red]{risk_score:.1f}[/red] / 10[/bold]")
            store.add_event(f"Risk score: {risk_score:.1f}/10 | Attack chains: {len(chains)}", scan_id=scan_id)
            if scan_id:
                completed_phases = on_phase_complete(
                    scan_id, "correlation", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            if scan_id and _SC.should_run("plugins", checkpoint):
                check_interrupt(scan_id, "plugins", **_ctx())
                plugin_findings = await self._run_plugins(recon_results, scan_id)
                findings.extend(plugin_findings)
                completed_phases = on_phase_complete(
                    scan_id, "plugins", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            if scan_id and _SC.should_run("reporting", checkpoint):
                check_interrupt(scan_id, "reporting", **_ctx())
            console.print("\n[bold cyan]Phase 7: Report Generation[/bold cyan]")
            all_findings = store.get_findings(scan_id=scan_id)
            reporter = ReportGenerator(all_findings, self.config, self.logger)
            reporter.generate(
                extra={
                    "attack_chains": chains,
                    "risk_score": risk_score,
                    "assets": store.get_assets(scan_id=scan_id),
                    "events": store.get_events(scan_id=scan_id),
                }
            )
            console.print("[green]Reports saved to reports/ (with steps to reproduce)[/green]")
            if scan_id:
                completed_phases = on_phase_complete(
                    scan_id, "reporting", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            if scan_id and _SC.should_run("submission", checkpoint) and self.config.get("scan", {}).get("submission_reports", True):
                check_interrupt(scan_id, "submission", **_ctx())
                console.print("\n[bold cyan]Phase 7b: Submission Reports[/bold cyan]")
                sub_paths = SubmissionReportBuilder(
                    store.get_findings(scan_id=scan_id),
                    program=self.scan_config.get("program", ""),
                ).export_all()
                console.print(f"[green]{len(sub_paths)} submission reports → reports/submissions/[/green]")
                completed_phases = on_phase_complete(
                    scan_id, "submission", self.scan_config, recon_results, completed_phases
                )
                checkpoint = ScanCheckpoint.load(scan_id)

            if scan_id and _SC.should_run("snapshot", checkpoint):
                check_interrupt(scan_id, "snapshot", **_ctx())
            if scan_id:
                snap = ScanSnapshot(scan_id)
                snap.save(
                    store.get_assets(scan_id=scan_id),
                    store.get_findings(scan_id=scan_id),
                    recon_results.get("urls", []),
                )
                current = {
                    "assets": [a["url"] for a in store.get_assets(scan_id=scan_id)],
                    "urls": recon_results.get("urls", []),
                    "findings_fp": [f.get("fingerprint", f["id"]) for f in store.get_findings(scan_id=scan_id)],
                }
                diff = ScanDiff.compare(current, ScanSnapshot.load_previous(scan_id))
                store.update_scan(scan_id, diff_json=json.dumps(diff), status="complete", progress=100.0)
                ScanCheckpoint.delete(scan_id)
                completed_phases = on_phase_complete(
                    scan_id, "snapshot", self.scan_config, recon_results, completed_phases
                )

            summary = store.findings_summary(scan_id=scan_id) if scan_id else store.findings_summary()
            asset_summary = store.assets_summary(scan_id=scan_id) if scan_id else store.assets_summary()
            diff_data = {}
            if scan_id:
                s = store.get_scan(scan_id) or {}
                try:
                    diff_data = json.loads(s.get("diff_json") or "{}")
                except Exception:
                    pass
            self._notify_scan_complete(scan_id or 0, summary, diff_data, risk_score)
            console.print(
                Panel.fit(
                    f"[bold green]Scan complete![/bold green]\n"
                    f"[white]Findings: [bold]{summary['total']}[/bold]  |  "
                    f"Assets: [bold]{asset_summary['total']}[/bold]  |  "
                    f"Attack Chains: [bold]{len(chains)}[/bold]  |  "
                    f"Risk Score: [bold red]{risk_score:.1f}/10[/bold red][/white]\n"
                    f"[cyan]Dashboard → http://localhost:{args.port}[/cyan]",
                    border_style="green",
                )
            )

        except ScanPausedError as e:
            console.print(f"\n[cyan]{e}[/cyan]")
            console.print(
                f"[dim]Progress saved. Resume with: python qayamat.py --resume {scan_id}[/dim]"
            )
        except ScanCancelledError as e:
            console.print(f"\n[yellow]{e}[/yellow]")
            if scan_id:
                store.update_scan(scan_id, status="cancelled")
            console.print("[dim]Partial results saved. Open dashboard to review.[/dim]")

        # ── Dashboard ─────────────────────────────────────────────────────
        uv_config = uvicorn.Config(fastapi_app, host="0.0.0.0", port=args.port, log_level="warning")
        server = uvicorn.Server(uv_config)
        await server.serve()


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="QAYAMAT — Autonomous AI-Powered Offensive Security OS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--targets",  help="Comma-separated in-scope targets")
    parser.add_argument(
        "--profile",
        choices=["passive", "safe", "balanced", "aggressive", "red_team"],
        default="safe",
        help="Testing profile (default: safe)",
    )
    parser.add_argument("--config",         default="config/qayamat.yaml")
    parser.add_argument("--port",           type=int, default=8000)
    parser.add_argument("--dashboard-only", action="store_true")
    parser.add_argument("--program",        help="Load config/programs/<name>.yaml profile")
    parser.add_argument("--scope-file",     help="Import scope from HackerOne/Bugcrowd/YAML/txt")
    parser.add_argument("--import-traffic", help="Import URLs from HAR/Burp XML/ZAP JSON")
    parser.add_argument("--monitor",        action="store_true", help="Enable continuous monitoring mode")
    parser.add_argument(
        "--out-of-scope",
        help="Out-of-scope targets or paste full exclusion policy text",
        default="",
    )
    parser.add_argument(
        "--resume",
        type=int,
        metavar="SCAN_ID",
        help="Resume a paused scan from its last saved checkpoint",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.dashboard_only:
        console.print("[cyan]Starting dashboard only...[/cyan]")
        uv_config = uvicorn.Config(fastapi_app, host="0.0.0.0", port=args.port, log_level="info")
        server = uvicorn.Server(uv_config)
        asyncio.run(server.serve())
    else:
        q = QAYAMAT(config_path=args.config)
        try:
            asyncio.run(q.run(args))
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
            sys.exit(0)
