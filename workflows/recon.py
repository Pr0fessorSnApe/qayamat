"""
QAYAMAT - Reconnaissance Workflow v3
"""

import asyncio
import json
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from core.ai_engine import AIEngine
from core.archive_miner import ArchiveMiner
from core.github_recon import GitHubRecon, is_github_target
from core.intel_fusion import IntelFusion
from core.logger import AuditLogger
from core.policy_engine import PolicyEngine
from core.rl_recon import RLReconAgent
from core.scan_control import ScanCancelledError, check_cancelled
from core.scan_store import store
from tools.orchestrator import ToolOrchestrator
from tools.wrappers.base import ToolWrapper

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text


class ScanProgressUI:
    def __init__(self):
        self.overall_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        self.overall_task = self.overall_progress.add_task("Overall Scan", total=100)
        self.phase_progresses: Dict[str, Progress] = {}
        self.stats = {"assets": 0, "vulns": 0, "requests": 0, "errors": 0, "phase": "Initializing"}
        self._live = Live(self._build_layout(), refresh_per_second=4, transient=False)
        self._live.start()

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(
                Panel(
                    Text("QAYAMAT - Autonomous Offensive Security OS  |  Pr0fessor_SnApe", style="bold red"),
                    border_style="red",
                ),
                size=3,
            ),
            Layout(name="body"),
        )
        layout["body"].split_row(Layout(name="progress", ratio=2), Layout(name="stats", ratio=1))
        layout["body"]["progress"].update(
            Panel(Group(self.overall_progress, *self.phase_progresses.values()), title="Scan Progress", border_style="cyan")
        )
        stats_table = Table(box=None, show_header=False, padding=(0, 1))
        stats_table.add_column(style="dim cyan", width=14)
        stats_table.add_column(style="bold white")
        for key, value in self.stats.items():
            stats_table.add_row(key.title() + ":", str(value))
        layout["body"]["stats"].update(Panel(stats_table, title="Live Stats", border_style="yellow"))
        return layout

    def _refresh(self):
        try:
            self._live.update(self._build_layout())
        except Exception:
            pass

    def add_phase(self, name: str, total: int) -> None:
        pb = Progress(
            TextColumn(f"  [yellow]{name:<25}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        pb.add_task(name, total=total)
        self.phase_progresses[name] = pb
        self._refresh()

    def update_phase(self, name: str, advance: int = 1) -> None:
        if name in self.phase_progresses:
            pb = self.phase_progresses[name]
            pb.advance(pb.task_ids[0], advance)
        self._refresh()

    def complete_phase(self, name: str) -> None:
        if name in self.phase_progresses:
            pb = self.phase_progresses[name]
            pb.update(pb.task_ids[0], completed=pb.tasks[0].total)
        self._refresh()

    def update_overall(self, value: float) -> None:
        self.overall_progress.update(self.overall_task, completed=value)
        self._refresh()

    def update_stats(self, **kwargs) -> None:
        self.stats.update(kwargs)
        self._refresh()

    def stop(self) -> None:
        try:
            self._live.stop()
        except Exception:
            pass


def _tool_path(name: str) -> Optional[str]:
    tools_dir = os.environ.get("QAYAMAT_TOOLS", "/opt/qayamat/tools")
    for candidate in [os.path.join(tools_dir, name), os.path.expanduser(f"~/go/bin/{name}"), shutil.which(name)]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


async def _run(cmd: List[str], timeout: int = 300, input_data: str = None) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )
        stdin_bytes = input_data.encode() if input_data else None
        stdout, _ = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=timeout)
        return stdout.decode(errors="ignore").strip()
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return ""
    except Exception:
        return ""


def _write_tmp(lines: List[str]) -> str:
    handle = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    handle.write("\n".join(lines))
    handle.flush()
    handle.close()
    return handle.name


def _get_targets(policy: PolicyEngine) -> List[str]:
    for attr in ("targets", "_targets", "scope"):
        value = getattr(policy, attr, None)
        if not value:
            continue
        if isinstance(value, list) and value:
            return [str(target).strip() for target in value if str(target).strip()]
        if isinstance(value, dict):
            targets = value.get("targets", [])
            if targets:
                return [str(target).strip() for target in targets if str(target).strip()]
    return []


async def _broadcast(event_type: str, data: dict, scan_id: Optional[int] = None) -> None:
    try:
        from api.websocket import manager

        await manager.broadcast({"type": event_type, "scan_id": scan_id, "stats": store.stats(), **data})
    except Exception:
        pass


class _Wrap(ToolWrapper):
    """Inline wrapper helper instantiated with just policy+logger."""

    def __init__(self, name: str, policy=None, logger=None):
        super().__init__(policy=policy, logger=logger)
        self.name = name


async def _wrap_run(
    name: str,
    args: List[str],
    policy=None,
    logger=None,
    target: str = None,
    timeout: int = 300,
) -> str:
    wrapper = _Wrap(name, policy=policy, logger=logger)
    return await asyncio.to_thread(wrapper.run, args, target=target, timeout=timeout)


async def run_subfinder(domain: str, policy=None, logger=None) -> List[str]:
    out = await _wrap_run("subfinder", ["-d", domain, "-silent", "-all"], policy=policy, logger=logger, target=domain, timeout=120)
    return [line.strip() for line in out.splitlines() if line.strip()]


async def run_amass(domain: str, policy=None, logger=None) -> List[str]:
    out = await _wrap_run("amass", ["enum", "-passive", "-d", domain, "-silent"], policy=policy, logger=logger, target=domain, timeout=180)
    return [line.strip() for line in out.splitlines() if line.strip()]


async def run_assetfinder(domain: str) -> List[str]:
    binary = _tool_path("assetfinder")
    if not binary:
        return []
    out = await _run([binary, "--subs-only", domain], timeout=60)
    return [line.strip() for line in out.splitlines() if line.strip()]


async def run_dnsx(hosts: List[str], policy=None, logger=None) -> List[str]:
    if not hosts:
        return hosts
    tmp = _write_tmp(hosts)
    try:
        out = await _wrap_run("dnsx", ["-l", tmp, "-silent", "-a", "-resp"], policy=policy, logger=logger, timeout=180)
        live = []
        for line in out.splitlines():
            line = line.strip()
            if line:
                host = line.split()[0].rstrip(".")
                if host:
                    live.append(host)
        return list(set(live)) if live else hosts
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


async def run_httpx(hosts: List[str], policy=None, logger=None) -> List[Dict[str, Any]]:
    if not hosts:
        return []
    tmp = _write_tmp(hosts)
    try:
        out = await _wrap_run(
            "httpx",
            ["-l", tmp, "-silent", "-json", "-title", "-tech-detect", "-status-code", "-content-length", "-follow-redirects"],
            policy=policy,
            logger=logger,
            timeout=300,
        )
        results = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(
                    {
                        "url": data.get("url", ""),
                        "host": data.get("host", data.get("input", "")),
                        "status_code": data.get("status-code", data.get("status_code", 0)),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", data.get("technologies", [])),
                        "ip": (data.get("a") or [""])[0],
                        "content_length": data.get("content-length", data.get("content_length", 0)),
                        "response_time": data.get("time", data.get("response_time", 0)),
                    }
                )
            except json.JSONDecodeError:
                if line.startswith("http"):
                    results.append({"url": line, "host": line, "status_code": 0, "title": "", "tech": [], "ip": ""})
        return results
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


async def run_naabu(hosts: List[str], policy=None, logger=None) -> Dict[str, List[int]]:
    if not hosts:
        return {}
    ports = "80,443,8080,8443,8000,3000,5000,9000,9090,22,21,25,3306,5432,6379,27017"
    tmp = _write_tmp(hosts)
    try:
        out = await _wrap_run("naabu", ["-l", tmp, "-p", ports, "-silent", "-json", "-rate", "1000"], policy=policy, logger=logger, timeout=300)
        port_map: Dict[str, List[int]] = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", data.get("ip", ""))
                port = data.get("port", 0)
                if host and port:
                    port_map.setdefault(host, []).append(int(port))
            except (json.JSONDecodeError, ValueError):
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    try:
                        port_map.setdefault(parts[0], []).append(int(parts[1]))
                    except ValueError:
                        pass
        return port_map
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


async def run_gau(domain: str, policy=None, logger=None) -> List[str]:
    out = await _wrap_run("gau", [domain, "--blacklist", "png,jpg,gif,css,woff,ttf,svg"], policy=policy, logger=logger, target=domain, timeout=120)
    return [line.strip() for line in out.splitlines() if line.strip() and line.startswith("http")]


async def run_waybackurls(domain: str) -> List[str]:
    binary = _tool_path("waybackurls")
    if not binary:
        return []
    out = await _run([binary, domain], timeout=60)
    return [line.strip() for line in out.splitlines() if line.strip() and line.startswith("http")]


async def run_katana(urls: List[str], policy=None, logger=None) -> List[str]:
    if not urls:
        return []
    discovered = []
    for url in urls[:10]:
        out = await _wrap_run("katana", ["-u", url, "-silent", "-depth", "2", "-jc", "-kf", "all"], policy=policy, logger=logger, target=url, timeout=120)
        for line in out.splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                discovered.append(line)
    return list(set(discovered))


async def run_gowitness(urls: List[str]) -> None:
    binary = _tool_path("gowitness")
    if not binary or not urls:
        return
    tmp = _write_tmp(urls)
    try:
        await _run([binary, "scan", "file", "-f", tmp, "--screenshot-path", "screenshots/"], timeout=300)
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


async def run_intel_fusion(domain: str, vault=None, config: Optional[dict] = None) -> List[str]:
    """Query Shodan/Censys/OTX/SecurityTrails/URLScan/VirusTotal for subdomains."""

    def _sync():
        try:
            fusion = IntelFusion(vault=vault, config=config)
            return fusion.gather_subdomains(domain)
        except Exception:
            return []

    return await asyncio.to_thread(_sync)


async def run_archive_miner(domain: str) -> tuple:
    """Fetch historical URLs and extract params/endpoints from Wayback/OTX."""

    def _sync():
        try:
            miner = ArchiveMiner(timeout=30)
            urls = miner.fetch_urls(domain)
            params = miner.extract_params(urls)
            endpoints = miner.extract_endpoints(urls, domain)
            return urls, params, endpoints
        except Exception:
            return [], set(), []

    return await asyncio.to_thread(_sync)


async def run_github_recon(target: str, vault=None, config: Optional[dict] = None, logger=None) -> Dict[str, Any]:
    """Collect passive GitHub org/repo metadata for in-scope GitHub targets."""

    def _sync():
        try:
            recon = GitHubRecon.from_sources(vault=vault, config=config, logger=logger)
            return recon.scan_target(target)
        except Exception:
            return {"profiles": [], "repos": [], "urls": [], "hosts": [], "contributors": []}

    return await asyncio.to_thread(_sync)


class ReconWorkflow:
    def __init__(self, config: dict, policy: PolicyEngine, ai: AIEngine, logger: AuditLogger):
        self.config = config
        self.policy = policy
        self.ai = ai
        self.logger = logger
        self.orchestrator = ToolOrchestrator(policy, logger)
        self.rl_agent = RLReconAgent()
        self._scan_id: Optional[int] = None

    def _event(self, msg: str, event_type: str = "info") -> None:
        self.logger.info(msg)
        store.add_event(msg, event_type=event_type, scan_id=self._scan_id)

    async def execute(self) -> Dict[str, Any]:
        ui = ScanProgressUI()
        results: Dict[str, Any] = {
            "subdomains": [],
            "live_hosts": [],
            "open_ports": {},
            "urls": [],
            "tech_stack": {},
            "params": set(),
            "github_profiles": [],
            "github_repos": [],
            "github_contributors": [],
        }

        targets = _get_targets(self.policy)
        if not targets:
            self._event("No in-scope targets found.", "error")
            ui.stop()
            return results

        github_targets = [target for target in targets if is_github_target(target)]
        domain_targets = [target for target in targets if target not in github_targets]

        active = store.get_active_scan()
        if active and active.get("status") == "running":
            self._scan_id = active["id"]
        else:
            scan = store.create_scan(
                name=f"Scan - {', '.join(targets[:3])}",
                targets=targets,
                profile=getattr(self.policy, "profile", "safe"),
            )
            self._scan_id = scan["id"]

        self._event(f"Recon started | targets={', '.join(targets)}")

        try:
            check_cancelled(self._scan_id, "recon start")

            github_urls: List[str] = []
            github_hosts: List[str] = []
            if github_targets:
                ui.add_phase("GitHub Recon", len(github_targets))
                ui.update_stats(phase="GitHub Recon")
                self._event(f"GitHub recon started for {len(github_targets)} target(s)")

                for target in github_targets:
                    self._event(f"github_recon -> {target}")
                    gh = await run_github_recon(
                        target,
                        vault=self.ai.vault if hasattr(self.ai, "vault") else None,
                        config=self.config,
                        logger=self.logger,
                    )
                    results["github_profiles"].extend(gh.get("profiles", []))
                    results["github_repos"].extend(gh.get("repos", []))
                    results["github_contributors"].extend(gh.get("contributors", []))
                    github_urls.extend(gh.get("urls", []))
                    github_hosts.extend(gh.get("hosts", []))

                    for profile in gh.get("profiles", []):
                        store.add_asset(
                            {"url": profile.get("url", ""), "asset_type": "github_profile", "status": "discovered"},
                            scan_id=self._scan_id,
                        )
                        if profile.get("blog"):
                            store.add_asset(
                                {"url": profile["blog"], "asset_type": "github_external", "status": "discovered"},
                                scan_id=self._scan_id,
                            )

                    for repo in gh.get("repos", []):
                        tech = [repo.get("language", "")] + list(repo.get("topics", []))
                        store.add_asset(
                            {
                                "url": repo.get("url", ""),
                                "asset_type": "github_repo",
                                "status": "discovered",
                                "technologies": [item for item in tech if item],
                            },
                            scan_id=self._scan_id,
                        )

                    for url in gh.get("urls", []):
                        store.add_asset(
                            {"url": url, "asset_type": "github_external", "status": "discovered"},
                            scan_id=self._scan_id,
                        )

                    for login in gh.get("contributors", []):
                        store.add_asset(
                            {
                                "url": f"https://github.com/{login}",
                                "asset_type": "github_contributor",
                                "status": "discovered",
                            },
                            scan_id=self._scan_id,
                        )

                    self._event(
                        "GitHub recon: "
                        f"profiles={len(gh.get('profiles', []))} "
                        f"repos={len(gh.get('repos', []))} "
                        f"urls={len(gh.get('urls', []))}"
                    )
                    ui.update_phase("GitHub Recon")

                ui.complete_phase("GitHub Recon")
                ui.update_overall(10)
                store.update_scan(self._scan_id, progress=10.0)

            ui.add_phase("Subdomain Enumeration", max(1, len(domain_targets) * 4))
            ui.update_stats(phase="Subdomain Enumeration")
            store.update_scan(self._scan_id, progress=10.0 if github_targets else 5.0)

            unique_subs: List[str] = []
            all_subs: List[str] = list(domain_targets)
            req = 0

            if domain_targets:
                for domain in domain_targets:
                    self._event(f"subfinder -> {domain}")
                    subs = await run_subfinder(domain, policy=self.policy, logger=self.logger)
                    all_subs.extend(subs)
                    req += 1
                    ui.update_phase("Subdomain Enumeration")
                    ui.update_stats(assets=len(set(all_subs)), requests=req)

                    self._event(f"assetfinder -> {domain}")
                    subs_af = await run_assetfinder(domain)
                    all_subs.extend(subs_af)
                    req += 1
                    ui.update_phase("Subdomain Enumeration")
                    ui.update_stats(assets=len(set(all_subs)), requests=req)

                    self._event(f"amass -> {domain}")
                    subs_am = await run_amass(domain, policy=self.policy, logger=self.logger)
                    all_subs.extend(subs_am)
                    req += 1
                    ui.update_phase("Subdomain Enumeration")
                    ui.update_stats(assets=len(set(all_subs)), requests=req)

                    self._event(f"intel_fusion -> {domain}")
                    intel_subs = await run_intel_fusion(
                        domain,
                        vault=self.ai.vault if hasattr(self.ai, "vault") else None,
                        config=self.config,
                    )
                    all_subs.extend(intel_subs)
                    req += 1
                    ui.update_phase("Subdomain Enumeration")
                    ui.update_stats(assets=len(set(all_subs)), requests=req)
                    if intel_subs:
                        self._event(f"Intel Fusion: {len(intel_subs)} additional hosts from OSINT")

                    self.rl_agent.update(
                        state_features={"domain_len": len(domain), "has_www": domain.startswith("www")},
                        action=0,
                        reward=float(len(subs) + len(intel_subs)),
                        next_state_features={"domain_len": len(domain), "subdomain_count": len(all_subs)},
                        next_available_actions=[0, 1],
                    )
                    self.rl_agent.decay_epsilon()

                unique_subs = sorted(
                    {
                        item.strip().lower().rstrip(".")
                        for item in all_subs
                        if item.strip() and "." in item
                    }
                )

                for sub in unique_subs:
                    store.add_asset({"url": sub, "asset_type": "subdomain", "status": "discovered"}, scan_id=self._scan_id)
            else:
                self._event("Subdomain enumeration skipped: no domain targets supplied")

            self._event(f"Subdomain enumeration complete: {len(unique_subs)} unique hosts")
            ui.complete_phase("Subdomain Enumeration")
            ui.update_overall(20)
            store.update_scan(self._scan_id, progress=20.0)
            await _broadcast("assets_update", {"count": len(unique_subs)}, self._scan_id)

            check_cancelled(self._scan_id, "DNS resolution")
            ui.add_phase("DNS Resolution", 1)
            ui.update_stats(phase="DNS Resolution")
            resolved: List[str] = []
            if unique_subs:
                self._event(f"dnsx resolving {len(unique_subs)} hosts...")
                resolved = await run_dnsx(unique_subs, policy=self.policy, logger=self.logger)
            else:
                self._event("DNS resolution skipped: no discovered domain hosts")
            ui.complete_phase("DNS Resolution")
            ui.update_overall(35)
            store.update_scan(self._scan_id, progress=35.0)
            self._event(f"DNS resolution: {len(resolved)} live hosts")

            check_cancelled(self._scan_id, "HTTP probing")
            ui.add_phase("HTTP Probing", 1)
            ui.update_stats(phase="HTTP Probing")
            live_hosts: List[Dict[str, Any]] = []
            live_urls: List[str] = []
            if resolved:
                self._event(f"httpx probing {len(resolved)} hosts...")
                live_hosts = await run_httpx(resolved, policy=self.policy, logger=self.logger)
                live_urls = [host["url"] for host in live_hosts if host.get("url")]
            else:
                self._event("HTTP probing skipped: no resolved hosts")

            tech_stack: Dict[str, List[Any]] = {}
            for host in live_hosts:
                tech = host.get("tech", [])
                if host.get("url"):
                    tech_stack[host["url"]] = tech
                store.add_asset(
                    {
                        "url": host.get("url", host.get("host", "")),
                        "asset_type": "endpoint",
                        "status": "active",
                        "technologies": tech,
                    },
                    scan_id=self._scan_id,
                )
                self._event(
                    f"httpx: {host.get('url', '')} [{host.get('status_code', '')}]"
                    + (f" [{','.join(tech[:3])}]" if tech else "")
                )
                await _broadcast("new_asset", {"url": host.get("url", ""), "tech": tech}, self._scan_id)

            ui.complete_phase("HTTP Probing")
            ui.update_overall(50)
            store.update_scan(self._scan_id, progress=50.0)
            self._event(f"HTTP probing: {len(live_hosts)} live hosts found")

            ui.add_phase("Port Scanning", 1)
            ui.update_stats(phase="Port Scanning")
            open_ports: Dict[str, List[int]] = {}
            if resolved:
                self._event(f"naabu scanning {len(resolved[:50])} hosts...")
                open_ports = await run_naabu(resolved[:50], policy=self.policy, logger=self.logger)
            else:
                self._event("Port scanning skipped: no resolved hosts")
            for host, ports in open_ports.items():
                self._event(f"naabu: {host} open ports: {','.join(map(str, ports))}")
            ui.complete_phase("Port Scanning")
            ui.update_overall(65)
            store.update_scan(self._scan_id, progress=65.0)
            self._event(f"Port scan: {sum(len(value) for value in open_ports.values())} open ports across {len(open_ports)} hosts")

            ui.add_phase("URL Discovery", 1)
            ui.update_stats(phase="URL Discovery")
            all_urls: List[str] = list(live_urls) + list(github_urls)
            all_params: set = set()

            for domain in domain_targets:
                self._event(f"gau -> {domain}")
                all_urls.extend(await run_gau(domain, policy=self.policy, logger=self.logger))

                all_urls.extend(await run_waybackurls(domain))

                self._event(f"archive_miner -> {domain}")
                archive_urls, params, _ = await run_archive_miner(domain)
                all_urls.extend(archive_urls)
                all_params.update(params)
                if params:
                    sample = ", ".join(list(params)[:10])
                    self._event(f"ArchiveMiner: discovered {len(params)} unique parameters: {sample}")

            if live_urls:
                self._event("katana crawling live hosts...")
                all_urls.extend(await run_katana(live_urls[:5], policy=self.policy, logger=self.logger))
            else:
                self._event("Katana skipped: no live HTTP targets")

            unique_urls = list(set(all_urls))
            for url in unique_urls:
                if url not in live_urls:
                    asset_type = "github_external" if url in github_urls else "endpoint"
                    store.add_asset({"url": url, "asset_type": asset_type, "status": "discovered"}, scan_id=self._scan_id)

            ui.complete_phase("URL Discovery")
            ui.update_overall(85)
            store.update_scan(self._scan_id, progress=85.0)
            self._event(f"URL discovery: {len(unique_urls)} total URLs | {len(all_params)} unique params")

            if live_urls:
                ui.add_phase("Screenshots", 1)
                ui.update_stats(phase="Screenshots")
                self._event(f"gowitness taking {min(len(live_urls), 20)} screenshots...")
                await run_gowitness(live_urls[:20])
                ui.complete_phase("Screenshots")
                self._event("Screenshots saved to screenshots/")

            ui.update_overall(100)
            total_assets = store.assets_summary(scan_id=self._scan_id)["total"]
            ui.update_stats(assets=total_assets, requests=req + len(resolved) * 2, phase="Complete")
            store.update_scan(self._scan_id, progress=100.0, status="recon_complete")
            self._event(
                "Recon complete | "
                f"subdomains={len(unique_subs)} "
                f"github_hosts={len(github_hosts)} "
                f"live={len(live_hosts)} "
                f"urls={len(unique_urls)} "
                f"params={len(all_params)}"
            )
            await _broadcast("recon_complete", {"total_assets": total_assets}, self._scan_id)

            ui.stop()
            results.update(
                {
                    "subdomains": unique_subs,
                    "live_hosts": live_hosts,
                    "open_ports": open_ports,
                    "urls": unique_urls,
                    "tech_stack": tech_stack,
                    "params": all_params,
                    "scan_id": self._scan_id,
                }
            )
            return results

        except ScanCancelledError:
            self._event("Recon cancelled by user", "warning")
            store.update_scan(self._scan_id, status="cancelled")
            ui.stop()
            raise
        except Exception as exc:
            self._event(f"Recon failed: {exc}", "error")
            store.update_scan(self._scan_id, status="failed")
            ui.stop()
            raise
