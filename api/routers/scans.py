"""QAYAMAT — Scans Router (reads from real ScanStore)"""

import asyncio
import time
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from api.websocket import manager
from core.scan_store import store

router = APIRouter()


# ─── Pydantic models ──────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    name: str
    targets: List[str]
    profile: str = "safe"


class ScanLaunch(BaseModel):
    targets: List[str]
    profile: str = "safe"
    auth: str = ""
    out_of_scope: List[str] = []
    exclusions_text: str = ""  # intelligent parser for pasted policy text


class ScanStatus(BaseModel):
    id: int
    name: str
    progress: float
    status: str
    profile: str
    targets: Optional[List[str]] = []
    created_at: Optional[str]
    completed_at: Optional[str]


# ─── Standard CRUD routes ─────────────────────────────────────────────────────

@router.post("/scans", response_model=ScanStatus)
async def create_scan(scan: ScanCreate):
    return store.create_scan(scan.name, scan.targets, scan.profile)


@router.get("/scans", response_model=List[ScanStatus])
async def list_scans():
    return store.get_scans()


@router.get("/scans/active")
async def get_active_scan():
    scan = store.get_active_scan()
    if not scan:
        return {"status": "idle", "message": "No active scan"}
    return scan


@router.get("/scans/{scan_id}", response_model=ScanStatus)
async def get_scan(scan_id: int):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/findings")
async def scan_findings(scan_id: int):
    return store.get_findings(scan_id=scan_id)


@router.get("/scans/{scan_id}/assets")
async def scan_assets(scan_id: int):
    return store.get_assets(scan_id=scan_id)


@router.get("/scans/{scan_id}/events")
async def scan_events(scan_id: int, limit: int = 100):
    return store.get_events(limit=limit, scan_id=scan_id)


@router.post("/scans/{scan_id}/pause")
async def pause_scan(scan_id: int):
    """Pause scan safely at the next phase boundary (checkpoint saved)."""
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") not in ("running", "pending"):
        return {"scan_id": scan_id, "status": scan.get("status"), "message": "Scan is not running"}
    store.pause_scan(scan_id)
    await manager.broadcast({
        "type": "pause_requested",
        "scan_id": scan_id,
        "message": "Pause requested — saving progress at end of current step",
    })
    return {"scan_id": scan_id, "status": "pausing", "message": "Pause requested"}


@router.post("/scans/{scan_id}/resume")
async def resume_scan(scan_id: int, background_tasks: BackgroundTasks):
    """Resume a paused scan from the last checkpoint."""
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not ScanCheckpoint.load(scan_id):
        raise HTTPException(status_code=400, detail="No checkpoint found for this scan")
    if not store.resume_scan(scan_id):
        raise HTTPException(status_code=400, detail="Cannot resume scan")
    ckpt = ScanCheckpoint.load(scan_id)
    cfg = ckpt.get("scan_config", {})
    targets = cfg.get("targets", scan.get("targets", []))
    profile = cfg.get("profile", scan.get("profile", "safe"))
    background_tasks.add_task(
        _run_scan_pipeline,
        scan_id,
        targets,
        profile,
        cfg.get("auth", ""),
        cfg.get("out_of_scope", []),
        "",
        resume=True,
    )
    await manager.broadcast({"type": "resumed", "scan_id": scan_id, "message": "Scan resumed"})
    return {"scan_id": scan_id, "status": "running", "message": "Resume started"}


@router.get("/scans/paused")
async def list_paused_scans():
    return {"paused": store.get_paused_scans()}


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    """Cancel a running scan from the dashboard or API."""
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") in ("complete", "cancelled", "failed", "error"):
        return {"scan_id": scan_id, "status": scan.get("status"), "message": "Scan already finished"}
    store.cancel_scan(scan_id)
    await manager.broadcast({
        "type": "cancelled",
        "scan_id": scan_id,
        "message": "Scan cancelled by user",
    })
    return {"scan_id": scan_id, "status": "cancelled", "message": "Cancellation requested"}


@router.get("/events")
async def all_events(limit: int = 100):
    """Live scan log — last N events across all scans."""
    return store.get_events(limit=limit)


@router.get("/stats")
async def dashboard_stats():
    """Single endpoint for dashboard summary card data."""
    s = store.stats()
    active = store.get_active_scan()
    return {
        **s,
        "active_scan": active,
        "findings":    store.get_findings()[-10:],   # last 10 for Recent Findings
        "assets":      store.get_assets()[:50],      # first 50 for Assets view
    }


# ─── Scan launcher (runs real pipeline in-process) ────────────────────────────

@router.post("/scans/launch")
async def launch_scan(req: ScanLaunch, background_tasks: BackgroundTasks):
    """
    Launch a full QAYAMAT scan pipeline from the dashboard.
    Runs the real workflow in an async background task so the in-memory
    scan_store is shared with the API process — results appear live.
    """
    first = req.targets[0] if req.targets else "target"
    name  = f"dash-{first}-{int(time.time())}"
    scan  = store.create_scan(name, req.targets, req.profile)

    background_tasks.add_task(
        _run_scan_pipeline,
        scan["id"],
        req.targets,
        req.profile,
        req.auth,
        req.out_of_scope,
        req.exclusions_text,
    )
    return scan


async def _run_scan_pipeline(
    scan_id: int,
    targets: list,
    profile: str,
    auth: str = "",
    out_of_scope: list = None,
    exclusions_text: str = "",
    resume: bool = False,
):
    """
    Full async scan pipeline — imports and runs the same workflow as qayamat.py
    but inside the running uvicorn process so results share the in-memory store.
    WebSocket broadcasts let the dashboard update in real time.
    """
    out_of_scope = list(out_of_scope or [])
    parsed_exclusions_dict = {}
    parsed_exclusions_obj = None

    if exclusions_text and exclusions_text.strip():
        from core.oos_parser import parse_exclusions_text, ParsedExclusions
        extra_oos, parsed_exclusions_obj = parse_exclusions_text(exclusions_text, in_scope=targets)
        out_of_scope = list(dict.fromkeys(out_of_scope + extra_oos))
        parsed_exclusions_dict = parsed_exclusions_obj.to_dict()
    else:
        from core.oos_parser import ParsedExclusions
        parsed_exclusions_obj = ParsedExclusions()

    async def emit(payload: dict):
        await manager.broadcast({"scan_id": scan_id, **payload})
        # Also push to scan-specific channel
        await manager.send_message(str(scan_id), {"scan_id": scan_id, **payload})

    try:
        from dotenv import load_dotenv
        load_dotenv()

        from config.loader import load_config
        from core.policy_engine import PolicyEngine
        from core.ai_engine import AIEngine
        from core.logger import AuditLogger
        from core.vault import Vault
        from core.scan_control import (
    check_interrupt,
    ScanCancelledError,
    ScanPausedError,
    clear_cancel,
    on_phase_complete,
)
from core.scan_checkpoint import ScanCheckpoint
        from core.finding_validator import FindingValidator
        from core.playwright_scanner import PlaywrightScanner
        from workflows.recon import ReconWorkflow
        from workflows.vuln_scan import VulnScanWorkflow
        from workflows.reporting import ReportGenerator
        from workflows.submission_report import SubmissionReportBuilder

        config = load_config("config/qayamat.yaml")
        clear_cancel(scan_id)

        checkpoint = ScanCheckpoint.load(scan_id) if resume else None
        completed_phases: list = list((checkpoint or {}).get("completed_phases", []))
        recon_results: dict = dict((checkpoint or {}).get("recon_results", {}))

        vault = Vault()
        vault.load_env_secrets()
        logger = AuditLogger()

        if checkpoint and checkpoint.get("scan_config"):
            scan_config = dict(checkpoint["scan_config"])
            scan_config.setdefault("targets", targets)
            scan_config.setdefault("profile", profile)
        else:
            scan_config = {
                "targets":           targets,
                "out_of_scope":      out_of_scope,
                "parsed_exclusions": parsed_exclusions_dict,
                "rules":             "Dashboard launch",
                "profile":           profile,
                "auth":              auth,
            }

        policy = PolicyEngine(config, logger)
        policy.update_scope(scan_config)

        parsed_exclusions = parsed_exclusions_obj
        if not parsed_exclusions:
            from core.oos_parser import ParsedExclusions
            parsed_exclusions = ParsedExclusions()

        ai = AIEngine(config, vault, logger)

        validator = FindingValidator(
            config,
            ai_validate=ai.validate_finding if ai.is_available else None,
        )

        def _save_validated(finding: dict):
            ok, _, updated = validator.validate(finding)
            if ok:
                return store.add_finding(updated, scan_id=scan_id)
            return None

        def _ctx():
            return {
                "scan_config": scan_config,
                "recon_results": recon_results,
                "completed_phases": completed_phases,
            }

        # ── Phase 1: Recon ──────────────────────────────────────────────────
        if ScanCheckpoint.should_run("recon", checkpoint):
            check_interrupt(scan_id, "recon", **_ctx())
            store.update_scan(scan_id, status="running", progress=5.0)
            await emit({"type": "phase", "phase": "Phase 1 — Reconnaissance", "progress": 5, "message": "Starting recon..."})

            recon = ReconWorkflow(config, policy, ai, logger)
            recon_results = await recon.execute()
            completed_phases = on_phase_complete(
                scan_id, "recon", scan_config, recon_results, completed_phases
            )
            checkpoint = ScanCheckpoint.load(scan_id)

        store.update_scan(scan_id, progress=40.0)
        urls  = recon_results.get("urls", [])
        subs  = recon_results.get("subdomains", [])
        await emit({
            "type":     "phase",
            "phase":    "Recon complete",
            "progress": 40,
            "message":  f"Found {len(subs)} subdomains, {len(urls)} URLs",
        })

        # ── Phase 1b: Playwright browser testing ────────────────────────────
        if ScanCheckpoint.should_run("playwright", checkpoint):
            check_interrupt(scan_id, "playwright", **_ctx())
            live_urls = [h.get("url") for h in recon_results.get("live_hosts", []) if h.get("url")]
            pw = PlaywrightScanner()
            if pw.available and live_urls:
                await emit({"type": "phase", "phase": "Playwright Browser Testing", "progress": 42, "message": "Running headless Chromium..."})
                pw_findings = await asyncio.to_thread(pw.scan_urls, live_urls, 8)
                for f in pw_findings:
                    _save_validated(f)
            completed_phases = on_phase_complete(
                scan_id, "playwright", scan_config, recon_results, completed_phases
            )
            checkpoint = ScanCheckpoint.load(scan_id)

        # ── Phase 2: Vuln Scan ──────────────────────────────────────────────
        findings = []
        if ScanCheckpoint.should_run("vuln_scan", checkpoint):
            check_interrupt(scan_id, "vuln scan", **_ctx())
            store.update_scan(scan_id, progress=45.0)
            await emit({"type": "phase", "phase": "Phase 2 — Vulnerability Scanning", "progress": 45, "message": "Running nuclei, dalfox, sqlmap..."})

            vuln = VulnScanWorkflow(config, policy, ai, logger, recon_results)
            findings = await vuln.execute()
            completed_phases = on_phase_complete(
                scan_id, "vuln_scan", scan_config, recon_results, completed_phases
            )
            checkpoint = ScanCheckpoint.load(scan_id)

        store.update_scan(scan_id, progress=85.0)
        await emit({
            "type":     "phase",
            "phase":    "Scan finalising",
            "progress": 85,
            "message":  f"{len(findings)} findings identified",
        })

        # ── Phase 3: API Testing (if URLs present) ──────────────────────────
        api_endpoints = [u for u in urls if any(
            k in u.lower() for k in ["api", "graphql", "/v1/", "/v2/", "/v3/", "rest", "json"]
        )]
        if api_endpoints and profile in ("safe", "balanced", "aggressive", "red_team"):
            try:
                from workflows.api_testing import APITestingWorkflow
                await emit({"type": "phase", "phase": "Phase 3 — API Testing", "progress": 88, "message": f"Testing {len(api_endpoints)} API endpoints..."})
                api_wf = APITestingWorkflow(config, policy, ai, logger)
                api_findings = await api_wf.execute(api_endpoints)
                for f in api_findings:
                    _save_validated(f)
            except Exception:
                pass  # optional phase, don't fail the whole scan

        # ── Phase 3c: Bug Bounty ───────────────────────────────────────────
        if (
            ScanCheckpoint.should_run("bug_bounty", checkpoint)
            and config.get("bugbounty", {}).get("enabled", True)
            and profile in ("safe", "balanced", "aggressive", "red_team")
        ):
            try:
                check_interrupt(scan_id, "bug bounty", **_ctx())
                from workflows.bugbounty import BugBountyWorkflow
                await emit({
                    "type": "phase",
                    "phase": "Phase 3c — Bug Bounty",
                    "progress": 82,
                    "message": "Running CORS, IDOR, OAuth, JS mining...",
                })
                bb_wf = BugBountyWorkflow(
                    config, policy, ai, logger,
                    validator=validator,
                    parsed_exclusions=parsed_exclusions,
                )
                await bb_wf.execute(recon_results, scan_id=scan_id)
                completed_phases = on_phase_complete(
                    scan_id, "bug_bounty", scan_config, recon_results, completed_phases
                )
            except Exception:
                pass

        check_interrupt(scan_id, "reporting", **_ctx())
        all_findings = store.get_findings(scan_id=scan_id)
        reporter = ReportGenerator(all_findings, config, logger)
        reporter.generate(extra={
            "assets": store.get_assets(scan_id=scan_id),
            "events": store.get_events(scan_id=scan_id),
        })
        SubmissionReportBuilder(all_findings).export_all()

        store.update_scan(scan_id, status="complete", progress=100.0)
        ScanCheckpoint.delete(scan_id)
        await emit({
            "type":           "complete",
            "phase":          "Scan complete",
            "progress":       100,
            "message":        f"Scan finished — {len(all_findings)} findings",
            "findings_count": len(all_findings),
        })

    except ScanPausedError:
        await emit({
            "type": "paused",
            "scan_id": scan_id,
            "phase": "Paused",
            "message": "Scan paused — use Resume to continue from last step",
        })
    except ScanCancelledError:
        store.update_scan(scan_id, status="cancelled")
        await emit({
            "type": "cancelled",
            "phase": "Cancelled",
            "progress": 0,
            "message": "Scan cancelled by user",
        })
    except Exception as exc:
        store.update_scan(scan_id, status="error")
        await emit({
            "type":     "error",
            "phase":    "Error",
            "progress": 0,
            "message":  f"Scan failed: {exc}",
        })


# ─── WebSocket endpoints ──────────────────────────────────────────────────────

@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)
    # Send current state immediately on connect
    try:
        scan_id_int = int(scan_id)
        scan = store.get_scan(scan_id_int)
        await websocket.send_json({
            "type":     "init",
            "findings": store.get_findings(scan_id=scan_id_int),
            "assets":   store.get_assets(scan_id=scan_id_int),
            "events":   store.get_events(scan_id=scan_id_int),
            "stats":    store.stats(),
            "scan":     scan,
        })
    except Exception:
        pass

    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect(scan_id)


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """General live feed — receives all broadcast events."""
    await manager.connect("live", websocket)
    try:
        await websocket.send_json({
            "type":   "init",
            "events": store.get_events(limit=50),
            "stats":  store.stats(),
        })
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect("live")
