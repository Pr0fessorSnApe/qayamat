"""Bug bounty features API — exclusions, submit, CVSS/bounty estimate, nuclei gen."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from core.oos_parser import parse_exclusions_text
from core.bugbounty import scanners
from core.bugbounty.submission_api import (
    submit_finding,
    submission_status,
    PlatformSubmissionError,
)
from core.bugbounty.bounty_estimator import estimate_bounty, estimate_scan_portfolio
from core.bugbounty.nuclei_template_gen import generate_from_scan
from core.program_profiles import ProgramProfileLoader
from core.scan_store import store

router = APIRouter()


class ExclusionsParseRequest(BaseModel):
    text: str
    in_scope: List[str] = []


class ExclusionsParseResponse(BaseModel):
    out_of_scope: List[str]
    parsed: dict
    summary: str


class PolicyParseRequest(BaseModel):
    rules_text: str


class BountyEntryRequest(BaseModel):
    program: str
    status: str
    amount: float = 0


class SubmitFindingRequest(BaseModel):
    platform: str  # hackerone | bugcrowd
    program_ref: str  # team_handle or program code
    dry_run: bool = False


class GenerateNucleiRequest(BaseModel):
    scan_id: Optional[int] = None
    program: str = ""


@router.post("/bugbounty/parse-exclusions", response_model=ExclusionsParseResponse)
async def parse_exclusions(req: ExclusionsParseRequest):
    if not req.text.strip():
        raise HTTPException(400, "Exclusion text is required")
    oos_list, parsed = parse_exclusions_text(req.text, in_scope=req.in_scope)
    summary_parts = [
        f"{len(parsed.domains)} domains",
        f"{len(parsed.wildcards)} wildcards",
        f"{len(parsed.paths)} paths",
        f"{len(parsed.excluded_vuln_types)} vuln type rules",
    ]
    if parsed.no_automated_scanning:
        summary_parts.append("no automated scanning")
    return ExclusionsParseResponse(
        out_of_scope=oos_list,
        parsed=parsed.to_dict(),
        summary="Parsed: " + ", ".join(summary_parts),
    )


@router.post("/bugbounty/parse-policy")
async def parse_policy(req: PolicyParseRequest):
    return scanners.parse_program_policy(req.rules_text)


@router.get("/bugbounty/tracker")
async def get_bounty_tracker():
    return scanners.load_bounty_tracker()


@router.post("/bugbounty/tracker")
async def update_bounty_tracker(req: BountyEntryRequest):
    if req.status not in ("submitted", "accepted", "paid"):
        raise HTTPException(400, "status must be submitted, accepted, or paid")
    return scanners.save_bounty_entry(req.program, req.status, req.amount)


@router.get("/bugbounty/scope-drift/{program_name}")
async def scope_drift(program_name: str):
    loader = ProgramProfileLoader()
    prog = loader.load(program_name)
    targets = prog.get("targets", [])
    return scanners.check_scope_drift(program_name, targets)


@router.get("/bugbounty/submission/status")
async def api_submission_status():
    return submission_status()


@router.post("/findings/{finding_id}/submit")
async def submit_finding_to_platform(finding_id: int, req: SubmitFindingRequest):
    """One-click submit to HackerOne or Bugcrowd (requires API tokens in .env)."""
    findings = store.get_findings()
    f = next((x for x in findings if x.get("id") == finding_id), None)
    if not f:
        raise HTTPException(404, "Finding not found")
    if f.get("triage_status") in ("false_positive", "duplicate", "rejected"):
        raise HTTPException(400, "Finding triage status blocks submission")
    try:
        result = submit_finding(
            f,
            platform=req.platform,
            program_ref=req.program_ref,
            dry_run=req.dry_run,
        )
        if not req.dry_run:
            store.update_finding_triage(
                finding_id,
                "reported",
                notes=f"Submitted via {req.platform}",
                report_id=str(result.get("report_id") or result.get("submission_id", "")),
            )
        return result
    except PlatformSubmissionError as e:
        raise HTTPException(400, str(e))


@router.get("/findings/{finding_id}/bounty-estimate")
async def finding_bounty_estimate(finding_id: int, program: str = ""):
    findings = store.get_findings()
    f = next((x for x in findings if x.get("id") == finding_id), None)
    if not f:
        raise HTTPException(404, "Finding not found")
    return estimate_bounty(f, program)


@router.get("/scans/{scan_id}/bounty-portfolio")
async def scan_bounty_portfolio(scan_id: int, program: str = ""):
    findings = store.get_findings(scan_id=scan_id)
    return estimate_scan_portfolio(findings, program)


@router.post("/bugbounty/generate-nuclei")
async def generate_nuclei_templates(req: GenerateNucleiRequest):
    findings = store.get_findings(scan_id=req.scan_id) if req.scan_id else store.get_findings()
    return generate_from_scan(findings, program=req.program)


@router.post("/findings/{finding_id}/report-score")
async def score_finding_report(finding_id: int):
    findings = store.get_findings()
    f = next((x for x in findings if x.get("id") == finding_id), None)
    if not f:
        raise HTTPException(404, "Finding not found")
    return scanners.score_report_quality(dict(f))


@router.get("/bugbounty/features")
async def list_features():
    return {
        "features": [
            "intelligent_exclusions_parser",
            "ct_monitor",
            "asset_priority_scorer",
            "js_bundle_miner",
            "ghost_endpoints",
            "openapi_discovery",
            "idor_bola_tester",
            "oauth_oidc_tester",
            "cors_hunter",
            "ssrf_verifier",
            "host_header_tester",
            "waf_detector",
            "ssti_auto_verify",
            "http_smuggling_hunter",
            "cache_poison_hunter",
            "race_condition_tester",
            "platform_api_submit",
            "cvss_bounty_estimator",
            "ai_nuclei_template_generator",
            "attack_chain_builder",
            "pause_resume_scan",
        ]
    }
