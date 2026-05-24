"""Finding triage workflow API."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from core.scan_store import store
from core.team_workspace import TeamWorkspace

router = APIRouter()
team = TeamWorkspace()

TRIAGE_STATUSES = ("new", "accepted", "false_positive", "duplicate", "reported", "rejected")


class TriageUpdate(BaseModel):
    status: str
    notes: str = ""
    report_id: str = ""


class AssignRequest(BaseModel):
    member_id: int


@router.patch("/findings/{finding_id}/triage")
async def update_triage(finding_id: int, body: TriageUpdate):
    if body.status not in TRIAGE_STATUSES:
        raise HTTPException(400, f"status must be one of {TRIAGE_STATUSES}")
    updated = store.update_finding_triage(finding_id, body.status, body.notes, body.report_id)
    if not updated:
        raise HTTPException(404, "Finding not found")
    return updated


@router.get("/findings/triage/{status}")
async def list_by_triage(status: str, scan_id: Optional[int] = None):
    return store.get_findings_by_triage(status, scan_id=scan_id)


@router.post("/findings/{finding_id}/assign")
async def assign_finding(finding_id: int, body: AssignRequest):
    active = store.get_active_scan()
    scan_id = active["id"] if active else None
    return team.assign_finding(finding_id, body.member_id, scan_id)
