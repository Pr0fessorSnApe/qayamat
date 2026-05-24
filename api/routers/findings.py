"""QAYAMAT — Findings Router (reads from real ScanStore)"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from core.scan_store import store

router = APIRouter()


class FindingCreate(BaseModel):
    title: str
    url: str
    severity: str
    description: str
    vuln_type: Optional[str] = None
    evidence: Optional[str] = None
    tool: Optional[str] = None
    template: Optional[str] = None


class FindingOut(BaseModel):
    id: int
    scan_id: Optional[int]
    title: str
    url: str
    severity: str
    description: str
    vuln_type: Optional[str]
    evidence: Optional[str]
    template: Optional[str]
    tool: Optional[str]
    tags: Optional[List[str]] = []
    cve: Optional[List[str]] = []
    cvss: Optional[str]
    fingerprint: Optional[str] = ""
    triage_status: Optional[str] = "new"
    triage_notes: Optional[str] = ""
    report_id: Optional[str] = ""
    affected_urls: Optional[List[str]] = []
    program_name: Optional[str] = ""
    created_at: str


@router.get("/findings", response_model=List[FindingOut])
async def list_findings(severity: Optional[str] = None, scan_id: Optional[int] = None):
    return store.get_findings(severity=severity, scan_id=scan_id)


@router.post("/findings", response_model=FindingOut)
async def create_finding(finding: FindingCreate):
    active = store.get_active_scan()
    scan_id = active["id"] if active else None
    return store.add_finding(finding.model_dump(), scan_id=scan_id)


@router.get("/findings/stats/summary")
async def findings_summary():
    return store.findings_summary()


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: int):
    for f in store.get_findings():
        if f["id"] == finding_id:
            return f
    raise HTTPException(status_code=404, detail="Finding not found")


@router.delete("/findings/{finding_id}")
async def delete_finding(finding_id: int):
    if not store.delete_finding(finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"deleted": True}
