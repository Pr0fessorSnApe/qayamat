"""Continuous monitoring schedules and diff reports."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from core.scan_store import store

router = APIRouter()


class MonitorJobCreate(BaseModel):
    program_name: str
    targets: List[str]
    interval_hours: float = 24
    webhook_url: str = ""


@router.get("/monitor/jobs")
async def list_jobs():
    return store.list_monitor_jobs()


@router.post("/monitor/jobs")
async def create_job(body: MonitorJobCreate):
    return store.add_monitor_job(body.program_name, body.targets, body.interval_hours, body.webhook_url)


@router.get("/monitor/diff/{scan_id}")
async def scan_diff(scan_id: int):
    from workflows.scan_diff import ScanSnapshot, ScanDiff
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    current = {
        "assets": [a["url"] for a in store.get_assets(scan_id=scan_id)],
        "urls": [a["url"] for a in store.get_assets(scan_id=scan_id)],
        "findings_fp": [f.get("fingerprint", f["id"]) for f in store.get_findings(scan_id=scan_id)],
    }
    previous = ScanSnapshot.load_previous(scan_id)
    diff = ScanDiff.compare(current, previous)
    store.update_scan(scan_id, diff_json=__import__("json").dumps(diff))
    return diff
