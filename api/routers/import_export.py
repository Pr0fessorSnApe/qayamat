"""Burp / HAR / ZAP import and export."""

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional
import tempfile
from pathlib import Path

from core.burp_import import TrafficImporter, BurpExporter
from core.scan_store import store

router = APIRouter()


class ImportPathRequest(BaseModel):
    path: str


@router.post("/import/traffic")
async def import_traffic(file: UploadFile = File(...)):
    suffix = Path(file.filename or "traffic.har").suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name
    try:
        data = TrafficImporter.auto_import(tmp_path)
        active = store.get_active_scan()
        scan_id = active["id"] if active else None
        for url in data.get("urls", []):
            store.add_asset({"url": url, "asset_type": "imported", "status": "discovered"}, scan_id=scan_id)
        return {"imported_urls": len(data.get("urls", [])), **data}
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.post("/export/burp")
async def export_burp(scan_id: Optional[int] = None):
    findings = store.get_findings(scan_id=scan_id)
    path = BurpExporter.export_findings(findings, "reports/burp_export.json")
    return {"path": path, "count": len(findings)}


@router.get("/export/submissions")
async def export_submissions(platform: str = "hackerone", scan_id: Optional[int] = None):
    from workflows.submission_report import SubmissionReportBuilder
    findings = store.get_findings(scan_id=scan_id)
    paths = SubmissionReportBuilder(findings).export_all(platform=platform)
    return {"files": paths, "count": len(paths)}
