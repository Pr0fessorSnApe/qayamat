"""QAYAMAT — Reports Router"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path

router = APIRouter()


@router.get("/reports/latest/json")
async def download_json_report():
    path = Path("reports/report.json")
    if not path.exists():
        raise HTTPException(status_code=404, detail="No report available yet. Run a scan first.")
    return FileResponse(str(path), media_type="application/json", filename="qayamat_report.json")


@router.get("/reports/latest/html")
async def download_html_report():
    path = Path("reports/report.html")
    if not path.exists():
        raise HTTPException(status_code=404, detail="No report available yet. Run a scan first.")
    return FileResponse(str(path), media_type="text/html", filename="qayamat_report.html")


@router.get("/reports/list")
async def list_reports():
    reports_dir = Path("reports")
    if not reports_dir.exists():
        return []
    return [f.name for f in sorted(reports_dir.iterdir()) if f.is_file()]
