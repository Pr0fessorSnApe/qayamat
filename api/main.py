"""QAYAMAT — FastAPI Application"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from api.routers import (
    scans, findings, assets, reports, team, notifications,
    programs, triage, import_export, oob, monitor, nuclei, bugbounty,
)
from api.websocket import manager as ws_manager

app = FastAPI(
    title="QAYAMAT API",
    description="Autonomous AI-Powered Offensive Security OS — REST API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(scans.router, prefix="/api", tags=["scans"])
app.include_router(findings.router, prefix="/api", tags=["findings"])
app.include_router(assets.router, prefix="/api", tags=["assets"])
app.include_router(reports.router, prefix="/api", tags=["reports"])
app.include_router(team.router, prefix="/api", tags=["team"])
app.include_router(notifications.router, prefix="/api", tags=["notifications"])
app.include_router(programs.router, prefix="/api", tags=["programs"])
app.include_router(triage.router, prefix="/api", tags=["triage"])
app.include_router(import_export.router, prefix="/api", tags=["import-export"])
app.include_router(oob.router, prefix="/api", tags=["oob"])
app.include_router(monitor.router, prefix="/api", tags=["monitor"])
app.include_router(nuclei.router, prefix="/api", tags=["nuclei"])
app.include_router(bugbounty.router, prefix="/api", tags=["bugbounty"])

# Serve React frontend if built
frontend_dist = Path("frontend/dist")
if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str = ""):
        index = frontend_dist / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return {"message": "QAYAMAT API running. Frontend not built — run: cd frontend && npm run build"}
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "message": "QAYAMAT API",
            "docs": "/api/docs",
            "note": "Frontend not built. Run: cd frontend && npm install && npm run build",
        }
