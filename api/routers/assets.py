"""QAYAMAT — Assets Router (reads from real ScanStore)"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from core.scan_store import store

router = APIRouter()


class AssetCreate(BaseModel):
    url: str
    asset_type: str
    status: Optional[str] = "active"
    technologies: Optional[List[str]] = []
    open_ports: Optional[List[int]] = []


class AssetOut(BaseModel):
    id: int
    scan_id: Optional[int]
    url: str
    asset_type: str
    status: str
    technologies: List[str]
    open_ports: Optional[List[int]] = []
    created_at: Optional[str]


@router.get("/assets", response_model=List[AssetOut])
async def list_assets(asset_type: Optional[str] = None, scan_id: Optional[int] = None):
    return store.get_assets(asset_type=asset_type, scan_id=scan_id)


@router.post("/assets", response_model=AssetOut)
async def create_asset(asset: AssetCreate):
    active = store.get_active_scan()
    scan_id = active["id"] if active else None
    result = store.add_asset(asset.model_dump(), scan_id=scan_id)
    if not result:
        raise HTTPException(status_code=400, detail="Asset URL is required")
    return result


@router.get("/assets/stats/summary")
async def assets_summary():
    return store.assets_summary()


@router.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: int):
    for a in store.get_assets():
        if a["id"] == asset_id:
            return a
    raise HTTPException(status_code=404, detail="Asset not found")
