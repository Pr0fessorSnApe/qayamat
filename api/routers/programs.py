"""Programs, scope import, custom profiles."""

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional
import tempfile
from pathlib import Path

from core.scope_import import ScopeImporter
from core.program_profiles import ProgramProfileLoader
from core.scan_store import store

router = APIRouter()
profiles = ProgramProfileLoader()


class ProgramCreate(BaseModel):
    name: str
    targets: List[str]
    out_of_scope: List[str] = []
    profile: str = "safe"
    nuclei_tags: str = ""
    rate_limit: int = 5


@router.get("/programs")
async def list_programs():
    return {"programs": profiles.list_programs()}


@router.get("/programs/{name}")
async def get_program(name: str):
    data = profiles.load(name)
    if not data:
        raise HTTPException(404, "Program not found")
    return data


@router.post("/programs")
async def create_program(body: ProgramCreate):
    path = profiles.save_program(body.name, body.model_dump())
    return {"saved": path, "program": body.name}


@router.post("/scope/import")
async def import_scope(file: UploadFile = File(...)):
    suffix = Path(file.filename or "scope.json").suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name
    try:
        scope = ScopeImporter.auto_detect(tmp_path)
        profiles.save_program(scope["program"], scope)
        return scope
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.post("/scope/import/path")
async def import_scope_path(path: str):
    if not Path(path).exists():
        raise HTTPException(404, "File not found")
    scope = ScopeImporter.auto_detect(path)
    profiles.save_program(scope["program"], scope)
    return scope
