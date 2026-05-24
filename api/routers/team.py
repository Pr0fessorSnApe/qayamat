"""QAYAMAT — Team workspace API."""

from fastapi import APIRouter
from pydantic import BaseModel
from core.team_workspace import TeamWorkspace

router = APIRouter()
workspace = TeamWorkspace()


class MemberCreate(BaseModel):
    name: str
    email: str = ""
    role: str = "hunter"


class InviteRequest(BaseModel):
    email: str
    role: str = "viewer"


@router.post("/team/members")
async def add_member(body: MemberCreate):
    return workspace.add_member(body.name, body.email, body.role)


@router.get("/team/members")
async def list_members():
    return workspace.list_members()


@router.get("/team/assignments")
async def list_assignments(member_id: int = None):
    return workspace.get_assignments(member_id)


@router.get("/team/audit")
async def audit_log(limit: int = 50):
    return workspace.audit_log(limit)


@router.post("/team/invite")
async def invite_member(req: InviteRequest):
    return workspace.add_member(req.email.split("@")[0], req.email, req.role)
