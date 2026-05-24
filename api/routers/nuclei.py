"""Nuclei template manager API."""

from fastapi import APIRouter
from pydantic import BaseModel
from core.nuclei_manager import NucleiTemplateManager

router = APIRouter()
mgr = NucleiTemplateManager()


class TemplateAction(BaseModel):
    template_id: str


@router.get("/nuclei/templates")
async def list_templates(tag: str = ""):
    return {"templates": mgr.list_templates(tag=tag)}


@router.get("/nuclei/disabled")
async def list_disabled():
    return {"disabled": mgr._disabled}


@router.post("/nuclei/disable")
async def disable_template(body: TemplateAction):
    mgr.disable_template(body.template_id)
    return {"disabled": body.template_id}


@router.post("/nuclei/enable")
async def enable_template(body: TemplateAction):
    mgr.enable_template(body.template_id)
    return {"enabled": body.template_id}


@router.get("/nuclei/recommend-tags")
async def recommend_tags(tech: str = ""):
    tags = mgr.recommend_tags(tech.split(",") if tech else [])
    return {"tags": tags}
