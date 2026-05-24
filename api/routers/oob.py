"""OOB callback server API."""

from fastapi import APIRouter
from pydantic import BaseModel
from core.oob_server import OOBServer
from core.scan_store import store

router = APIRouter()
_oob: OOBServer = None


def _get_oob() -> OOBServer:
    global _oob
    if _oob is None:
        _oob = OOBServer()
        _oob.register()
    return _oob


@router.get("/oob/status")
async def oob_status():
    oob = _get_oob()
    return {
        "callback_host": oob.callback_host,
        "correlation_id": oob.correlation_id,
        "server": oob.server,
    }


@router.get("/oob/payload")
async def oob_payload(tag: str = "xss"):
    return {"payload_url": _get_oob().payload_url(tag)}


@router.post("/oob/poll")
async def oob_poll():
    oob = _get_oob()
    hits = oob.poll_interactions()
    active = store.get_active_scan()
    scan_id = active["id"] if active else None
    findings = oob.correlate_findings(scan_id or 0, store)
    saved = []
    for f in findings:
        saved.append(store.add_finding(f, scan_id=scan_id))
    return {"interactions": hits, "findings_created": len(saved)}
