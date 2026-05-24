"""QAYAMAT — Celery Distributed Workers"""

import os
from celery import Celery
from celery.utils.log import get_task_logger

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "qayamat",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

logger = get_task_logger(__name__)


@app.task(bind=True, name="qayamat.run_tool")
def run_tool(self, tool_name: str, args: list, target: str = None):
    """Run a security tool as a Celery task."""
    import subprocess, shutil
    logger.info(f"Running tool: {tool_name} args={args}")
    binary = shutil.which(tool_name) or f"/opt/qayamat/tools/{tool_name}"
    try:
        result = subprocess.run(
            [binary] + args,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        logger.error(f"Tool {tool_name} failed: {e}")
        raise self.retry(exc=e, countdown=5, max_retries=2)


@app.task(name="qayamat.scan_target")
def scan_target(target: str, profile: str = "safe"):
    """Full scan pipeline for a single target."""
    logger.info(f"Scanning target: {target} profile={profile}")
    results = {"target": target, "profile": profile, "subdomains": [], "findings": []}
    return results


@app.task(name="qayamat.send_notification")
def send_notification(finding: dict, webhook_url: str = ""):
    """Send a Slack/webhook notification for a new finding."""
    import requests
    if not webhook_url:
        webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return {"sent": False, "reason": "no webhook configured"}
    sev = finding.get("severity", "Unknown")
    title = finding.get("title", "Finding")
    url = finding.get("url", "")
    msg = f"[{sev}] {title}\n{url}"
    try:
        resp = requests.post(webhook_url, json={"text": msg}, timeout=10)
        return {"sent": True, "status_code": resp.status_code}
    except Exception as e:
        return {"sent": False, "error": str(e)}
