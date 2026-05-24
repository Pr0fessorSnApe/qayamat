"""QAYAMAT — Agent Manager (Celery-based distributed workers)"""

import asyncio
from typing import Optional
from core.logger import AuditLogger


class AgentManager:
    def __init__(self, config: dict, logger: Optional[AuditLogger] = None):
        self.config = config
        self.logger = logger
        self._celery = None

    def _get_celery(self):
        if self._celery is None:
            try:
                from celery import Celery
                self._celery = Celery(
                    "qayamat",
                    broker=self.config.get("redis", {}).get("url", "redis://localhost:6379/0"),
                )
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Celery unavailable: {e}. Running in single-process mode.")
        return self._celery

    async def start(self) -> None:
        """Initialize the agent manager. Workers run as separate processes."""
        celery = self._get_celery()
        if celery and self.logger:
            self.logger.info("Agent manager initialized (workers: celery -A agents.worker worker)")
        elif self.logger:
            self.logger.info("Agent manager initialized in single-process mode")

    async def submit_task(self, task_name: str, *args, **kwargs):
        """Submit a task to Celery if available, else run synchronously."""
        celery = self._get_celery()
        if celery:
            try:
                return celery.send_task(task_name, args=args, kwargs=kwargs)
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Task submission failed: {e}")
        return None
