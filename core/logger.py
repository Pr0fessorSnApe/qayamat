"""
QAYAMAT — Audit Logger
JSON-structured, append-only audit log with standard Python logging integration.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    _instances: dict = {}
    _lock = threading.Lock()

    def __init__(self, log_file: str = "data/audit.jsonl"):
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        self.log_file = log_file
        self._write_lock = threading.Lock()

        # Avoid duplicate handlers when re-instantiated
        logger_name = f"qayamat.{log_file}"
        self._logger = logging.getLogger(logger_name)
        if not self._logger.handlers:
            self._logger.setLevel(logging.DEBUG)
            fh = logging.FileHandler("data/qayamat.log")
            fh.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
            # Console handler for INFO+ 
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self._logger.addHandler(fh)
            self._logger.addHandler(ch)
            # Prevent propagation to root logger
            self._logger.propagate = False

    def _write(self, level: str, message: str, **kwargs) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            **kwargs,
        }
        with self._write_lock:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

        log_fn = getattr(self._logger, level.lower(), self._logger.info)
        log_fn(message)

    def info(self, message: str, **kwargs) -> None:
        self._write("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        self._write("WARNING", message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        self._write("ERROR", message, **kwargs)

    def debug(self, message: str, **kwargs) -> None:
        self._write("DEBUG", message, **kwargs)

    def critical(self, message: str, **kwargs) -> None:
        self._write("CRITICAL", message, **kwargs)

    def finding(self, title: str, severity: str, url: str, **kwargs) -> None:
        """Structured log specifically for security findings."""
        self._write(
            "FINDING",
            f"[{severity}] {title} @ {url}",
            title=title,
            severity=severity,
            url=url,
            **kwargs,
        )
