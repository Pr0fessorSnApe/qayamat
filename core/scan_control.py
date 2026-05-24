"""
QAYAMAT — Scan cancellation, pause, and resume control.
"""

import threading
from typing import Optional, Set, Dict, Any

from core.scan_checkpoint import ScanCheckpoint, PHASE_PROGRESS


class ScanCancelledError(Exception):
    """Raised when a scan is cancelled by the user."""


class ScanPausedError(Exception):
    """Raised when a scan is paused — checkpoint saved, safe to resume later."""


_lock = threading.Lock()
_cancelled_ids: Set[int] = set()
_paused_ids: Set[int] = set()
_global_cancel = False


def request_cancel(scan_id: Optional[int] = None) -> None:
    global _global_cancel
    with _lock:
        if scan_id is not None:
            _cancelled_ids.add(int(scan_id))
            _paused_ids.discard(int(scan_id))
        else:
            _global_cancel = True


def request_pause(scan_id: int) -> None:
    with _lock:
        _paused_ids.add(int(scan_id))
        _cancelled_ids.discard(int(scan_id))


def clear_pause(scan_id: Optional[int] = None) -> None:
    with _lock:
        if scan_id is not None:
            _paused_ids.discard(int(scan_id))


def clear_cancel(scan_id: Optional[int] = None) -> None:
    global _global_cancel
    with _lock:
        if scan_id is not None:
            _cancelled_ids.discard(int(scan_id))
        _global_cancel = False


def is_cancelled(scan_id: Optional[int] = None) -> bool:
    with _lock:
        if _global_cancel:
            return True
        if scan_id is not None and int(scan_id) in _cancelled_ids:
            return True
        return False


def is_paused(scan_id: Optional[int] = None) -> bool:
    with _lock:
        if scan_id is not None and int(scan_id) in _paused_ids:
            return True
        return False


def check_cancelled(scan_id: Optional[int] = None, phase: str = "") -> None:
    """Raise ScanCancelledError if cancel was requested."""
    if is_cancelled(scan_id):
        msg = "Scan cancelled" + (f" during {phase}" if phase else "")
        raise ScanCancelledError(msg)


def check_pause(
    scan_id: Optional[int],
    phase: str,
    *,
    scan_config: Optional[dict] = None,
    recon_results: Optional[dict] = None,
    completed_phases: Optional[list] = None,
) -> None:
    """
    If pause requested, persist checkpoint and raise ScanPausedError.
    Call at the start of each pipeline phase.
    """
    if scan_id is None or not is_paused(scan_id):
        return

    from core.scan_store import store

    ckpt = ScanCheckpoint.load(scan_id) or {}
    completed = list(completed_phases or ckpt.get("completed_phases", []))
    ScanCheckpoint.save(
        scan_id,
        next_phase=phase,
        completed_phases=completed,
        scan_config=scan_config or ckpt.get("scan_config", {}),
        recon_results=recon_results or ckpt.get("recon_results"),
    )
    progress = PHASE_PROGRESS.get(phase, ckpt.get("progress", 0))
    store.update_scan(scan_id, status="paused", progress=progress)
    store.add_event(
        f"Scan paused at phase '{phase}' — resume to continue from here",
        event_type="warning",
        scan_id=scan_id,
    )
    clear_pause(scan_id)
    raise ScanPausedError(f"Scan paused during {phase}")


def check_interrupt(
    scan_id: Optional[int],
    phase: str,
    *,
    scan_config: Optional[dict] = None,
    recon_results: Optional[dict] = None,
    completed_phases: Optional[list] = None,
) -> None:
    """Check cancel first, then pause."""
    check_cancelled(scan_id, phase)
    check_pause(
        scan_id,
        phase,
        scan_config=scan_config,
        recon_results=recon_results,
        completed_phases=completed_phases,
    )


def on_phase_complete(
    scan_id: int,
    phase: str,
    scan_config: dict,
    recon_results: Optional[dict] = None,
    completed_phases: Optional[list] = None,
) -> list:
    """Record phase completion in checkpoint; return updated completed list."""
    ckpt = ScanCheckpoint.load(scan_id) or {
        "completed_phases": [],
        "scan_config": scan_config,
        "recon_results": recon_results or {},
    }
    completed = list(completed_phases or ckpt.get("completed_phases", []))
    if phase not in completed:
        completed.append(phase)
    from core.scan_checkpoint import SCAN_PHASES
    idx = SCAN_PHASES.index(phase) if phase in SCAN_PHASES else -1
    next_phase = SCAN_PHASES[idx + 1] if idx + 1 < len(SCAN_PHASES) else "done"
    ScanCheckpoint.save(
        scan_id,
        next_phase=next_phase,
        completed_phases=completed,
        scan_config=scan_config,
        recon_results=recon_results or ckpt.get("recon_results"),
    )
    from core.scan_store import store
    store.update_scan(scan_id, progress=PHASE_PROGRESS.get(phase, 0))
    return completed
