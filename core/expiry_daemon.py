"""
core/expiry_daemon.py — Server-side background worker for authoritative approval expiry.

Periodically sweeps pending actions and expires any that exceed the 300-second window.
Ensures restart safety: sweeps immediately upon initialization/startup so pending
actions from prior sessions/crashes are cleanly expired without retroactive approval risk.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import List, Optional

from storage.db import expire_stale_actions, APPROVAL_TIMEOUT_SECONDS

logger = logging.getLogger("checkpoint.expiry")


class ApprovalExpiryWorker:
    """
    Background worker daemon that authoritatively expires stale approvals.
    """

    def __init__(
        self,
        interval_seconds: float = 2.0,
        timeout_seconds: float = APPROVAL_TIMEOUT_SECONDS,
    ):
        self.interval = interval_seconds
        self.timeout = timeout_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self, initial_sweep: bool = True) -> None:
        """Start the background worker thread. Performs an initial sweep by default."""
        if self._thread and self._thread.is_alive():
            return

        if initial_sweep:
            try:
                self.sweep_once()
            except Exception as e:
                logger.warning("Initial expiry sweep error: %s", e)

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="ApprovalExpiryWorker",
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the background worker thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def sweep_once(self) -> List[int]:
        """Run a single expiry sweep and return expired action IDs."""
        return expire_stale_actions(self.timeout)

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval):
            try:
                self.sweep_once()
            except Exception as e:
                logger.warning("Approval expiry worker sweep error: %s", e)


_global_worker: Optional[ApprovalExpiryWorker] = None
_worker_lock = threading.Lock()


def get_expiry_worker(
    interval_seconds: float = 2.0,
    timeout_seconds: float = APPROVAL_TIMEOUT_SECONDS,
) -> ApprovalExpiryWorker:
    global _global_worker
    with _worker_lock:
        if _global_worker is None:
            _global_worker = ApprovalExpiryWorker(
                interval_seconds=interval_seconds,
                timeout_seconds=timeout_seconds,
            )
        return _global_worker


def start_expiry_worker(
    interval_seconds: float = 2.0,
    timeout_seconds: float = APPROVAL_TIMEOUT_SECONDS,
    initial_sweep: bool = True,
) -> ApprovalExpiryWorker:
    worker = get_expiry_worker(interval_seconds, timeout_seconds)
    worker.start(initial_sweep=initial_sweep)
    return worker


def stop_expiry_worker(timeout: float = 5.0) -> None:
    global _global_worker
    with _worker_lock:
        if _global_worker:
            _global_worker.stop(timeout=timeout)
            _global_worker = None
