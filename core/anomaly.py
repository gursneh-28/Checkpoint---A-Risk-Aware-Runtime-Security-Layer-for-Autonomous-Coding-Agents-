"""
Anomaly detector for Checkpoint — Feature 11.

Rule-based anomaly detection.  Recognized patterns:
  - burst:              > N high-risk commands within T seconds in a session
  - repeated_rejection: same command hash rejected > N times in a session
  - out_of_scope:       action targets a path outside the registered project root
  - unusual_time:       action at an unusual hour (configurable)

A triggered anomaly escalates the effective tier (via policy_resolver).
Repeated attempts at rejected commands are also logged here, satisfying the
"rejection feedback tracking" requirement from Feature 4.

This module never executes commands and never approves actions.
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

from core.event_types import AnomalySignal, Event, RiskTier
from core.path_module import is_inside_project


# ---------------------------------------------------------------------------
# Configurable thresholds
# ---------------------------------------------------------------------------

BURST_WINDOW_SECONDS    = 60      # rolling window for burst detection
BURST_THRESHOLD         = 5       # > N high/critical events in window → anomaly
REJECTION_THRESHOLD     = 3       # same command rejected > N times → anomaly
UNUSUAL_HOUR_START      = 0       # 00:00 (midnight)
UNUSUAL_HOUR_END        = 5       # 05:00
REJECTION_WINDOW_SECONDS = 3600   # track repeated rejections for 1 hour


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

@dataclass
class _SessionState:
    # Burst: timestamps of HIGH/CRITICAL events
    high_risk_times: Deque[float] = field(default_factory=deque)
    # Repeated rejection: command_hash → list of rejection timestamps
    rejection_times: Dict[str, Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )


class AnomalyDetector:
    """Per-service singleton; call record_event AFTER every decision."""

    def __init__(self):
        self._sessions: Dict[str, _SessionState] = {}
        self._project_root: str = ""   # set by the service at startup

    def set_project_root(self, root: str):
        self._project_root = root

    def _state(self, session_id: str) -> _SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionState()
        return self._sessions[session_id]

    def _prune_burst(self, state: _SessionState):
        cutoff = time.time() - BURST_WINDOW_SECONDS
        while state.high_risk_times and state.high_risk_times[0] < cutoff:
            state.high_risk_times.popleft()

    def _prune_rejections(self, state: _SessionState):
        cutoff = time.time() - REJECTION_WINDOW_SECONDS
        for q in state.rejection_times.values():
            while q and q[0] < cutoff:
                q.popleft()

    def record_high_risk(self, session_id: str):
        """Call after classifying an event as HIGH or CRITICAL."""
        s = self._state(session_id)
        s.high_risk_times.append(time.time())

    def record_rejection(self, session_id: str, command: str):
        """Call after a command is rejected by the user."""
        s = self._state(session_id)
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:12]
        s.rejection_times[cmd_hash].append(time.time())

    def get_signal(self, event: Event, effective_tier: RiskTier) -> AnomalySignal:
        """
        Compute an anomaly signal for the current event.
        Called BEFORE recording (so we detect the anomaly on this event).
        """
        sid = event.session_id
        s   = self._state(sid)
        self._prune_burst(s)
        self._prune_rejections(s)

        # 1. Burst detection
        if effective_tier in (RiskTier.HIGH, RiskTier.CRITICAL):
            count = len(s.high_risk_times) + 1  # +1 for the current event
            if count > BURST_THRESHOLD:
                return AnomalySignal(
                    triggered=True,
                    kind="burst",
                    detail=(
                        f"{count} high-risk commands in {BURST_WINDOW_SECONDS}s "
                        f"in session {sid[:8]}..."
                    ),
                    escalation_reason=(
                        f"Burst of high-risk commands detected ({count} in "
                        f"{BURST_WINDOW_SECONDS}s). Escalating to CRITICAL for review."
                    ),
                )

        # 2. Repeated rejection
        if event.command:
            cmd_hash = hashlib.sha256(event.command.encode()).hexdigest()[:12]
            reject_count = len(s.rejection_times.get(cmd_hash, deque()))
            if reject_count >= REJECTION_THRESHOLD:
                return AnomalySignal(
                    triggered=True,
                    kind="repeated_rejection",
                    detail=(
                        f"Same command rejected {reject_count} times "
                        f"in the past {REJECTION_WINDOW_SECONDS // 60} minutes"
                    ),
                    escalation_reason=(
                        "Agent is retrying a previously rejected command. "
                        "Escalating for human review."
                    ),
                )

        # 3. Out-of-scope
        if self._project_root and event.cwd:
            if not is_inside_project(event.cwd, self._project_root):
                return AnomalySignal(
                    triggered=True,
                    kind="out_of_scope",
                    detail=f"Working directory {event.cwd!r} is outside project root",
                    escalation_reason=(
                        "Action is outside the registered project root. "
                        "Escalating for human review."
                    ),
                )

        # 4. Unusual time (disabled in base limits-only mode unless explicitly enabled)
        # Note: Section 11 of spec specifies: "Unattended activity, as an explicit policy... Banner only by default"
        # Hardcoded escalation based merely on local clock hour without policy configuration is not compliant with 11a.
        if getattr(self, "_check_unusual_time", False):
            hour = datetime.now().hour
            if UNUSUAL_HOUR_START <= hour < UNUSUAL_HOUR_END:
                return AnomalySignal(
                    triggered=True,
                    kind="unusual_time",
                    detail=f"Action at {hour:02d}:00 (outside expected hours)",
                    escalation_reason=(
                        f"Action submitted at an unusual hour ({hour:02d}:xx). "
                        "Consider reviewing manually."
                    ),
                )

        return AnomalySignal(triggered=False)

    def post_decision(self, event: Event, effective_tier: RiskTier, rejected: bool):
        """Update state after a decision is made."""
        sid = event.session_id
        if effective_tier in (RiskTier.HIGH, RiskTier.CRITICAL):
            self.record_high_risk(sid)
        if rejected and event.command:
            self.record_rejection(sid, event.command)

    def check_circuit_breaker(self, session_id: str, quota_headroom_pct: float = 100.0) -> Tuple[bool, str]:
        """
        Check if any circuit-breaker threshold is tripped for this session:
        - Burst > BURST_THRESHOLD (5 high risk in 60s)
        - Repeated rejection >= REJECTION_THRESHOLD (3 rejections)
        - Quota headroom < 5%
        Returns (should_pause, reason).
        """
        s = self._state(session_id)
        self._prune_burst(s)
        self._prune_rejections(s)

        if len(s.high_risk_times) >= BURST_THRESHOLD:
            return True, f"Circuit breaker tripped: high-risk burst threshold exceeded ({len(s.high_risk_times)} in {BURST_WINDOW_SECONDS}s)"

        for cmd_hash, q in s.rejection_times.items():
            if len(q) >= REJECTION_THRESHOLD:
                return True, f"Circuit breaker tripped: repeated retry of rejected command (rejected {len(q)} times)"

        if quota_headroom_pct < 5.0:
            return True, f"Circuit breaker tripped: shared quota headroom critically low ({quota_headroom_pct:.1f}% remaining < 5%)"

        return False, ""


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_detector = AnomalyDetector()


def set_project_root(root: str):
    _detector.set_project_root(root)


def get_signal(event: Event, effective_tier: RiskTier) -> AnomalySignal:
    return _detector.get_signal(event, effective_tier)


def post_decision(event: Event, effective_tier: RiskTier, rejected: bool):
    _detector.post_decision(event, effective_tier, rejected)


def check_circuit_breaker(session_id: str, quota_headroom_pct: float = 100.0) -> Tuple[bool, str]:
    return _detector.check_circuit_breaker(session_id, quota_headroom_pct)
