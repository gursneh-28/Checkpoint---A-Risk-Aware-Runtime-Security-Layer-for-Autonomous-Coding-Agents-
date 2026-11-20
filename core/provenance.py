"""
Provenance tracker for Checkpoint — Feature 10.

Tracks whether untrusted external content was visible in the agent's
context when a tool use was submitted.  Untrusted content can be:
  - Text fetched from the web (curl, wget)
  - Files whose origin is unknown or external
  - User-pasted content marked as untrusted

An untrusted-input signal raises the effective tier (via policy_resolver).
Observed exposure is NOT automatically proof of influence: the signal is
presented to the human reviewer, who decides.

This module never executes commands and never approves actions.
"""
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from core.event_types import ProvenanceSignal, Event


# ---------------------------------------------------------------------------
# Heuristic detectors for untrusted-input sources in Bash commands
# ---------------------------------------------------------------------------

# Commands that commonly fetch remote content
_FETCH_PATTERNS = [
    re.compile(r'\bcurl\b'),
    re.compile(r'\bwget\b'),
    re.compile(r'\bfetch\b'),
    re.compile(r'https?://'),
    re.compile(r'\bpip install\b'),     # may pull untrusted packages
    re.compile(r'\bnpm install\b'),
    re.compile(r'\byarn add\b'),
]

# Patterns suggesting the command was constructed from external data
_DYNAMIC_PATTERNS = [
    re.compile(r'\$\('),     # command substitution
    re.compile(r'`[^`]+`'),  # backtick substitution
    re.compile(r'\beval\b'),
    re.compile(r'\bexec\b.*\$'),
]

# Pipe-into-shell: the downloaded content IS the command
_PIPE_SHELL_RE = re.compile(r'\|\s*(sudo\s+)?(ba|z|da|k)?sh\b', re.IGNORECASE)


def _detect_sources_in_command(command: str) -> List[str]:
    sources = []
    if _PIPE_SHELL_RE.search(command):
        sources.append("pipe-into-shell (command downloads and executes remote code)")
    for p in _FETCH_PATTERNS:
        if p.search(command):
            sources.append(f"remote fetch detected ({p.pattern})")
            break
    for p in _DYNAMIC_PATTERNS:
        if p.search(command) and "pipe-into-shell" not in str(sources):
            sources.append(f"dynamic command construction ({p.pattern})")
            break
    return sources


# ---------------------------------------------------------------------------
# Session provenance accumulator
# ---------------------------------------------------------------------------

@dataclass
class _FetchRecord:
    timestamp: float
    command:   str
    sources:   List[str]


class ProvenanceTracker:
    """
    Maintains a rolling window of recent fetch/external operations per session.
    Consulted by the pipeline when evaluating each new event.
    """

    def __init__(self, window_seconds: int = 300):
        self._window   = window_seconds
        # session_id → deque of recent fetch records
        self._sessions: Dict[str, Deque[_FetchRecord]] = {}

    def _prune(self, session_id: str):
        cutoff = time.time() - self._window
        q = self._sessions.get(session_id, deque())
        while q and q[0].timestamp < cutoff:
            q.popleft()

    def record_event(self, event: Event) -> None:
        """Call this for every event (whether trusted or not)."""
        if not event.command:
            return
        sources = _detect_sources_in_command(event.command)
        if not sources:
            return
        sid = event.session_id
        if sid not in self._sessions:
            self._sessions[sid] = deque()
        self._prune(sid)
        self._sessions[sid].append(_FetchRecord(
            timestamp=event.timestamp,
            command=event.command[:200],
            sources=sources,
        ))

    def get_signal(self, event: Event) -> ProvenanceSignal:
        """
        Returns a ProvenanceSignal for this event.

        The signal is based on:
        1. This event's own command (direct fetch/dynamic construction).
        2. Recent fetch operations in the same session within the window
           (prior context that may have introduced untrusted data).
        """
        all_sources: List[str] = []

        # 1. Direct sources in this event's command
        if event.command:
            direct = _detect_sources_in_command(event.command)
            all_sources.extend(direct)

        # 2. Prior fetches in the session window
        sid = event.session_id
        self._prune(sid)
        for rec in self._sessions.get(sid, deque()):
            for src in rec.sources:
                label = f"prior fetch in session ({src}, cmd: {rec.command[:60]})"
                if label not in all_sources:
                    all_sources.append(label)

        has_untrusted = bool(all_sources)
        reason = ""
        if has_untrusted:
            reason = (
                "Untrusted external content was recently fetched or the command "
                "constructs its arguments dynamically. This is an observed signal, "
                "not proof of influence — the human reviewer decides."
            )

        return ProvenanceSignal(
            has_untrusted_input=has_untrusted,
            sources=all_sources,
            escalation_reason=reason,
        )


# ---------------------------------------------------------------------------
# Module-level singleton (shared across the service lifetime)
# ---------------------------------------------------------------------------

_tracker = ProvenanceTracker()


def record_event(event: Event) -> None:
    _tracker.record_event(event)


def get_signal(event: Event) -> ProvenanceSignal:
    return _tracker.get_signal(event)
