"""
core/session_summary.py — Feature 16: Session Summaries

Generates structured metrics and comprehensive Markdown summaries for agent sessions:
- Total actions, risk tier distribution, and approval/rejection outcomes.
- File snapshots and Git backup counts.
- Anomaly detections and circuit breaker trip states.
- Reversibility and average safety score.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from storage.db import _connect


def generate_session_summary(session_id: str) -> Dict[str, Any]:
    """
    Generate an aggregated summary dictionary for a given session_id.
    """
    if not session_id:
        return {"error": "Missing session_id", "session_id": ""}

    with _connect() as conn:
        # 1. Actions query
        cur = conn.execute("""
            SELECT id, timestamp, action_type, command, risk_tier, status,
                   base_tier, effective_tier, preview_hash, backup_hash
            FROM actions
            WHERE session_id = ?
            ORDER BY id ASC
        """, (session_id,))
        actions = cur.fetchall()

        # 2. Session state
        state_row = conn.execute("""
            SELECT state, paused_at, pause_reason
            FROM session_states
            WHERE session_id = ?
        """, (session_id,)).fetchone()

        session_state = state_row[0] if state_row else "active"
        paused_at = state_row[1] if state_row else None
        pause_reason = state_row[2] if state_row else None

        # 3. Action Events / Anomalies
        events_cur = conn.execute("""
            SELECT event_type, timestamp, payload
            FROM action_events
            WHERE session_id = ?
            ORDER BY id ASC
        """, (session_id,))
        events = events_cur.fetchall()

        # 4. Snapshots count
        snap_row = conn.execute("""
            SELECT COUNT(DISTINCT af.id)
            FROM action_files af
            JOIN actions a ON af.action_id = a.id
            WHERE a.session_id = ?
        """, (session_id,)).fetchone()
        snapshots_count = snap_row[0] if snap_row else 0

        # 5. Git backups count
        git_snap_row = conn.execute("""
            SELECT COUNT(*)
            FROM actions
            WHERE session_id = ? AND backup_hash IS NOT NULL AND backup_hash != ''
        """, (session_id,)).fetchone()
        git_backups_count = git_snap_row[0] if git_snap_row else 0

    total_actions = len(actions)
    tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
    status_counts: Dict[str, int] = {}
    timestamps: List[str] = []

    for a in actions:
        eff_tier = a[7] if a[7] and a[7] != "UNKNOWN" else (a[4] or "UNKNOWN")
        tier_counts[eff_tier] = tier_counts.get(eff_tier, 0) + 1

        st = a[5] or "unknown"
        status_counts[st] = status_counts.get(st, 0) + 1

        if a[1]:
            timestamps.append(a[1])

    # Calculate duration if timestamps exist
    started_at = timestamps[0] if timestamps else None
    ended_at = timestamps[-1] if timestamps else None
    duration_seconds = 0.0
    if started_at and ended_at:
        try:
            t0 = datetime.datetime.fromisoformat(started_at)
            t1 = datetime.datetime.fromisoformat(ended_at)
            duration_seconds = max(0.0, (t1 - t0).total_seconds())
        except Exception:
            duration_seconds = 0.0

    # Anomalies
    anomalies = []
    for ev in events:
        ev_type = ev[0]
        if ev_type in ("session_sequence_gap", "session_late_event_recorded") or "circuit" in str(ev[2]).lower():
            anomalies.append({
                "type": ev_type,
                "timestamp": ev[1],
                "payload": ev[2],
            })

    # Overall safety rating
    if tier_counts.get("CRITICAL", 0) > 0 or session_state == "paused":
        overall_rating = "CRITICAL"
    elif tier_counts.get("HIGH", 0) > 0:
        overall_rating = "CAUTION"
    else:
        overall_rating = "SAFE"

    return {
        "session_id": session_id,
        "state": session_state,
        "paused_at": paused_at,
        "pause_reason": pause_reason,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": round(duration_seconds, 2),
        "total_actions": total_actions,
        "tier_breakdown": tier_counts,
        "status_breakdown": status_counts,
        "snapshots_count": snapshots_count,
        "git_backups_count": git_backups_count,
        "anomalies_detected": anomalies,
        "overall_safety_rating": overall_rating,
    }


def format_session_summary_markdown(summary: Dict[str, Any]) -> str:
    """
    Format a session summary dictionary into a clean GitHub-style Markdown report.
    """
    sid = summary.get("session_id", "Unknown")
    state = summary.get("state", "active").upper()
    total = summary.get("total_actions", 0)
    dur = summary.get("duration_seconds", 0.0)
    rating = summary.get("overall_safety_rating", "SAFE")

    tiers = summary.get("tier_breakdown", {})
    statuses = summary.get("status_breakdown", {})
    anomalies = summary.get("anomalies_detected", [])

    lines = [
        f"# Checkpoint Session Summary: `{sid}`",
        f"**Session State:** `{state}` | **Safety Rating:** `{rating}` | **Duration:** {dur:.1f}s",
        "",
        "## Overview",
        f"- **Total Actions Evaluated:** {total}",
        f"- **File Snapshots Created:** {summary.get('snapshots_count', 0)}",
        f"- **Git Safety Backups:** {summary.get('git_backups_count', 0)}",
        "",
        "## Risk Tier Distribution",
        "| Risk Tier | Count |",
        "|---|---|",
        f"| `LOW` (Fast-Path) | {tiers.get('LOW', 0)} |",
        f"| `MEDIUM` (Review) | {tiers.get('MEDIUM', 0)} |",
        f"| `HIGH` (Confirmed) | {tiers.get('HIGH', 0)} |",
        f"| `CRITICAL` (Typed YES) | {tiers.get('CRITICAL', 0)} |",
        "",
        "## Execution Outcomes",
        "| Outcome Status | Count |",
        "|---|---|",
    ]

    for st, count in sorted(statuses.items()):
        lines.append(f"| `{st}` | {count} |")

    lines.append("")
    lines.append("## Anomalies & Safety Events")
    if anomalies:
        for a in anomalies:
            lines.append(f"- **{a['type']}** at `{a['timestamp']}`")
    else:
        lines.append("- No integrity anomalies or sequence gaps detected.")

    if summary.get("pause_reason"):
        lines.append("")
        lines.append(f"> [!WARNING]\n> Session paused on `{summary.get('paused_at')}`: {summary.get('pause_reason')}")

    return "\n".join(lines)
