"""
Checkpoint storage — Feature 8: Full action log.

Tables:
  actions       — current state (searchable, rebuilt from events)
  action_events — append-only event log with SHA-256 hash chain
  action_files  — before/after snapshots per path per action
  flag_events   — wrong-rating feedback queue (Feature 14)
  alerts        — pending approval alerts (Feature 15)

Event types:
  requested, classified, preview_generated, approval_requested,
  decision_recorded, alternative_selected, backup_started,
  backup_completed, backup_failed, execution_authorized,
  execution_started, execution_completed, execution_failed,
  outcome_unknown, flagged

Design doc rules:
  - Record FIRST, then answer.
  - If the journal write fails, the action is blocked.
  - action_events is the audit authority.
  - Duplicate tool_use_id within a session → idempotent (no duplicate record).
  - Nobody queries tables directly; writes go through this module.
  - Output: 1 MB cap, stored redacted, secrets scrubbed.
  - Retention: 30-day unpinned snapshots; 365-day metadata default.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(__file__), "checkpoint.db")

VALID_DECISIONS = ("approved", "rejected", "alternative")
OUTPUT_MAX_BYTES = 1 * 1024 * 1024   # 1 MB


# ---------------------------------------------------------------------------
# Secret scrubbing (before any write)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    re.compile(r'(password|passwd|secret|token|api[_-]?key|private[_-]?key'
               r'|access[_-]?key|auth[_-]?token)\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),  # long base64-like strings
]


def _scrub_secrets(text: str) -> str:
    """Replace apparent secrets with <REDACTED>."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + "<REDACTED>", text)
    return text


def _truncate_output(text: str) -> str:
    if not text:
        return ""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= OUTPUT_MAX_BYTES:
        return text
    half = OUTPUT_MAX_BYTES // 2
    head = encoded[:half].decode("utf-8", errors="replace")
    tail = encoded[-half:].decode("utf-8", errors="replace")
    return head + "\n\n... [truncated] ...\n\n" + tail


# ---------------------------------------------------------------------------
# DB connection helpers
# ---------------------------------------------------------------------------

@contextmanager
def _connect() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, timeout=10,
                           isolation_level=None)   # autocommit; we manage transactions
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def init_db():
    with _connect() as conn:
        conn.executescript("""
        BEGIN;

        CREATE TABLE IF NOT EXISTS actions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            action_type     TEXT NOT NULL,
            command         TEXT NOT NULL,
            risk_tier       TEXT NOT NULL,
            status          TEXT NOT NULL,
            output          TEXT,
            suggestion      TEXT,
            tool_use_id     TEXT,
            session_id      TEXT,
            base_tier       TEXT NOT NULL DEFAULT 'UNKNOWN',
            effective_tier  TEXT NOT NULL DEFAULT 'UNKNOWN',
            preview_hash    TEXT,
            manifest_hash   TEXT,
            backup_hash     TEXT,
            policy_version  TEXT DEFAULT '1',
            cwd             TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS action_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id   INTEGER NOT NULL REFERENCES actions(id),
            event_type  TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            payload     TEXT,
            prev_hash   TEXT NOT NULL DEFAULT '',
            event_hash  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS action_files (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id       INTEGER NOT NULL REFERENCES actions(id),
            file_path       TEXT NOT NULL,
            before_blob_id  TEXT,
            after_blob_id   TEXT,
            coverage        TEXT DEFAULT 'unknown'
        );

        CREATE TABLE IF NOT EXISTS checkpoints (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT NOT NULL,
            file_path     TEXT NOT NULL,
            snapshot_path TEXT NOT NULL,
            description   TEXT
        );

        CREATE TABLE IF NOT EXISTS flag_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id   INTEGER NOT NULL REFERENCES actions(id),
            timestamp   TEXT NOT NULL,
            reason      TEXT NOT NULL,
            correct_tier TEXT,
            notes       TEXT,
            reviewed    INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id   INTEGER NOT NULL REFERENCES actions(id),
            timestamp   TEXT NOT NULL,
            kind        TEXT NOT NULL,
            delivered   INTEGER DEFAULT 0
        );

        COMMIT;
        """)

    # Upgrade old databases
    _upgrade_schema()


def _upgrade_schema():
    """Add missing columns to existing databases."""
    new_cols = {
        "actions": [
            ("risk_tier",      "TEXT DEFAULT 'UNKNOWN'"),
            ("suggestion",     "TEXT"),
            ("tool_use_id",    "TEXT"),
            ("session_id",     "TEXT"),
            ("base_tier",      "TEXT DEFAULT 'UNKNOWN'"),
            ("effective_tier", "TEXT DEFAULT 'UNKNOWN'"),
            ("preview_hash",   "TEXT"),
            ("manifest_hash",  "TEXT"),
            ("backup_hash",    "TEXT"),
            ("policy_version", "TEXT DEFAULT '1'"),
            ("cwd",            "TEXT DEFAULT ''"),
        ]
    }
    with _connect() as conn:
        for table, cols in new_cols.items():
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for col_name, col_type in cols:
                if col_name not in existing:
                    try:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                    except sqlite3.OperationalError:
                        pass


# ---------------------------------------------------------------------------
# Hash chain helpers
# ---------------------------------------------------------------------------

def _compute_event_hash(action_id: int, event_type: str, timestamp: str,
                        payload: str, prev_hash: str) -> str:
    blob = json.dumps({
        "action_id":  action_id,
        "event_type": event_type,
        "timestamp":  timestamp,
        "payload":    payload,
        "prev_hash":  prev_hash,
    }, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _last_event_hash(conn: sqlite3.Connection, action_id: int) -> str:
    row = conn.execute(
        "SELECT event_hash FROM action_events WHERE action_id=? ORDER BY id DESC LIMIT 1",
        (action_id,)
    ).fetchone()
    return row[0] if row else ""


def _append_event(conn: sqlite3.Connection, action_id: int,
                  event_type: str, payload: Dict[str, Any] = None) -> str:
    """Append an event to the hash chain.  Returns the new event hash."""
    ts       = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload_str = json.dumps(payload or {})
    prev    = _last_event_hash(conn, action_id)
    ev_hash = _compute_event_hash(action_id, event_type, ts, payload_str, prev)
    conn.execute("""
        INSERT INTO action_events (action_id, event_type, timestamp, payload, prev_hash, event_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (action_id, event_type, ts, payload_str, prev, ev_hash))
    return ev_hash


# ---------------------------------------------------------------------------
# Write API
# ---------------------------------------------------------------------------

def log_action(action_type: str, command: str, risk_tier: str, status: str,
               output: str = "", session_id: str = "", cwd: str = "") -> int:
    """Log a completed LOW-tier action (auto-executed)."""
    command = _scrub_secrets(command)
    output  = _scrub_secrets(_truncate_output(output))
    ts      = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("BEGIN")
        cur = conn.execute("""
            INSERT INTO actions
              (timestamp, action_type, command, risk_tier, status, output,
               base_tier, effective_tier, session_id, cwd)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, action_type, command, risk_tier, status, output,
               risk_tier, risk_tier, session_id, cwd))
        action_id = cur.lastrowid
        _append_event(conn, action_id, "requested",   {"command": command[:200]})
        _append_event(conn, action_id, "classified",  {"tier": risk_tier})
        _append_event(conn, action_id, event_type_for_status(status))
        conn.execute("COMMIT")
    return action_id


def event_type_for_status(status: str) -> str:
    return {
        "executed":             "execution_completed",
        "executed-alternative": "execution_completed",
        "rejected":             "rejected",
        "failed":               "execution_failed",
        "outcome_unknown":      "outcome_unknown",
        "pending":              "approval_requested",
        "approved":             "decision_recorded",
        "stale":                "rejected",
    }.get(status, "execution_completed")


def log_pending_action(action_type: str, command: str, risk_tier: str,
                       suggestion: dict = None, effective_tier: str = None,
                       preview_hash: str = "", manifest_hash: str = "",
                       backup_hash: str = "", session_id: str = "",
                       tool_use_id: str = "", cwd: str = "") -> int:
    """
    Idempotently log a MEDIUM/HIGH action as 'pending'.
    Returns the action_id.  If tool_use_id already exists in this session,
    returns the existing action_id without creating a duplicate.
    """
    command  = _scrub_secrets(command)
    sugg_json = json.dumps(suggestion) if suggestion else None
    eff       = effective_tier or risk_tier
    ts        = datetime.datetime.now(datetime.timezone.utc).isoformat()

    with _connect() as conn:
        # Idempotency: check for existing tool_use_id
        if tool_use_id and session_id:
            existing = conn.execute(
                "SELECT id FROM actions WHERE tool_use_id=? AND session_id=? LIMIT 1",
                (tool_use_id, session_id)
            ).fetchone()
            if existing:
                return existing[0]

        conn.execute("BEGIN")
        cur = conn.execute("""
            INSERT INTO actions
              (timestamp, action_type, command, risk_tier, status, output,
               suggestion, base_tier, effective_tier, preview_hash, manifest_hash, backup_hash,
               session_id, tool_use_id, cwd)
            VALUES (?, ?, ?, ?, 'pending', '', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, action_type, command, risk_tier, sugg_json,
              risk_tier, eff, preview_hash, manifest_hash, backup_hash, session_id, tool_use_id, cwd))
        action_id = cur.lastrowid
        _append_event(conn, action_id, "requested",   {"command": command[:200], "cwd": cwd})
        _append_event(conn, action_id, "classified",  {"base": risk_tier, "effective": eff})
        _append_event(conn, action_id, "preview_generated", {"preview_hash": preview_hash})
        _append_event(conn, action_id, "approval_requested")
        conn.execute("COMMIT")
    return action_id


def append_action_event(action_id: int, event_type: str, payload: Dict[str, Any] = None):
    """Append an arbitrary event to an existing action's hash chain."""
    with _connect() as conn:
        conn.execute("BEGIN")
        _append_event(conn, action_id, event_type, payload)
        conn.execute("COMMIT")


def set_action_status(action_id: int, status: str, output: str = ""):
    """Update status and append a matching event."""
    output = _scrub_secrets(_truncate_output(output))
    ev     = event_type_for_status(status)
    with _connect() as conn:
        conn.execute("BEGIN")
        if output:
            conn.execute("UPDATE actions SET status=?, output=? WHERE id=?",
                         (status, output, action_id))
        else:
            conn.execute("UPDATE actions SET status=? WHERE id=?", (status, action_id))
        _append_event(conn, action_id, ev, {"status": status})
        conn.execute("COMMIT")


def decide_action(action_id: int, decision: str) -> bool:
    """
    Single-use, transactional decision.
    Returns True only if this call actually made the decision.
    Double-clicks and two-tab races produce exactly one decision.
    """
    if decision not in VALID_DECISIONS:
        return False
    with _connect() as conn:
        conn.execute("BEGIN EXCLUSIVE")
        if decision == "alternative":
            cur = conn.execute(
                "UPDATE actions SET status=? WHERE id=? AND status='pending' AND suggestion IS NOT NULL",
                (decision, action_id)
            )
        else:
            cur = conn.execute(
                "UPDATE actions SET status=? WHERE id=? AND status='pending'",
                (decision, action_id)
            )
        success = cur.rowcount == 1
        if success:
            _append_event(conn, action_id, "decision_recorded", {"decision": decision})
        conn.execute("COMMIT")
    return success


def flag_action(action_id: int, reason: str, correct_tier: str = "",
                notes: str = "") -> int:
    """Feature 14: flag a wrong rating. Never changes current decision."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("BEGIN")
        cur = conn.execute("""
            INSERT INTO flag_events (action_id, timestamp, reason, correct_tier, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (action_id, ts, reason, correct_tier, notes))
        flag_id = cur.lastrowid
        _append_event(conn, action_id, "flagged",
                      {"reason": reason, "correct_tier": correct_tier})
        conn.execute("COMMIT")
    return flag_id


def create_alert(action_id: int, kind: str = "pending_approval"):
    """Feature 15: create a pending approval alert."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("INSERT INTO alerts (action_id, timestamp, kind) VALUES (?, ?, ?)",
                     (action_id, ts, kind))


# ---------------------------------------------------------------------------
# Read API — Feature 8
# ---------------------------------------------------------------------------

def get_action(action_id: int) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        if not row:
            return None
        return _row_to_dict(row, conn)


def get_action_history(action_id: int) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM action_events WHERE action_id=? ORDER BY id",
            (action_id,)
        ).fetchall()
        cols = ["id", "action_id", "event_type", "timestamp", "payload", "prev_hash", "event_hash"]
        return [dict(zip(cols, r)) for r in rows]


def get_all_actions() -> List[Tuple]:
    with _connect() as conn:
        return conn.execute("SELECT * FROM actions ORDER BY id DESC").fetchall()


def get_pending_actions() -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM actions WHERE status='pending' ORDER BY id DESC"
        ).fetchall()
        return [_row_to_dict(r, conn) for r in rows]


def search_actions(query: str = "", status: str = "",
                   risk_tier: str = "", limit: int = 100) -> List[Dict[str, Any]]:
    sql    = "SELECT * FROM actions WHERE 1=1"
    params: List[Any] = []
    if query:
        sql += " AND command LIKE ?"
        params.append(f"%{query}%")
    if status:
        sql += " AND status=?"
        params.append(status)
    if risk_tier:
        sql += " AND (base_tier=? OR effective_tier=?)"
        params += [risk_tier, risk_tier]
    sql += f" ORDER BY id DESC LIMIT {int(limit)}"
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r, conn) for r in rows]


def get_actions_by_file(file_path: str) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("""
            SELECT a.* FROM actions a
            JOIN action_files af ON a.id = af.action_id
            WHERE af.file_path = ?
            ORDER BY a.id DESC
        """, (file_path,)).fetchall()
        return [_row_to_dict(r, conn) for r in rows]


def get_actions_by_session(session_id: str) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM actions WHERE session_id=? ORDER BY id",
            (session_id,)
        ).fetchall()
        return [_row_to_dict(r, conn) for r in rows]


def get_actions_by_risk(tier: str) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM actions WHERE effective_tier=? ORDER BY id DESC",
            (tier,)
        ).fetchall()
        return [_row_to_dict(r, conn) for r in rows]


def get_pending_flags() -> List[Dict[str, Any]]:
    """Feature 14: return unreviewed wrong-rating flags."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM flag_events WHERE reviewed=0 ORDER BY id"
        ).fetchall()
        cols = ["id", "action_id", "timestamp", "reason", "correct_tier", "notes", "reviewed"]
        return [dict(zip(cols, r)) for r in rows]


def get_pending_alerts() -> List[Dict[str, Any]]:
    """Feature 15: return undelivered alerts."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE delivered=0 ORDER BY id"
        ).fetchall()
        cols = ["id", "action_id", "timestamp", "kind", "delivered"]
        return [dict(zip(cols, r)) for r in rows]


def get_summary_stats() -> Dict[str, Any]:
    """Feature 16: summary statistics."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
        by_status = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT status, COUNT(*) FROM actions GROUP BY status"
            ).fetchall()
        }
        by_tier = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT effective_tier, COUNT(*) FROM actions GROUP BY effective_tier"
            ).fetchall()
        }
        pending_count = conn.execute(
            "SELECT COUNT(*) FROM actions WHERE status='pending'"
        ).fetchone()[0]
        return {
            "total":        total,
            "by_status":    by_status,
            "by_tier":      by_tier,
            "pending_count": pending_count,
        }


# ---------------------------------------------------------------------------
# Checkpoint (file version history) API — Feature 7
# ---------------------------------------------------------------------------

def record_checkpoint(file_path: str, snapshot_path: str, description: str = "") -> int:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute("""
            INSERT INTO checkpoints (timestamp, file_path, snapshot_path, description)
            VALUES (?, ?, ?, ?)
        """, (ts, file_path, snapshot_path, description))
        return cur.lastrowid


def get_all_checkpoints() -> List[Tuple]:
    with _connect() as conn:
        return conn.execute("SELECT * FROM checkpoints ORDER BY id DESC").fetchall()


def get_checkpoint(checkpoint_id: int) -> Optional[Tuple]:
    with _connect() as conn:
        return conn.execute("SELECT * FROM checkpoints WHERE id=?",
                            (checkpoint_id,)).fetchone()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_action_columns() -> List[str]:
    return [
        "id", "timestamp", "action_type", "command", "risk_tier",
        "status", "output", "suggestion", "tool_use_id", "session_id",
        "base_tier", "effective_tier", "preview_hash", "manifest_hash",
        "backup_hash", "policy_version", "cwd",
    ]


def _row_to_dict(row: Tuple, conn: sqlite3.Connection) -> Dict[str, Any]:
    cols = _get_action_columns()
    d    = dict(zip(cols, row))
    if d.get("suggestion"):
        try:
            d["suggestion"] = json.loads(d["suggestion"])
        except (json.JSONDecodeError, TypeError):
            pass
    return d


def get_action_suggestion(action_id: int) -> Optional[dict]:
    with _connect() as conn:
        row = conn.execute("SELECT suggestion FROM actions WHERE id=?",
                           (action_id,)).fetchone()
        if not row or not row[0]:
            return None
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return None


def get_action_status(action_id: int) -> Optional[str]:
    with _connect() as conn:
        row = conn.execute("SELECT status FROM actions WHERE id=?",
                           (action_id,)).fetchone()
        return row[0] if row else None


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    aid = log_action("shell", "echo test", "LOW", "executed", "test output")
    print(f"Logged LOW action #{aid}")
    aid2 = log_pending_action("shell", "rm -rf build/", "HIGH",
                               suggestion={"kind": "trash", "text": "Move to trash"})
    print(f"Logged pending HIGH action #{aid2}")
    print("DB initialized. Current actions:")
    for row in get_all_actions():
        print(row[:6])