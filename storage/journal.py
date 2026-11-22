"""
Checkpoint Durable Journal Ingestion & Audit Engine — Task 1.2

Implements:
1. Append-only audit event storage with cryptographic hash chaining (SHA-256).
2. Canonical versioned event serialization format ("1").
3. Drop-folder writer with atomic fsync and drop-folder ingestion under BEGIN IMMEDIATE.
4. Out-of-order session sequence buffering and grace period handling.
5. Strict acyclic tombstone redaction preserving verifiable hash-chain continuity.
6. Local chain-head anchoring and startup crash/rollback reconciliation.
7. Query read API with filtering and pagination.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil
import sqlite3
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64
HASH_VERSION = "1"

# ---------------------------------------------------------------------------
# Secret Scrubbing
# ---------------------------------------------------------------------------

_PAT1 = re.compile(
    r'((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*)(\S+)',
    re.IGNORECASE
)
_PAT2 = re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{30,}|ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b')
_PAT3 = re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b')


def scrub_secrets(text: str) -> str:
    """Replace apparent secrets with <REDACTED>."""
    if not isinstance(text, str):
        return text
    # Preserve 64-character pure hex hashes
    if len(text) == 64 and re.fullmatch(r'[0-9a-fA-F]{64}', text):
        return text
    text = _PAT1.sub(r'\1<REDACTED>', text)
    text = _PAT2.sub('<REDACTED>', text)

    def _replace_base64(m):
        val = m.group(0)
        if len(val) == 64 and re.fullmatch(r'[0-9a-fA-F]{64}', val):
            return val
        return "<REDACTED>"

    text = _PAT3.sub(_replace_base64, text)
    return text


def scrub_dict(d: Any) -> Any:
    """Recursively scrub secrets in dictionary or list values."""
    if isinstance(d, dict):
        return {k: scrub_dict(v) for k, v in d.items()}
    elif isinstance(d, list):
        return [scrub_dict(x) for x in d]
    elif isinstance(d, str):
        return scrub_secrets(d)
    return d


# ---------------------------------------------------------------------------
# Canonical Serialization & Hashing
# ---------------------------------------------------------------------------

def canonical_payload_json(payload: Dict[str, Any]) -> str:
    """Deterministic JSON serialization for event payloads."""
    scrubbed = scrub_dict(payload or {})
    return json.dumps(scrubbed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_payload_hash(payload: Dict[str, Any]) -> str:
    """SHA-256 digest of canonical payload."""
    raw = canonical_payload_json(payload)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_event_hash(
    hash_version: str,
    global_seq: int,
    session_id: str,
    session_seq: int,
    tool_use_id: str,
    action_id: Optional[int],
    event_type: str,
    timestamp: str,
    prev_hash: str,
    payload_hash: str,
) -> str:
    """
    Compute deterministic event hash over all security-relevant fields.
    """
    canonical_dict = {
        "action_id": action_id,
        "event_type": event_type,
        "global_seq": global_seq,
        "hash_version": hash_version,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "session_id": session_id,
        "session_seq": session_seq,
        "timestamp": timestamp,
        "tool_use_id": tool_use_id,
    }
    raw = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Data Models & Results
# ---------------------------------------------------------------------------

@dataclass
class EventRecord:
    id: int
    journal_event_id: str
    global_seq: int
    session_id: str
    session_seq: Optional[int]
    tool_use_id: str
    action_id: Optional[int]
    event_type: str
    timestamp: str
    payload: Dict[str, Any]
    payload_hash: str
    prev_hash: str
    event_hash: str
    hash_version: str
    is_redacted: bool
    tombstone_event_id: Optional[int]
    redacted_at: Optional[str]
    redaction_reason: Optional[str]


@dataclass
class IngestSummary:
    ingested_count: int = 0
    skipped_count: int = 0
    gap_count: int = 0
    buffered_count: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class IntegrityReport:
    is_valid: bool
    total_events: int
    head_global_seq: int
    head_event_hash: str
    tombstones_count: int
    errors: List[str] = field(default_factory=list)
    anchor_synchronized: Optional[bool] = None


@dataclass
class RedactResult:
    success: bool
    target_event_id: int
    tombstone_event_id: Optional[int] = None
    message: str = ""


@dataclass
class AnchorReconciliationResult:
    status: str   # "synchronized", "advanced", "rollback_detected", "divergence_detected", "initialized"
    anchor_seq: int
    db_seq: int
    message: str


# ---------------------------------------------------------------------------
# Chain-Head Anchoring Interfaces
# ---------------------------------------------------------------------------

class ChainHeadAnchor(ABC):
    @abstractmethod
    def record_anchor(self, global_seq: int, head_hash: str, timestamp: str) -> None:
        """Record the latest chain head outside the main database."""
        pass

    @abstractmethod
    def get_latest_anchor(self) -> Optional[Tuple[int, str, str]]:
        """Return (global_seq, head_hash, timestamp) of latest anchor, or None."""
        pass


class InMemoryChainHeadAnchor(ChainHeadAnchor):
    """In-memory anchor for isolated testing."""
    def __init__(self):
        self._anchor: Optional[Tuple[int, str, str]] = None

    def record_anchor(self, global_seq: int, head_hash: str, timestamp: str) -> None:
        self._anchor = (global_seq, head_hash, timestamp)

    def get_latest_anchor(self) -> Optional[Tuple[int, str, str]]:
        return self._anchor


class FileChainHeadAnchor(ChainHeadAnchor):
    """Local atomic file-based anchor stored outside the database file."""
    def __init__(self, anchor_path: str):
        self.anchor_path = os.path.abspath(anchor_path)
        os.makedirs(os.path.dirname(self.anchor_path), exist_ok=True)

    def record_anchor(self, global_seq: int, head_hash: str, timestamp: str) -> None:
        data = {
            "anchor_version": "1",
            "global_seq": global_seq,
            "head_hash": head_hash,
            "timestamp": timestamp,
        }
        raw = json.dumps(data, indent=2).encode("utf-8")
        parent_dir = os.path.dirname(self.anchor_path)
        tmp_path = os.path.join(parent_dir, f"anchor_{uuid.uuid4().hex[:8]}.tmp")
        with open(tmp_path, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.anchor_path)

    def get_latest_anchor(self) -> Optional[Tuple[int, str, str]]:
        if not os.path.exists(self.anchor_path):
            return None
        try:
            with open(self.anchor_path, "rb") as f:
                data = json.load(f)
            return (int(data["global_seq"]), str(data["head_hash"]), str(data["timestamp"]))
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Journal Manager
# ---------------------------------------------------------------------------

class JournalManager:
    """
    Manages durable write-ahead journal ingestion, append-only cryptographic event
    storage, query interfaces, and integrity verification.
    """

    def __init__(
        self,
        db_path: str,
        drop_dir: str,
        anchor: Optional[ChainHeadAnchor] = None,
        grace_period_seconds: float = 5.0,
    ):
        self.db_path = os.path.abspath(db_path)
        self.drop_dir = os.path.abspath(drop_dir)
        self.processed_dir = os.path.join(self.drop_dir, "processed")
        self.anchor = anchor
        self.grace_period_seconds = grace_period_seconds

        os.makedirs(self.drop_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
        self._init_db_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db_schema(self):
        """Ensure action_events has all cryptographic audit columns and triggers."""
        with self._connect() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS action_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                journal_event_id    TEXT UNIQUE,
                global_seq          INTEGER UNIQUE,
                session_id          TEXT NOT NULL DEFAULT '',
                session_seq         INTEGER,
                tool_use_id         TEXT NOT NULL DEFAULT '',
                action_id           INTEGER,
                event_type          TEXT NOT NULL,
                timestamp           TEXT NOT NULL,
                payload             TEXT NOT NULL,
                payload_hash        TEXT NOT NULL DEFAULT '',
                prev_hash           TEXT NOT NULL DEFAULT '',
                event_hash          TEXT NOT NULL UNIQUE,
                hash_version        TEXT NOT NULL DEFAULT '1',
                is_redacted         INTEGER NOT NULL DEFAULT 0,
                tombstone_event_id  INTEGER REFERENCES action_events(id),
                redacted_at         TEXT,
                redaction_reason    TEXT
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS session_states (
                session_id          TEXT PRIMARY KEY,
                state               TEXT NOT NULL DEFAULT 'active',
                paused_at           TEXT,
                pause_reason        TEXT
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS journal_ingest_records (
                journal_event_id    TEXT PRIMARY KEY,
                session_id          TEXT NOT NULL,
                session_seq         INTEGER NOT NULL,
                event_id            INTEGER NOT NULL REFERENCES action_events(id),
                ingested_at         TEXT NOT NULL,
                file_hash           TEXT NOT NULL
            );
            """)

            # Indices
            conn.execute("CREATE INDEX IF NOT EXISTS idx_action_events_action ON action_events(action_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_action_events_session ON action_events(session_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_action_events_seq ON action_events(global_seq);")

            # Append-only triggers
            conn.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_action_events_no_delete
            BEFORE DELETE ON action_events
            BEGIN
                SELECT RAISE(ABORT, 'action_events is append-only: deletion is prohibited');
            END;
            """)

            conn.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_action_events_immutable_crypto
            BEFORE UPDATE OF id, journal_event_id, global_seq, session_id, session_seq,
                             tool_use_id, action_id, event_type, timestamp, payload_hash,
                             prev_hash, event_hash, hash_version
            ON action_events
            BEGIN
                SELECT RAISE(ABORT, 'Cryptographic and sequence fields in action_events are strictly immutable');
            END;
            """)

            conn.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_action_events_redaction_check
            BEFORE UPDATE OF is_redacted, payload, tombstone_event_id ON action_events
            BEGIN
                SELECT CASE WHEN OLD.is_redacted = 1 AND NEW.is_redacted = 0
                    THEN RAISE(ABORT, 'Redacted events cannot be un-redacted') END;
                SELECT CASE WHEN OLD.event_type = 'tombstone'
                    THEN RAISE(ABORT, 'Tombstone events cannot be redacted') END;
                SELECT CASE WHEN NEW.is_redacted = 1 AND NEW.tombstone_event_id IS NULL
                    THEN RAISE(ABORT, 'Redaction requires a valid tombstone_event_id') END;
            END;
            """)

    # ---------------------------------------------------------------------------
    # Write Path (Drop Folder)
    # ---------------------------------------------------------------------------

    def write_journal_entry(
        self,
        session_id: str,
        session_seq: int,
        tool_use_id: str,
        event_type: str,
        payload: Dict[str, Any],
        action_id: Optional[int] = None,
        journal_event_id: Optional[str] = None,
    ) -> str:
        """
        Write a durable journal entry to the drop folder with fsync.
        Atomic write: .tmp -> .journal.
        """
        j_id = journal_event_id or uuid.uuid4().hex
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scrubbed_payload = scrub_dict(payload or {})

        entry_data = {
            "journal_event_id": j_id,
            "session_id": session_id,
            "session_seq": session_seq,
            "tool_use_id": tool_use_id,
            "action_id": action_id,
            "event_type": event_type,
            "timestamp": ts,
            "payload": scrubbed_payload,
        }

        filename = f"{session_id}_{session_seq:08d}_{j_id}.journal"
        tmp_filename = f"{filename}.tmp"
        tmp_path = os.path.join(self.drop_dir, tmp_filename)
        final_path = os.path.join(self.drop_dir, filename)

        raw = json.dumps(entry_data, indent=2).encode("utf-8")
        with open(tmp_path, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, final_path)
        return final_path

    # ---------------------------------------------------------------------------
    # Direct Durable Append
    # ---------------------------------------------------------------------------

    def append_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        session_id: str = "",
        session_seq: Optional[int] = None,
        tool_use_id: str = "",
        action_id: Optional[int] = None,
        journal_event_id: Optional[str] = None,
    ) -> EventRecord:
        """
        Directly append an event to SQLite under BEGIN IMMEDIATE with cryptographic chaining.
        """
        j_id = journal_event_id or uuid.uuid4().hex
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scrubbed = scrub_dict(payload or {})
        canonical_p = canonical_payload_json(scrubbed)
        p_hash = compute_payload_hash(scrubbed)

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            # Allocate session_seq if not provided
            if session_seq is None:
                if session_id and event_type not in (
                    "session_sequence_gap", "session_late_event_recorded", "session_resumed", "tombstone"
                ):
                    row_s = conn.execute(
                        "SELECT COALESCE(MAX(session_seq), 0) + 1 FROM action_events WHERE session_id=? AND session_seq IS NOT NULL",
                        (session_id,)
                    ).fetchone()
                    session_seq = row_s[0]
                else:
                    session_seq = None

            # Allocate global_seq & get prev_hash
            row_h = conn.execute(
                "SELECT global_seq, event_hash FROM action_events ORDER BY global_seq DESC LIMIT 1"
            ).fetchone()

            if row_h:
                global_seq = row_h[0] + 1
                prev_hash = row_h[1]
            else:
                global_seq = 1
                prev_hash = GENESIS_HASH

            ev_hash = compute_event_hash(
                hash_version=HASH_VERSION,
                global_seq=global_seq,
                session_id=session_id,
                session_seq=session_seq,
                tool_use_id=tool_use_id,
                action_id=action_id,
                event_type=event_type,
                timestamp=ts,
                prev_hash=prev_hash,
                payload_hash=p_hash,
            )

            cur = conn.execute("""
                INSERT INTO action_events
                  (journal_event_id, global_seq, session_id, session_seq, tool_use_id,
                   action_id, event_type, timestamp, payload, payload_hash, prev_hash,
                   event_hash, hash_version, is_redacted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (j_id, global_seq, session_id, session_seq, tool_use_id,
                  action_id, event_type, ts, canonical_p, p_hash, prev_hash,
                  ev_hash, HASH_VERSION))
            row_id = cur.lastrowid
            conn.execute("COMMIT")

        if self.anchor:
            self.anchor.record_anchor(global_seq, ev_hash, ts)

        return EventRecord(
            id=row_id,
            journal_event_id=j_id,
            global_seq=global_seq,
            session_id=session_id,
            session_seq=session_seq,
            tool_use_id=tool_use_id,
            action_id=action_id,
            event_type=event_type,
            timestamp=ts,
            payload=scrubbed,
            payload_hash=p_hash,
            prev_hash=prev_hash,
            event_hash=ev_hash,
            hash_version=HASH_VERSION,
            is_redacted=False,
            tombstone_event_id=None,
            redacted_at=None,
            redaction_reason=None,
        )

    # ---------------------------------------------------------------------------
    # Ingestion Path
    # ---------------------------------------------------------------------------

    def ingest_drop_folder(self) -> IngestSummary:
        """
        Scan drop folder, verify sequence buffering, append to SQLite under BEGIN IMMEDIATE,
        and move ingested files to processed/.
        """
        summary = IngestSummary()
        files = [
            f for f in os.listdir(self.drop_dir)
            if f.endswith(".journal") and not f.endswith(".tmp")
        ]

        if not files:
            return summary

        # Group by session_id and sort by session_seq
        session_files: Dict[str, List[Tuple[int, str, str]]] = {}
        for fname in files:
            fpath = os.path.join(self.drop_dir, fname)
            try:
                with open(fpath, "rb") as fp:
                    data = json.load(fp)
                sess = data.get("session_id", "")
                seq = int(data.get("session_seq", 0))
                session_files.setdefault(sess, []).append((seq, fpath, fname))
            except Exception as e:
                summary.errors.append(f"Failed to read journal file {fname}: {e}")

        now = time.time()

        for session_id, file_list in session_files.items():
            file_list.sort(key=lambda x: x[0])  # sort by session_seq

            with self._connect() as conn:
                # Query last ingested session_seq
                row = conn.execute(
                    "SELECT COALESCE(MAX(session_seq), 0) FROM action_events WHERE session_id=?",
                    (session_id,)
                ).fetchone()
                last_seq = row[0]

                # Check session state
                st_row = conn.execute(
                    "SELECT state FROM session_states WHERE session_id=?", (session_id,)
                ).fetchone()
                session_paused = bool(st_row and st_row[0] == "paused")

            for seq, fpath, fname in file_list:
                try:
                    with open(fpath, "rb") as fp:
                        raw_bytes = fp.read()
                        entry = json.loads(raw_bytes.decode("utf-8"))
                    file_sha = hashlib.sha256(raw_bytes).hexdigest()
                except Exception as e:
                    summary.errors.append(f"Malformed journal file {fname}: {e}")
                    continue

                j_id = entry.get("journal_event_id", "")
                tool_use_id = entry.get("tool_use_id", "")
                action_id = entry.get("action_id")
                event_type = entry.get("event_type", "unknown")
                payload = entry.get("payload", {})

                # 1. Duplicate check
                with self._connect() as conn:
                    existing = conn.execute(
                        "SELECT id, payload_hash FROM action_events WHERE journal_event_id=?",
                        (j_id,)
                    ).fetchone()
                    if existing:
                        p_hash = compute_payload_hash(payload)
                        if existing[1] == p_hash:
                            # Benign duplicate retry
                            dest = os.path.join(self.processed_dir, fname)
                            os.replace(fpath, dest)
                            summary.skipped_count += 1
                            continue
                        else:
                            summary.errors.append(
                                f"Collision: duplicate journal_event_id {j_id} with conflicting payload"
                            )
                            continue

                    # Check (session_id, session_seq) collision
                    seq_collision = conn.execute(
                        "SELECT id FROM action_events WHERE session_id=? AND session_seq=?",
                        (session_id, seq)
                    ).fetchone()
                    if seq_collision:
                        summary.errors.append(
                            f"Collision: duplicate (session_id={session_id}, session_seq={seq})"
                        )
                        self._pause_session(session_id, f"Duplicate session sequence collision at seq {seq}")
                        continue

                # 2. Sequence gap check
                if seq > last_seq + 1:
                    mtime = os.path.getmtime(fpath)
                    age = now - mtime
                    if age < self.grace_period_seconds:
                        # Grace period: buffer file in drop folder
                        summary.buffered_count += 1
                        break  # stop processing this session's subsequent files until gap resolves
                    else:
                        # Gap timeout expired: record integrity event and pause session
                        summary.gap_count += 1
                        summary.errors.append(
                            f"Journal sequence gap detected in session {session_id}: expected {last_seq + 1}, got {seq}"
                        )
                        self._pause_session(
                            session_id,
                            f"Journal sequence gap: expected {last_seq + 1}, got {seq}"
                        )
                        self.append_event(
                            event_type="session_sequence_gap",
                            payload={
                                "session_id": session_id,
                                "expected_seq": last_seq + 1,
                                "received_seq": seq,
                                "status": "gap_unresolved",
                            },
                            session_id=session_id,
                        )
                        break

                # 3. If session is paused, late arrival handling
                if session_paused:
                    with self._connect() as conn:
                        gap_row = conn.execute("""
                            SELECT payload FROM action_events
                            WHERE session_id=? AND event_type='session_sequence_gap'
                            ORDER BY id DESC LIMIT 1
                        """, (session_id,)).fetchone()

                    is_gap_filler = False
                    if gap_row:
                        try:
                            g_payload = json.loads(gap_row[0])
                            exp_s = g_payload.get("expected_seq", 0)
                            rec_s = g_payload.get("received_seq", 0)
                            if exp_s <= seq < rec_s:
                                is_gap_filler = True
                        except Exception:
                            pass

                    if is_gap_filler:
                        rec = self.append_event(
                            event_type=event_type,
                            payload=payload,
                            session_id=session_id,
                            session_seq=seq,
                            tool_use_id=tool_use_id,
                            action_id=action_id,
                            journal_event_id=j_id,
                        )
                        self.append_event(
                            event_type="session_late_event_recorded",
                            payload={"session_id": session_id, "recovered_seq": seq, "global_seq": rec.global_seq},
                            session_id=session_id,
                        )
                        dest = os.path.join(self.processed_dir, fname)
                        os.replace(fpath, dest)
                        summary.ingested_count += 1
                        continue
                    else:
                        # Cannot advance a paused session without explicit resume
                        summary.errors.append(f"Session {session_id} is paused; new events blocked until resume")
                        break

                # 4. Normal sequential ingest
                rec = self.append_event(
                    event_type=event_type,
                    payload=payload,
                    session_id=session_id,
                    session_seq=seq,
                    tool_use_id=tool_use_id,
                    action_id=action_id,
                    journal_event_id=j_id,
                )

                # Record idempotency record
                with self._connect() as conn:
                    conn.execute("""
                        INSERT INTO journal_ingest_records
                          (journal_event_id, session_id, session_seq, event_id, ingested_at, file_hash)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (j_id, session_id, seq, rec.id, datetime.datetime.now(datetime.timezone.utc).isoformat(), file_sha))

                dest = os.path.join(self.processed_dir, fname)
                os.replace(fpath, dest)
                summary.ingested_count += 1
                last_seq = seq

        if self.anchor:
            self.reconcile_anchor()

        return summary

    def _pause_session(self, session_id: str, reason: str):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO session_states (session_id, state, paused_at, pause_reason)
                VALUES (?, 'paused', ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    state='paused', paused_at=excluded.paused_at, pause_reason=excluded.pause_reason
            """, (session_id, ts, reason))

    def resume_session(self, session_id: str, reason: str, operator: str = "user"):
        """Explicitly resume a paused session after administrative review."""
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO session_states (session_id, state, paused_at, pause_reason)
                VALUES (?, 'active', NULL, NULL)
                ON CONFLICT(session_id) DO UPDATE SET
                    state='active', paused_at=NULL, pause_reason=NULL
            """, (session_id,))

        self.append_event(
            event_type="session_resumed",
            payload={"session_id": session_id, "reason": reason, "operator": operator},
            session_id=session_id,
        )

    def is_session_paused(self, session_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT state FROM session_states WHERE session_id=?", (session_id,)).fetchone()
            return bool(row and row[0] == "paused")

    # ---------------------------------------------------------------------------
    # Query Read API
    # ---------------------------------------------------------------------------

    def query_events(
        self,
        action_id: Optional[int] = None,
        session_id: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        include_redacted: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EventRecord]:
        """Read API for audit events with filtering and pagination."""
        clauses = []
        params = []

        if action_id is not None:
            clauses.append("action_id = ?")
            params.append(action_id)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp <= ?")
            params.append(until)
        if not include_redacted:
            clauses.append("is_redacted = 0")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT id, journal_event_id, global_seq, session_id, session_seq,
                   tool_use_id, action_id, event_type, timestamp, payload,
                   payload_hash, prev_hash, event_hash, hash_version,
                   is_redacted, tombstone_event_id, redacted_at, redaction_reason
            FROM action_events
            {where_sql}
            ORDER BY global_seq ASC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        results = []
        for r in rows:
            try:
                p = json.loads(r[9])
            except Exception:
                p = {"raw": r[9]}
            results.append(EventRecord(
                id=r[0],
                journal_event_id=r[1],
                global_seq=r[2],
                session_id=r[3],
                session_seq=r[4],
                tool_use_id=r[5],
                action_id=r[6],
                event_type=r[7],
                timestamp=r[8],
                payload=p,
                payload_hash=r[10],
                prev_hash=r[11],
                event_hash=r[12],
                hash_version=r[13],
                is_redacted=bool(r[14]),
                tombstone_event_id=r[15],
                redacted_at=r[16],
                redaction_reason=r[17],
            ))
        return results

    # ---------------------------------------------------------------------------
    # Integrity Verification API
    # ---------------------------------------------------------------------------

    def verify_chain_integrity(self) -> IntegrityReport:
        """
        Full cryptographic verification of event chain:
        - Global sequence continuity (1..N)
        - prev_hash linkage
        - Canonical event_hash calculation
        - payload_hash verification for active events
        - Tombstone authorization for redacted events
        - Anchor head comparison
        """
        errors = []
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT id, journal_event_id, global_seq, session_id, session_seq,
                       tool_use_id, action_id, event_type, timestamp, payload,
                       payload_hash, prev_hash, event_hash, hash_version,
                       is_redacted, tombstone_event_id
                FROM action_events
                ORDER BY global_seq ASC
            """).fetchall()

        total = len(rows)
        if total == 0:
            return IntegrityReport(
                is_valid=True,
                total_events=0,
                head_global_seq=0,
                head_event_hash="",
                tombstones_count=0,
                anchor_synchronized=True,
            )

        expected_prev = GENESIS_HASH
        expected_seq = 1
        tombstones_count = 0
        head_hash = ""
        head_seq = 0

        # Pre-load tombstone records for fast verification
        tombstones_by_id = {}
        for r in rows:
            if r[7] == "tombstone":
                try:
                    tombstones_by_id[r[0]] = json.loads(r[9])
                except Exception:
                    pass

        for r in rows:
            (e_id, j_id, g_seq, s_id, s_seq, tool_id, a_id,
             ev_type, ts, payload_str, p_hash, prev_h, ev_h, h_ver,
             is_red, tomb_id) = r

            head_seq = g_seq
            head_hash = ev_h

            # 1. Global sequence continuity
            if g_seq != expected_seq:
                errors.append(f"Sequence gap/disorder at event {e_id}: expected global_seq {expected_seq}, got {g_seq}")

            # 2. prev_hash cryptographic link
            if prev_h != expected_prev:
                errors.append(f"Broken hash link at global_seq {g_seq}: expected prev_hash {expected_prev}, got {prev_h}")

            # 3. Canonical event_hash calculation
            expected_ev_hash = compute_event_hash(
                hash_version=h_ver,
                global_seq=g_seq,
                session_id=s_id,
                session_seq=s_seq,
                tool_use_id=tool_id,
                action_id=a_id,
                event_type=ev_type,
                timestamp=ts,
                prev_hash=prev_h,
                payload_hash=p_hash,
            )
            if ev_h != expected_ev_hash:
                errors.append(f"Tampered event_hash at global_seq {g_seq}: expected {expected_ev_hash}, got {ev_h}")

            # 4. Payload integrity & Tombstone check
            try:
                p_dict = json.loads(payload_str)
            except Exception:
                p_dict = {}

            if is_red:
                tombstones_count += 1
                if not tomb_id or tomb_id not in tombstones_by_id:
                    errors.append(f"Unauthorized redaction at global_seq {g_seq}: missing or invalid tombstone_event_id {tomb_id}")
                else:
                    t_payload = tombstones_by_id[tomb_id]
                    if t_payload.get("target_payload_hash") != p_hash:
                        errors.append(f"Tombstone payload hash mismatch at global_seq {g_seq}")
            else:
                # Active event: payload must match payload_hash
                actual_p_hash = compute_payload_hash(p_dict)
                if actual_p_hash != p_hash:
                    errors.append(f"Tampered payload at global_seq {g_seq}: payload hash mismatch")

            expected_prev = ev_h
            expected_seq += 1

        # 5. External Anchor check
        anchor_sync = None
        if self.anchor:
            recon = self.reconcile_anchor()
            if recon.status in ("rollback_detected", "divergence_detected"):
                errors.append(f"Anchor check failed: {recon.message}")
                anchor_sync = False
            else:
                anchor_sync = True

        return IntegrityReport(
            is_valid=(len(errors) == 0),
            total_events=total,
            head_global_seq=head_seq,
            head_event_hash=head_hash,
            tombstones_count=tombstones_count,
            errors=errors,
            anchor_synchronized=anchor_sync,
        )

    # ---------------------------------------------------------------------------
    # Tombstone Redaction API
    # ---------------------------------------------------------------------------

    def redact_event(
        self,
        target_event_id: int,
        reason: str,
        operator: str = "user"
    ) -> RedactResult:
        """
        Acyclic tombstone redaction:
        1. Validates target exists, is not redacted, is not a tombstone.
        2. Appends tombstone audit event at tail (global_seq = M > N).
        3. Replaces target payload with tombstone descriptor and marks is_redacted = 1.
        Preserves original payload_hash, prev_hash, and event_hash.
        """
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            target = conn.execute("""
                SELECT id, global_seq, session_id, event_type, payload_hash, is_redacted
                FROM action_events WHERE id=?
            """, (target_event_id,)).fetchone()

            if not target:
                conn.execute("ROLLBACK")
                return RedactResult(success=False, target_event_id=target_event_id, message="Target event not found")

            (t_id, t_seq, t_sess, t_type, t_phash, t_is_red) = target

            if t_is_red:
                conn.execute("ROLLBACK")
                return RedactResult(success=False, target_event_id=target_event_id, message="Event is already redacted")

            if t_type == "tombstone":
                conn.execute("ROLLBACK")
                return RedactResult(success=False, target_event_id=target_event_id, message="Cannot redact a tombstone event")

            # Allocate tombstone event at tail
            row_h = conn.execute(
                "SELECT global_seq, event_hash FROM action_events ORDER BY global_seq DESC LIMIT 1"
            ).fetchone()
            m_seq = row_h[0] + 1
            prev_h = row_h[1]

            tombstone_payload = {
                "target_event_id": t_id,
                "target_global_seq": t_seq,
                "target_payload_hash": t_phash,
                "operator": operator,
                "reason": reason,
                "redacted_at": ts,
            }
            canonical_tp = canonical_payload_json(tombstone_payload)
            tp_hash = compute_payload_hash(tombstone_payload)

            tomb_ev_hash = compute_event_hash(
                hash_version=HASH_VERSION,
                global_seq=m_seq,
                session_id=t_sess,
                session_seq=0,
                tool_use_id="",
                action_id=None,
                event_type="tombstone",
                timestamp=ts,
                prev_hash=prev_h,
                payload_hash=tp_hash,
            )

            # Insert tombstone event first
            cur = conn.execute("""
                INSERT INTO action_events
                  (journal_event_id, global_seq, session_id, session_seq, tool_use_id,
                   action_id, event_type, timestamp, payload, payload_hash, prev_hash,
                   event_hash, hash_version, is_redacted)
                VALUES (?, ?, ?, 0, '', NULL, 'tombstone', ?, ?, ?, ?, ?, ?, 0)
            """, (uuid.uuid4().hex, m_seq, t_sess, ts, canonical_tp, tp_hash, prev_h, tomb_ev_hash, HASH_VERSION))
            tombstone_row_id = cur.lastrowid

            # Update target event with tombstone notice
            tombstone_notice = json.dumps({
                "redacted": True,
                "reason": reason,
                "tombstone_global_seq": m_seq,
                "redacted_at": ts,
            })

            conn.execute("""
                UPDATE action_events
                SET payload=?, is_redacted=1, tombstone_event_id=?, redacted_at=?, redaction_reason=?
                WHERE id=?
            """, (tombstone_notice, tombstone_row_id, ts, reason, t_id))

            conn.execute("COMMIT")

        if self.anchor:
            self.anchor.record_anchor(m_seq, tomb_ev_hash, ts)

        return RedactResult(
            success=True,
            target_event_id=t_id,
            tombstone_event_id=tombstone_row_id,
            message="Event successfully redacted and tombstoned",
        )

    # ---------------------------------------------------------------------------
    # Anchor Reconciliation
    # ---------------------------------------------------------------------------

    def reconcile_anchor(self) -> AnchorReconciliationResult:
        """
        Reconcile database head with external anchor:
        - Synchronized: matches exactly.
        - Database ahead: verifies history at anchor_seq, then advances anchor.
        - Database behind: flags database rollback or tail truncation!
        - Divergence: head at anchor_seq does not match anchor_hash.
        """
        if not self.anchor:
            return AnchorReconciliationResult(
                status="no_anchor", anchor_seq=0, db_seq=0, message="No anchor configured"
            )

        with self._connect() as conn:
            row = conn.execute(
                "SELECT global_seq, event_hash, timestamp FROM action_events ORDER BY global_seq DESC LIMIT 1"
            ).fetchone()

        db_seq = row[0] if row else 0
        db_hash = row[1] if row else ""
        db_ts = row[2] if row else ""

        anchor_data = self.anchor.get_latest_anchor()
        if not anchor_data:
            if db_seq > 0:
                self.anchor.record_anchor(db_seq, db_hash, db_ts)
                return AnchorReconciliationResult(
                    status="initialized", anchor_seq=db_seq, db_seq=db_seq, message="Anchor initialized from DB head"
                )
            return AnchorReconciliationResult(
                status="synchronized", anchor_seq=0, db_seq=0, message="Both empty"
            )

        anchor_seq, anchor_hash, _ = anchor_data

        if db_seq == anchor_seq and db_hash == anchor_hash:
            return AnchorReconciliationResult(
                status="synchronized", anchor_seq=anchor_seq, db_seq=db_seq, message="Fully synchronized"
            )

        if db_seq > anchor_seq:
            # DB has more events; check if history at anchor_seq matches
            with self._connect() as conn:
                ev_at_anchor = conn.execute(
                    "SELECT event_hash FROM action_events WHERE global_seq=?", (anchor_seq,)
                ).fetchone()

            if ev_at_anchor and ev_at_anchor[0] == anchor_hash:
                # History is consistent, advance anchor
                self.anchor.record_anchor(db_seq, db_hash, db_ts)
                return AnchorReconciliationResult(
                    status="advanced", anchor_seq=db_seq, db_seq=db_seq, message=f"Anchor advanced from {anchor_seq} to {db_seq}"
                )
            else:
                return AnchorReconciliationResult(
                    status="divergence_detected",
                    anchor_seq=anchor_seq,
                    db_seq=db_seq,
                    message=f"DB history at seq {anchor_seq} diverged from anchor hash!",
                )

        if db_seq < anchor_seq:
            # DB has fewer events than previously anchored!
            return AnchorReconciliationResult(
                status="rollback_detected",
                anchor_seq=anchor_seq,
                db_seq=db_seq,
                message=f"Database rollback or tail truncation detected! DB head {db_seq} < anchor {anchor_seq}",
            )

        return AnchorReconciliationResult(
            status="divergence_detected",
            anchor_seq=anchor_seq,
            db_seq=db_seq,
            message="Anchor hash mismatch at equal sequence",
        )
