import datetime
import json
import os
import sqlite3
import time
import pytest

from storage.journal import (
    JournalManager,
    InMemoryChainHeadAnchor,
    FileChainHeadAnchor,
    GENESIS_HASH,
    HASH_VERSION,
    compute_event_hash,
    compute_payload_hash,
)


@pytest.fixture
def journal_env(tmp_path):
    db_file = tmp_path / "journal_test.db"
    drop_dir = tmp_path / "drop_folder"
    anchor = InMemoryChainHeadAnchor()
    manager = JournalManager(
        db_path=str(db_file),
        drop_dir=str(drop_dir),
        anchor=anchor,
        grace_period_seconds=0.2,  # fast grace period for testing
    )
    return manager, db_file, drop_dir, anchor


def test_genesis_event_and_hash_chaining(journal_env):
    manager, db_file, _, anchor = journal_env

    # 1. First event uses GENESIS_HASH
    ev1 = manager.append_event(
        event_type="requested",
        payload={"command": "ls -la"},
        session_id="sess_01",
        tool_use_id="tool_1",
    )
    assert ev1.global_seq == 1
    assert ev1.prev_hash == GENESIS_HASH
    assert ev1.session_seq == 1
    assert ev1.hash_version == HASH_VERSION

    # 2. Second event chains to first event's hash
    ev2 = manager.append_event(
        event_type="classified",
        payload={"tier": "LOW"},
        session_id="sess_01",
        tool_use_id="tool_1",
    )
    assert ev2.global_seq == 2
    assert ev2.prev_hash == ev1.event_hash
    assert ev2.session_seq == 2

    # Verify anchor updated
    assert anchor.get_latest_anchor()[0] == 2
    assert anchor.get_latest_anchor()[1] == ev2.event_hash


def test_verify_chain_integrity_valid(journal_env):
    manager, _, _, _ = journal_env

    for i in range(1, 6):
        manager.append_event(
            event_type="test_step",
            payload={"step": i},
            session_id="sess_01",
        )

    report = manager.verify_chain_integrity()
    assert report.is_valid is True
    assert report.total_events == 5
    assert report.head_global_seq == 5
    assert len(report.errors) == 0


def test_detect_tampered_payload(journal_env):
    manager, db_file, _, _ = journal_env

    ev1 = manager.append_event("requested", {"cmd": "safe_command"})
    manager.append_event("classified", {"tier": "LOW"})

    # Tamper with payload in the raw database (bypassing triggers if needed)
    with sqlite3.connect(str(db_file)) as conn:
        conn.execute(
            "UPDATE action_events SET payload=? WHERE id=?",
            (json.dumps({"cmd": "malicious_injected_cmd"}), ev1.id),
        )

    report = manager.verify_chain_integrity()
    assert report.is_valid is False
    assert any("Tampered payload" in err for err in report.errors)


def test_detect_tampered_event_hash(journal_env):
    manager, db_file, _, _ = journal_env

    manager.append_event("requested", {"cmd": "safe_command"})
    ev2 = manager.append_event("classified", {"tier": "LOW"})

    # Temporarily drop trigger to simulate raw file tamper on event_hash
    with sqlite3.connect(str(db_file)) as conn:
        conn.execute("DROP TRIGGER IF EXISTS trg_action_events_immutable_crypto")
        conn.execute(
            "UPDATE action_events SET event_hash='deadbeef' WHERE id=?",
            (ev2.id,),
        )

    report = manager.verify_chain_integrity()
    assert report.is_valid is False
    assert any("Tampered event_hash" in err for err in report.errors)


def test_append_only_triggers_prevent_delete_and_crypto_updates(journal_env):
    manager, db_file, _, _ = journal_env

    ev = manager.append_event("requested", {"cmd": "echo 1"})

    with sqlite3.connect(str(db_file)) as conn:
        # 1. DELETE is blocked
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM action_events WHERE id=?", (ev.id,))

        # 2. UPDATE on cryptographic fields is blocked
        with pytest.raises(sqlite3.DatabaseError, match="strictly immutable"):
            conn.execute("UPDATE action_events SET prev_hash='tampered' WHERE id=?", (ev.id,))


def test_durable_drop_folder_write_and_ingest(journal_env):
    manager, _, drop_dir, _ = journal_env

    # Write entry to drop folder
    fpath = manager.write_journal_entry(
        session_id="sess_alpha",
        session_seq=1,
        tool_use_id="call_99",
        event_type="requested",
        payload={"command": "git status"},
    )
    assert os.path.exists(fpath)
    assert fpath.endswith(".journal")

    # Ingest drop folder
    summary = manager.ingest_drop_folder()
    assert summary.ingested_count == 1
    assert summary.errors == []
    assert not os.path.exists(fpath)  # Moved to processed/

    # Verify event in SQLite
    events = manager.query_events(session_id="sess_alpha")
    assert len(events) == 1
    assert events[0].session_seq == 1
    assert events[0].payload["command"] == "git status"


def test_ingest_idempotency_duplicate_files(journal_env):
    manager, _, drop_dir, _ = journal_env

    j_id = "duplicate_test_uuid"
    fpath = manager.write_journal_entry(
        session_id="sess_idemp",
        session_seq=1,
        tool_use_id="call_1",
        event_type="requested",
        payload={"command": "npm test"},
        journal_event_id=j_id,
    )

    # First ingest
    sum1 = manager.ingest_drop_folder()
    assert sum1.ingested_count == 1

    # Simulate same file arriving again (e.g. client retry)
    fpath2 = manager.write_journal_entry(
        session_id="sess_idemp",
        session_seq=1,
        tool_use_id="call_1",
        event_type="requested",
        payload={"command": "npm test"},
        journal_event_id=j_id,
    )
    sum2 = manager.ingest_drop_folder()
    assert sum2.ingested_count == 0
    assert sum2.skipped_count == 1  # Benign duplicate skipped

    # Verify only 1 event in database
    events = manager.query_events(session_id="sess_idemp")
    assert len(events) == 1


def test_ingest_sequence_gap_detection_and_pause(journal_env):
    manager, _, drop_dir, _ = journal_env

    # Ingest seq 1
    manager.write_journal_entry("sess_gap", 1, "t1", "requested", {"n": 1})
    manager.ingest_drop_folder()

    # Drop seq 3 directly (missing seq 2)
    manager.write_journal_entry("sess_gap", 3, "t3", "requested", {"n": 3})

    # Wait past grace period (0.2s)
    time.sleep(0.3)
    sum_gap = manager.ingest_drop_folder()

    assert sum_gap.gap_count == 1
    assert manager.is_session_paused("sess_gap") is True

    # Check that session_sequence_gap event was appended
    events = manager.query_events(session_id="sess_gap", event_type="session_sequence_gap")
    assert len(events) == 1
    assert events[0].payload["expected_seq"] == 2


def test_grace_period_buffers_delayed_files(journal_env):
    # Long grace period (2.0s)
    manager, _, drop_dir, _ = journal_env
    manager.grace_period_seconds = 2.0

    # Ingest seq 1
    manager.write_journal_entry("sess_buf", 1, "t1", "requested", {"n": 1})
    manager.ingest_drop_folder()

    # Drop seq 3 immediately
    manager.write_journal_entry("sess_buf", 3, "t3", "requested", {"n": 3})

    # Ingest immediately (< 2.0s): file is buffered, not treated as permanent gap
    sum_early = manager.ingest_drop_folder()
    assert sum_early.buffered_count == 1
    assert sum_early.gap_count == 0
    assert manager.is_session_paused("sess_buf") is False

    # Now drop the missing seq 2
    manager.write_journal_entry("sess_buf", 2, "t2", "requested", {"n": 2})

    # Ingest again: both seq 2 and seq 3 ingest in order!
    sum_resolved = manager.ingest_drop_folder()
    assert sum_resolved.ingested_count == 2
    assert manager.is_session_paused("sess_buf") is False

    events = manager.query_events(session_id="sess_buf")
    seqs = [e.session_seq for e in events]
    assert seqs == [1, 2, 3]


def test_late_event_recovery_requires_explicit_resume(journal_env):
    manager, _, drop_dir, _ = journal_env
    manager.grace_period_seconds = 0.1

    # Ingest seq 1
    manager.write_journal_entry("sess_late", 1, "t1", "requested", {"n": 1})
    manager.ingest_drop_folder()

    # Drop seq 3 and let gap expire to pause session
    manager.write_journal_entry("sess_late", 3, "t3", "requested", {"n": 3})
    time.sleep(0.15)
    manager.ingest_drop_folder()
    assert manager.is_session_paused("sess_late") is True

    # Drop late seq 2
    manager.write_journal_entry("sess_late", 2, "t2", "requested", {"n": 2})
    sum_late = manager.ingest_drop_folder()
    assert sum_late.ingested_count == 1  # Absorbed into tail

    # CRUCIAL RULE: Late arrival does NOT silently unpause session!
    assert manager.is_session_paused("sess_late") is True

    # Explicit administrative resume unpauses
    manager.resume_session("sess_late", reason="Reviewed late event; authorized resume")
    assert manager.is_session_paused("sess_late") is False


def test_tombstone_redaction_preserves_chain(journal_env):
    manager, _, _, _ = journal_env

    ev1 = manager.append_event("requested", {"cmd": "curl https://secret-token.com"})
    ev2 = manager.append_event("classified", {"tier": "MEDIUM"})
    ev3 = manager.append_event("executed", {"status": "success"})

    # Redact ev1
    res = manager.redact_event(ev1.id, reason="Privacy request", operator="admin")
    assert res.success is True
    assert res.tombstone_event_id is not None

    # Verify chain integrity PASSES even with redacted payload
    report = manager.verify_chain_integrity()
    assert report.is_valid is True
    assert report.tombstones_count == 1

    # Verify payload was scrubbed in database
    redacted_ev = manager.query_events(action_id=ev1.action_id)[0]
    assert redacted_ev.is_redacted is True
    assert redacted_ev.payload.get("redacted") is True
    assert "secret-token" not in str(redacted_ev.payload)


def test_tombstone_redaction_enforces_rules(journal_env):
    manager, _, _, _ = journal_env

    ev = manager.append_event("requested", {"cmd": "test"})

    # 1. Non-existent event
    res1 = manager.redact_event(9999, "reason")
    assert res1.success is False

    # 2. First redaction succeeds
    res2 = manager.redact_event(ev.id, "reason")
    assert res2.success is True

    # 3. Already redacted event cannot be redacted again
    res3 = manager.redact_event(ev.id, "second redaction")
    assert res3.success is False

    # 4. Tombstone event itself cannot be redacted
    res4 = manager.redact_event(res2.tombstone_event_id, "attempt redact tombstone")
    assert res4.success is False


def test_query_events_filtering_and_pagination(journal_env):
    manager, _, _, _ = journal_env

    for i in range(10):
        manager.append_event(
            event_type="test_event",
            payload={"idx": i},
            session_id=f"sess_{i % 2}",
            action_id=i + 1,
        )

    # Filter by session
    sess_0_events = manager.query_events(session_id="sess_0")
    assert len(sess_0_events) == 5

    # Filter by action_id
    act_1_events = manager.query_events(action_id=1)
    assert len(act_1_events) == 1

    # Pagination: limit 3, offset 2
    page = manager.query_events(limit=3, offset=2)
    assert len(page) == 3
    assert page[0].global_seq == 3


def test_chain_head_anchor_reconciliation(tmp_path):
    db_file = tmp_path / "anchor_test.db"
    drop_dir = tmp_path / "anchor_drop"
    anchor_file = tmp_path / "chain_head.anchor"

    anchor = FileChainHeadAnchor(str(anchor_file))
    manager = JournalManager(
        db_path=str(db_file),
        drop_dir=str(drop_dir),
        anchor=anchor,
    )

    # 1. Initial state
    recon = manager.reconcile_anchor()
    assert recon.status == "synchronized"

    # 2. Append events -> anchor advances
    ev1 = manager.append_event("step", {"x": 1})
    ev2 = manager.append_event("step", {"x": 2})

    recon2 = manager.reconcile_anchor()
    assert recon2.status == "synchronized"
    assert anchor.get_latest_anchor()[0] == 2

    # 3. Rollback detection: simulate DB rollback where DB only has 1 event while anchor has 2
    with sqlite3.connect(str(db_file)) as conn:
        conn.execute("DROP TRIGGER IF EXISTS trg_action_events_no_delete")
        conn.execute("DELETE FROM action_events WHERE global_seq=2")

    recon_rollback = manager.reconcile_anchor()
    assert recon_rollback.status == "rollback_detected"
    assert "Database rollback" in recon_rollback.message


def test_secret_scrubbing_before_write(journal_env):
    manager, _, _, _ = journal_env

    ev = manager.append_event(
        event_type="requested",
        payload={"token": "ghp_1234567890abcdef1234567890abcdef123456", "note": "api_key: secret12345"},
    )

    # Raw secret must not exist in payload
    assert "ghp_1234567890abcdef" not in str(ev.payload)
    assert "<REDACTED>" in str(ev.payload)
