"""
tests/test_expiry.py — Tests for Task C: Server-Side Authoritative Approval Expiry
"""
import datetime
import os
import sqlite3
import time
import pytest

from storage.db import (
    init_db,
    log_pending_action,
    get_action,
    decide_action,
    expire_stale_actions,
    get_alerts,
    _connect,
)
from storage.journal import JournalManager
from core.expiry_daemon import ApprovalExpiryWorker, start_expiry_worker, stop_expiry_worker


@pytest.fixture(autouse=True)
def setup_clean_db(tmp_path, monkeypatch):
    """Isolate DB for each test."""
    db_file = str(tmp_path / "checkpoint_expiry_test.db")
    monkeypatch.setattr("storage.db.DB_PATH", db_file)
    init_db()
    yield
    stop_expiry_worker()


def _backdate_action(action_id: int, seconds_ago: float):
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds_ago)
    with _connect() as conn:
        conn.execute("UPDATE actions SET timestamp=? WHERE id=?", (dt.isoformat(), action_id))


def test_decide_action_rejects_expired_pending_action():
    aid = log_pending_action("bash", "rm -rf /critical/path", "HIGH", session_id="sess_exp_1", tool_use_id="tu_1")
    action = get_action(aid)
    assert action["status"] == "pending"

    # Backdate to 301 seconds ago
    _backdate_action(aid, 301.0)

    # Attempt to approve
    result = decide_action(aid, "approved")
    assert result is False

    # Status must be authoritatively 'stale'
    updated = get_action(aid)
    assert updated["status"] == "stale"

    # Journal must contain approval_expired event
    with _connect() as conn:
        row = conn.execute(
            "SELECT event_type, payload FROM action_events WHERE action_id=? AND event_type='approval_expired'",
            (aid,)
        ).fetchone()
        assert row is not None
        assert row[0] == "approval_expired"
        assert "late_decision_attempt" in row[1]


def test_expire_stale_actions_sweep():
    # Fresh action
    aid_fresh = log_pending_action("bash", "ls -la", "MEDIUM", session_id="sess_exp_2", tool_use_id="tu_fresh")

    # Expired action (310 seconds old)
    aid_expired = log_pending_action("bash", "git reset --hard HEAD~1", "HIGH", session_id="sess_exp_2", tool_use_id="tu_exp")
    _backdate_action(aid_expired, 310.0)

    expired_ids = expire_stale_actions(timeout_seconds=300.0)

    assert aid_expired in expired_ids
    assert aid_fresh not in expired_ids

    assert get_action(aid_fresh)["status"] == "pending"
    assert get_action(aid_expired)["status"] == "stale"

    # Verify alert created in DB
    alerts = get_alerts()
    timeout_alerts = [a for a in alerts if a["action_id"] == aid_expired and a["kind"] == "timeout"]
    assert len(timeout_alerts) >= 1


def test_expiry_daemon_background_sweep():
    aid = log_pending_action("bash", "npm publish --force", "HIGH", session_id="sess_daemon", tool_use_id="tu_d")
    _backdate_action(aid, 2.0)

    # Start worker with 1.0s timeout and 0.1s interval
    worker = ApprovalExpiryWorker(interval_seconds=0.1, timeout_seconds=1.0)
    worker.start(initial_sweep=False)

    try:
        # Give worker a brief moment to sweep
        time.sleep(0.3)
        updated = get_action(aid)
        assert updated["status"] == "stale"
    finally:
        worker.stop()


def test_restart_safety():
    # Simulate action left pending across application restart
    aid = log_pending_action("bash", "shutdown /r /t 0", "HIGH", session_id="sess_restart", tool_use_id="tu_r")
    _backdate_action(aid, 400.0)

    # Initial state is still recorded as pending in DB
    with _connect() as conn:
        row = conn.execute("SELECT status FROM actions WHERE id=?", (aid,)).fetchone()
        assert row[0] == "pending"

    # Simulate new process startup initializing worker with default initial_sweep=True
    worker = ApprovalExpiryWorker(interval_seconds=10.0, timeout_seconds=300.0)
    worker.start(initial_sweep=True)
    try:
        updated = get_action(aid)
        assert updated["status"] == "stale"

        # Subsequent approval must be refused
        assert decide_action(aid, "approved") is False
    finally:
        worker.stop()


def test_hash_chain_continuity_after_expiry(tmp_path):
    aid = log_pending_action("bash", "format C:", "CRITICAL", session_id="sess_chain", tool_use_id="tu_c")
    _backdate_action(aid, 350.0)
    expire_stale_actions(timeout_seconds=300.0)

    # Check that global chain integrity passes
    from storage.db import DB_PATH
    manager = JournalManager(db_path=DB_PATH, drop_dir=str(tmp_path / "journal_drop"))
    report = manager.verify_chain_integrity()
    assert report.is_valid is True
    assert report.total_events > 0
