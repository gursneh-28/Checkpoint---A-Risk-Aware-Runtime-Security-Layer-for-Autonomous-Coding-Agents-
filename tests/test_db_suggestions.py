import os
import sqlite3
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import storage.db as db

SUGGESTION = {"kind": "command", "text": "Use --force-with-lease",
              "command": "git push --force-with-lease origin dev"}


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    return db


def test_suggestion_is_stored_and_read_back(fresh_db):
    action_id = fresh_db.log_pending_action("shell", "git push --force origin dev", "HIGH", SUGGESTION)
    assert fresh_db.get_action_suggestion(action_id) == SUGGESTION


def test_action_without_suggestion_returns_none(fresh_db):
    action_id = fresh_db.log_pending_action("shell", "rm -rf build/", "HIGH")
    assert fresh_db.get_action_suggestion(action_id) is None


def test_alternative_decision_works_when_suggestion_exists(fresh_db):
    action_id = fresh_db.log_pending_action("shell", "git push --force origin dev", "HIGH", SUGGESTION)
    assert fresh_db.decide_action(action_id, "alternative") is True
    assert fresh_db.get_action_status(action_id) == "alternative"


def test_alternative_is_refused_without_a_suggestion(fresh_db):
    action_id = fresh_db.log_pending_action("shell", "chmod 777 x", "HIGH")
    assert fresh_db.decide_action(action_id, "alternative") is False
    assert fresh_db.get_action_status(action_id) == "pending"


def test_decided_action_cannot_be_flipped_to_alternative(fresh_db):
    action_id = fresh_db.log_pending_action("shell", "git push -f origin dev", "HIGH", SUGGESTION)
    assert fresh_db.decide_action(action_id, "rejected") is True
    assert fresh_db.decide_action(action_id, "alternative") is False
    assert fresh_db.get_action_status(action_id) == "rejected"


def test_second_alternative_click_is_ignored(fresh_db):
    action_id = fresh_db.log_pending_action("shell", "git push -f origin dev", "HIGH", SUGGESTION)
    assert fresh_db.decide_action(action_id, "alternative") is True
    assert fresh_db.decide_action(action_id, "approved") is False
    assert fresh_db.get_action_status(action_id) == "alternative"


def test_unknown_decision_is_rejected(fresh_db):
    action_id = fresh_db.log_pending_action("shell", "rm x", "MEDIUM")
    assert fresh_db.decide_action(action_id, "hack") is False
    assert fresh_db.get_action_status(action_id) == "pending"


def test_old_database_without_suggestion_column_is_upgraded(tmp_path, monkeypatch):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        action_type TEXT NOT NULL, command TEXT NOT NULL,
        risk_tier TEXT NOT NULL, status TEXT NOT NULL, output TEXT)""")
    conn.commit()
    conn.close()

    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()

    conn = sqlite3.connect(path)
    columns = [r[1] for r in conn.execute("PRAGMA table_info(actions)")]
    conn.close()
    assert "suggestion" in columns