import os
import sys
import threading
import time

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import storage.db as db
import core.confirmation as conf

SUGGESTION = {"kind": "command", "text": "Use the safer version", "command": "safer"}


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(conf, "POLL_INTERVAL_SECONDS", 0.01)
    db.init_db()


def _decide_later(decision, delay=0.1):
    def run():
        time.sleep(delay)
        action_id = db.get_all_actions()[0][0]
        db.decide_action(action_id, decision)
    t = threading.Thread(target=run)
    t.start()
    return t


def _run(risk="HIGH", suggestion=SUGGESTION, with_alt=True):
    calls = []
    result = conf.resolve_action(
        "shell", "test action", risk,
        lambda: calls.append("original") or "orig-out",
        suggestion=suggestion,
        alternative_fn=(lambda: calls.append("alternative") or "alt-out") if with_alt else None,
    )
    return result, calls


def test_low_risk_runs_immediately(fresh):
    result, calls = _run(risk="LOW")
    assert result is True and calls == ["original"]


def test_approve_runs_only_the_original(fresh):
    t = _decide_later("approved")
    result, calls = _run()
    t.join()
    assert result is True and calls == ["original"]
    assert db.get_all_actions()[0][5] == "executed"


def test_reject_runs_nothing(fresh):
    t = _decide_later("rejected")
    result, calls = _run()
    t.join()
    assert result is False and calls == []
    assert db.get_all_actions()[0][5] == "rejected"


def test_alternative_runs_only_the_safer_action(fresh):
    t = _decide_later("alternative")
    result, calls = _run()
    t.join()
    assert result is True and calls == ["alternative"]
    row = db.get_all_actions()[0]
    assert row[5] == "executed-alternative" and row[6] == "alt-out"


def test_suggestion_without_a_runnable_alternative_is_not_stored(fresh):
    t = _decide_later("rejected")
    _run(with_alt=False)
    t.join()
    action_id = db.get_all_actions()[0][0]
    assert db.get_action_suggestion(action_id) is None