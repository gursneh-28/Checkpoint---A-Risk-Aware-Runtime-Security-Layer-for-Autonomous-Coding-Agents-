import pytest

from core.event_types import Event, DecisionKind, RiskTier
from core.pipeline import evaluate
from core import anomaly
from storage.db import init_db, is_session_paused, pause_session


@pytest.fixture
def clean_pipeline_env(tmp_path, monkeypatch):
    db_file = tmp_path / "pipeline_test.db"
    monkeypatch.setattr("storage.db.DB_PATH", str(db_file))
    init_db()
    # Reset detector sessions
    anomaly._detector._sessions.clear()
    return str(db_file)


def test_circuit_breaker_trips_on_high_risk_burst(clean_pipeline_env):
    session_id = "sess_burst"

    # Record 5 high risk events
    for _ in range(5):
        anomaly.post_decision(
            Event(session_id=session_id, tool_use_id="t1", tool_name="Bash", command="rm -rf tmp"),
            effective_tier=RiskTier.HIGH,
            rejected=False,
        )

    tripped, reason = anomaly.check_circuit_breaker(session_id)
    assert tripped is True
    assert "burst threshold exceeded" in reason


def test_circuit_breaker_trips_on_repeated_rejection(clean_pipeline_env):
    session_id = "sess_repeat"
    bad_cmd = "git reset --hard HEAD~1"

    # Reject 3 times
    for _ in range(3):
        anomaly.post_decision(
            Event(session_id=session_id, tool_use_id="t1", tool_name="Bash", command=bad_cmd),
            effective_tier=RiskTier.HIGH,
            rejected=True,
        )

    tripped, reason = anomaly.check_circuit_breaker(session_id)
    assert tripped is True
    assert "repeated retry of rejected command" in reason


def test_circuit_breaker_trips_on_low_quota_headroom(clean_pipeline_env):
    session_id = "sess_quota"
    tripped, reason = anomaly.check_circuit_breaker(session_id, quota_headroom_pct=3.5)
    assert tripped is True
    assert "quota headroom critically low" in reason


def test_pipeline_blocks_low_risk_when_session_is_paused(clean_pipeline_env):
    session_id = "sess_paused_test"
    pause_session(session_id, "Admin investigation")
    assert is_session_paused(session_id) is True

    # Attempt a safe LOW command
    ev = Event(
        session_id=session_id,
        tool_use_id="call_low",
        tool_name="Bash",
        command="ls -la",
    )
    decision = evaluate(ev)
    assert decision.kind == DecisionKind.DENY
    assert "PAUSED" in decision.reason


def test_pipeline_fast_path_instant_run_when_unpaused(clean_pipeline_env):
    session_id = "sess_active_test"
    ev = Event(
        session_id=session_id,
        tool_use_id="call_active",
        tool_name="Bash",
        command="cat notes.txt",
    )
    decision = evaluate(ev)
    assert decision.kind == DecisionKind.ALLOW
    assert decision.effective_tier == RiskTier.LOW
    assert "instant-run approved" in decision.reason


def test_out_of_scope_directory_escalation(clean_pipeline_env, tmp_path):
    project_dir = str(tmp_path / "my_project")
    anomaly.set_project_root(project_dir)

    ev = Event(
        session_id="sess_scope",
        tool_use_id="call_scope",
        tool_name="Bash",
        command="rm file.txt",
        cwd="C:\\Windows\\System32",
    )
    signal = anomaly.get_signal(ev, RiskTier.MEDIUM)
    assert signal.triggered is True
    assert signal.kind == "out_of_scope"
