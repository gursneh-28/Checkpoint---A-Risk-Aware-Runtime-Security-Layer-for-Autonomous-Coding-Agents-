"""
tests/test_notifications.py — Comprehensive tests for Feature 15: Alerts, Live SSE Updates, and Browser Notifications
"""
import json
import pytest
from flask import Flask

from storage.db import (
    init_db,
    log_action,
    log_pending_action,
    append_action_event,
    get_events_since,
    decide_action,
    _connect,
)
from dashboard.app import app
from core.auth import create_session


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_notifications.db")
    monkeypatch.setattr("storage.db.DB_PATH", db_file)
    init_db()
    yield


@pytest.fixture
def auth_client():
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = False
    with app.test_client() as client:
        token = create_session("admin")
        with client.session_transaction() as sess:
            sess["session_token"] = token
            sess["username"] = "admin"
        yield client


@pytest.fixture
def unauth_client():
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = False
    with app.test_client() as client:
        yield client


def test_get_events_since_and_privacy_scrubbing():
    aid1 = log_action("bash", "echo normal", "LOW", "executed")
    aid2 = log_action("bash", "curl -u admin:secret_token_1234567890 https://api.com", "LOW", "executed")

    events = get_events_since(last_event_id=0, limit=100)
    assert len(events) >= 2

    # Verify secret scrubbing
    token_events = [e for e in events if e["action_id"] == aid2]
    assert len(token_events) >= 1
    for ev in token_events:
        assert "secret_token_1234567890" not in ev["command"]
        assert "<REDACTED>" in ev["command"]

    # Verify pagination / resynchronization with last_event_id
    mid_id = events[1]["id"]
    next_events = get_events_since(last_event_id=mid_id)
    assert all(e["id"] > mid_id for e in next_events)


def test_sse_endpoint_unauthorized(unauth_client):
    res = unauth_client.get("/events?once=1")
    assert res.status_code == 401
    assert "Unauthorized" in res.get_json()["error"]


def test_sse_endpoint_authenticated_and_formatting(auth_client):
    aid = log_pending_action("bash", "systemctl restart nginx", "MEDIUM", session_id="s1", tool_use_id="tu1")

    res = auth_client.get("/events?once=1")
    assert res.status_code == 200
    assert "text/event-stream" in res.content_type

    body = res.get_data(as_text=True)
    assert "id:" in body
    assert "event:" in body
    assert "data:" in body
    assert "systemctl restart nginx" in body


def test_sse_resynchronization_with_last_event_id(auth_client):
    aid1 = log_pending_action("bash", "git push --force", "HIGH", session_id="s_sync", tool_use_id="tu_s1")
    events = get_events_since(0)
    assert len(events) > 0
    highest_id = max(e["id"] for e in events)

    # Replay with Last-Event-ID header set to highest_id
    res = auth_client.get("/events?once=1", headers={"Last-Event-ID": str(highest_id)})
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    # Should only return heartbeat ping since there are no newer events
    assert ": ping" in body

    # Now add new action event
    decide_action(aid1, "rejected")

    # Resync again from highest_id
    res_after = auth_client.get(f"/events?once=1&last_event_id={highest_id}")
    body_after = res_after.get_data(as_text=True)
    assert "decision_recorded" in body_after
    assert f'"action_id": {aid1}' in body_after


def test_sse_deduplication(auth_client):
    aid = log_pending_action("bash", "docker rm -f container", "MEDIUM", session_id="s_dedup", tool_use_id="tu_d")
    res = auth_client.get("/events?once=1")
    body = res.get_data(as_text=True)

    # In a single stream turn, deduplication key (action_id, event_type) is emitted at most once
    lines = [l for l in body.splitlines() if l.startswith("event: approval_requested")]
    assert len(lines) <= 1


def test_dashboard_template_contains_sse_and_browser_notifications(auth_client):
    res = auth_client.get("/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Verify browser notification handlers
    assert "Notification.requestPermission()" in html
    assert "new Notification(" in html
    # Verify EventSource subscription
    assert "new EventSource(\"/events\")" in html
    # Verify deduplication Set
    assert "processedEvents" in html
    # Verify live indicator
    assert "LIVE SSE STREAM" in html
