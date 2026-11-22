"""
tests/test_milestone4.py — Test Suite for Milestone 4 (Features 14, 15, 16)

Tests:
- Feature 14: Feedback & Wrong-Rating Queue (flagging, review workflow, immutable audit, calibration dataset export)
- Feature 15: Alerts & Notifications (webhook formatting, desktop rate-limiting, DB delivery tracking)
- Feature 16: Session Summaries & Audit Export (metrics aggregation, markdown report, CSV formula-injection defense)
- Dashboard routes for flags, alerts, session summaries, and CSV/JSON export
"""

import csv
import io
import json
import pytest

import storage.db
from core.alerts import (
    AlertChannel,
    DesktopNotifier,
    dispatch_alerts,
    format_webhook_payload,
)
from core.session_summary import (
    format_session_summary_markdown,
    generate_session_summary,
)
from dashboard.app import app
from storage.export import (
    export_audit_csv,
    export_audit_json,
    export_audit_log,
    sanitize_csv_cell,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_m4.db"
    monkeypatch.setattr(storage.db, "DB_PATH", str(test_db))
    storage.db.init_db()
    return test_db


@pytest.fixture
def client(db):
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def set_csrf(client, token="test_csrf_token"):
    with client.session_transaction() as sess:
        sess["csrf_token"] = token
    return token


# ===========================================================================
# Feature 14: Feedback & Wrong-Rating Queue Tests
# ===========================================================================

def test_flag_action_and_review_workflow(db):
    action_id = storage.db.log_pending_action(
        "bash", "rm -rf /tmp/cache", "HIGH",
        session_id="sess-feedback-1", tool_use_id="tool-fb-1"
    )

    # 1. User flags action rating
    flag_id = storage.db.flag_action(
        action_id=action_id,
        reason="Should be LOW because /tmp/cache is safe to clear",
        correct_tier="LOW",
        notes="Developer confirms temporary folder",
    )
    assert flag_id > 0

    # 2. Check flagged actions list
    flags = storage.db.list_flagged_actions(unreviewed_only=True)
    assert len(flags) == 1
    f = flags[0]
    assert f["flag_id"] == flag_id
    assert f["action_id"] == action_id
    assert f["reason"] == "Should be LOW because /tmp/cache is safe to clear"
    assert f["correct_tier"] == "LOW"
    assert f["reviewed"] is False

    # 3. Review the flag
    success = storage.db.review_flag(
        flag_id=flag_id,
        resolution="reviewed_approved",
        corrected_tier="LOW",
        reviewer_notes="Agreed; added rule refinement to backlog",
    )
    assert success is True

    # 4. Invariant: Original action's decision and tier remain intact in actions table
    action = storage.db.get_action(action_id)
    assert action["status"] == "pending"
    assert action["risk_tier"] == "HIGH"

    # 5. Check unreviewed queue is now empty
    unreviewed = storage.db.list_flagged_actions(unreviewed_only=True)
    assert len(unreviewed) == 0

    # 6. Check export of labeled dataset
    dataset = storage.db.export_flagged_dataset()
    assert len(dataset) == 1
    d = dataset[0]
    assert d["command"] == "rm -rf /tmp/cache"
    assert d["labeled_tier"] == "LOW"
    assert d["original_tier"] == "HIGH"


# ===========================================================================
# Feature 15: Alerts & Notifications Tests
# ===========================================================================

def test_webhook_payload_formatting(db):
    action_id = storage.db.log_pending_action(
        "bash", "git push --force origin main", "CRITICAL",
        session_id="sess-alert-1", preview_hash="hash1234"
    )
    action = storage.db.get_action(action_id)

    payload = format_webhook_payload(action, base_url="https://sec.local:8443")
    assert payload["event"] == "action.pending_approval"
    assert payload["action_id"] == action_id
    assert payload["command"] == "git push --force origin main"
    assert payload["risk_tier"] == "CRITICAL"
    assert payload["preview_hash"] == "hash1234"
    assert payload["approval_url"] == f"https://sec.local:8443/action/{action_id}"


def test_desktop_notifier_rate_limiting():
    notifier = DesktopNotifier(rate_limit_seconds=1.0)

    # First notification should succeed
    assert notifier.notify("Test Alert 1", "Message 1") is True

    # Immediate second notification should be throttled
    assert notifier.notify("Test Alert 2", "Message 2") is False

    assert len(notifier.notification_log) == 2
    assert notifier.notification_log[0]["status"] == "delivered"
    assert notifier.notification_log[1]["status"] == "throttled"


def test_dispatch_alerts(db):
    action_id = storage.db.log_pending_action(
        "bash", "sudo systemctl restart nginx", "HIGH"
    )
    notifier = DesktopNotifier(rate_limit_seconds=5.0)

    res = dispatch_alerts(
        action_id=action_id,
        channels=["webhook", "desktop"],
        notifier=notifier,
    )

    assert "channels" in res
    assert res["channels"]["webhook"]["status"] == "delivered"
    assert res["channels"]["desktop"]["status"] == "delivered"

    # Verify alerts table has 2 entries
    alerts = storage.db.get_alerts()
    assert len(alerts) == 2
    channels = {a["channel"] for a in alerts}
    assert channels == {"webhook", "desktop"}


# ===========================================================================
# Feature 16: Session Summaries & Audit Export Tests
# ===========================================================================

def test_session_summary_generation(db):
    sid = "sess-metrics-test"
    # Action 1: LOW executed
    a1 = storage.db.log_pending_action("bash", "ls -la", "LOW", session_id=sid)
    storage.db.set_action_status(a1, "executed")

    # Action 2: HIGH approved
    a2 = storage.db.log_pending_action("bash", "drop table users", "HIGH", session_id=sid)
    storage.db.set_action_status(a2, "approved")

    # Action 3: CRITICAL denied
    a3 = storage.db.log_pending_action("bash", "rm -rf /", "CRITICAL", session_id=sid)
    storage.db.set_action_status(a3, "rejected")

    summary = generate_session_summary(sid)
    assert summary["session_id"] == sid
    assert summary["total_actions"] == 3
    assert summary["tier_breakdown"]["LOW"] == 1
    assert summary["tier_breakdown"]["HIGH"] == 1
    assert summary["tier_breakdown"]["CRITICAL"] == 1
    assert summary["overall_safety_rating"] == "CRITICAL"

    md = format_session_summary_markdown(summary)
    assert f"# Checkpoint Session Summary: `{sid}`" in md
    assert "| `LOW` (Fast-Path) | 1 |" in md
    assert "| `CRITICAL` (Typed YES) | 1 |" in md


def test_csv_formula_injection_defense():
    """CWE-1236 CSV Formula Injection defense verification."""
    # Malicious inputs starting with =, +, -, @, \t, \r
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+2+3") == "'+2+3"
    assert sanitize_csv_cell("-4+5") == "'-4+5"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("\tCMD|' /C calc'!A0") == "'\tCMD|' /C calc'!A0"
    assert sanitize_csv_cell("\rCMD|' /C calc'!A0") == "'\rCMD|' /C calc'!A0"

    # Benign inputs must remain untouched
    assert sanitize_csv_cell("git commit -m 'initial'") == "git commit -m 'initial'"
    assert sanitize_csv_cell("ls -la") == "ls -la"
    assert sanitize_csv_cell(123) == "123"
    assert sanitize_csv_cell("") == ""
    assert sanitize_csv_cell(None) == ""


def test_audit_log_export_json_and_csv(db):
    sid = "sess-export-1"
    storage.db.log_pending_action("bash", "echo harmless", "LOW", session_id=sid)
    # Action with formula injection attempt
    storage.db.log_pending_action("bash", "=cmd|' /C calc'!A0", "HIGH", session_id=sid)

    # 1. Test JSON export
    json_out = export_audit_log(session_id=sid, format="json")
    data = json.loads(json_out)
    assert len(data) == 2
    assert data[0]["command"] == "echo harmless"
    assert data[1]["command"] == "=cmd|' /C calc'!A0"

    # 2. Test CSV export with formula sanitization
    csv_out = export_audit_log(session_id=sid, format="csv")
    reader = csv.DictReader(io.StringIO(csv_out))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["command"] == "echo harmless"
    # The cell must have leading single quote prepended
    assert rows[1]["command"] == "'=cmd|' /C calc'!A0"


# ===========================================================================
# Dashboard Endpoints Integration Tests
# ===========================================================================

def test_dashboard_flags_endpoints(client, db):
    action_id = storage.db.log_pending_action("bash", "touch file.txt", "MEDIUM")
    token = set_csrf(client, "valid_token")

    # POST /flag/<id>
    resp = client.post(
        f"/flag/{action_id}",
        data={"csrf_token": token, "reason": "Too strict", "correct_tier": "LOW", "notes": "Safe file"}
    )
    assert resp.status_code == 200
    flag_data = resp.get_json()
    assert flag_data["success"] is True
    flag_id = flag_data["flag_id"]

    # GET /flags
    resp_list = client.get("/flags")
    assert resp_list.status_code == 200
    flags = resp_list.get_json()["flags"]
    assert len(flags) == 1
    assert flags[0]["flag_id"] == flag_id

    # POST /flags/<id>/resolve
    resp_res = client.post(
        f"/flags/{flag_id}/resolve",
        data={"csrf_token": token, "resolution": "reviewed_approved", "reviewer_notes": "Confirmed"}
    )
    assert resp_res.status_code == 200
    assert resp_res.get_json()["success"] is True

    # GET /flags/export
    resp_exp = client.get("/flags/export")
    assert resp_exp.status_code == 200
    dataset = resp_exp.get_json()["dataset"]
    assert len(dataset) == 1
    assert dataset[0]["flag_id"] == flag_id


def test_dashboard_export_and_summary_endpoints(client, db):
    sid = "sess-dashboard-export"
    storage.db.log_pending_action("bash", "git status", "LOW", session_id=sid)

    # GET /session/<sid>/summary
    resp_sum = client.get(f"/session/{sid}/summary")
    assert resp_sum.status_code == 200
    data = resp_sum.get_json()
    assert data["session_id"] == sid
    assert data["total_actions"] == 1

    # GET /session/<sid>/summary?format=markdown
    resp_md = client.get(f"/session/{sid}/summary?format=markdown")
    assert resp_md.status_code == 200
    assert "text/markdown" in resp_md.content_type
    assert f"Session Summary: `{sid}`" in resp_md.get_data(as_text=True)

    # GET /export?format=csv
    resp_csv = client.get(f"/export?session_id={sid}&format=csv")
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.content_type
    assert "git status" in resp_csv.get_data(as_text=True)

    # GET /export?format=json
    resp_json = client.get(f"/export?session_id={sid}&format=json")
    assert resp_json.status_code == 200
    assert "application/json" in resp_json.content_type
    parsed = json.loads(resp_json.get_data(as_text=True))
    assert len(parsed) == 1
    assert parsed[0]["command"] == "git status"
