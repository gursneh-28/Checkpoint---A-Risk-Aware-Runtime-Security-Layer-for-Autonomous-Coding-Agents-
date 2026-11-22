import sys
import os
import secrets
import json
import time
from functools import wraps

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, redirect, url_for, session, request, abort, jsonify, Response
from storage.db import (
    get_all_actions,
    init_db,
    set_action_status,
    get_all_checkpoints,
    decide_action,
    flag_action,
    list_flagged_actions,
    review_flag,
    export_flagged_dataset,
    get_alerts,
    get_events_since,
)
from core.sandbox import rollback_checkpoint
from core.session_summary import generate_session_summary, format_session_summary_markdown
from storage.export import export_audit_log
from core.auth import (
    get_signing_key,
    rotate_signing_key,
    validate_request_host,
    validate_request_origin,
    verify_user,
    create_session,
    validate_session,
    invalidate_session,
    invalidate_all_sessions_for_user,
    check_login_rate_limit,
    reset_login_rate_limit,
    can_approve_critical,
    init_auth_tables,
)

app = Flask(__name__)
# Persistent signing key stored outside project repository
app.secret_key = get_signing_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"


# ---------------------------------------------------------------------------
# Host and Origin Validation (DNS rebinding and Cross-Site defense)
# ---------------------------------------------------------------------------

@app.before_request
def validate_security_headers():
    # 1. Strict Host validation
    if not validate_request_host(request.host):
        abort(400, description="Invalid Host header")

    # 2. Strict Origin/Referer validation for mutating requests
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin and not validate_request_origin(origin):
            abort(403, description="Invalid Origin or Referer")


# ---------------------------------------------------------------------------
# CSRF and Session Authentication
# ---------------------------------------------------------------------------

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=get_csrf_token)

def check_csrf():
    token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    if not session_token or not secrets.compare_digest(token.encode(), session_token.encode()):
        abort(403)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if app.config.get("LOGIN_DISABLED"):
            return f(*args, **kwargs)
        token = session.get("session_token")
        username = validate_session(token)
        if not username:
            if request.path.startswith(("/action/", "/session/", "/export", "/flags", "/alerts", "/resolve", "/rollback", "/events")):
                return jsonify({"error": "Unauthorized. Please log in."}), 401
            return redirect(url_for("login_view", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def check_hook_token_not_approving():
    """Ensure agent hook credentials CANNOT approve or modify actions."""
    hook_token = request.headers.get("X-Checkpoint-Hook-Token")
    if hook_token:
        abort(403, description="Hook credentials are strictly forbidden from approving or resolving actions")


# ---------------------------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login_view():
    init_auth_tables()
    if request.method == "GET":
        return render_template("login.html", error=None)

    client_ip = request.remote_addr or "127.0.0.1"
    if not check_login_rate_limit(client_ip):
        abort(429, description="Too many login attempts. Please wait 60 seconds.")

    check_csrf()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not verify_user(username, password):
        return render_template("login.html", error="Invalid username or password"), 401

    reset_login_rate_limit(client_ip)
    token = create_session(username)
    session["session_token"] = token
    session["username"] = username
    next_url = request.args.get("next") or url_for("dashboard")
    return redirect(next_url)


@app.route("/logout", methods=["POST"])
def logout_view():
    check_csrf()
    token = session.get("session_token")
    if token:
        invalidate_session(token)
    session.clear()
    return redirect(url_for("login_view"))


@app.route("/rotate-key", methods=["POST"])
@login_required
def rotate_key_view():
    check_csrf()
    new_key = rotate_signing_key()
    app.secret_key = new_key
    username = session.get("username")
    if username:
        invalidate_all_sessions_for_user(username)
    session.clear()
    return jsonify({"success": True, "message": "Signing key rotated successfully. Please log in again."})


# ---------------------------------------------------------------------------
# Main Dashboard & Resolution
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    init_db()
    raw_rows = get_all_actions()
    actions = []
    for row in raw_rows:
        suggestion = json.loads(row[7]) if len(row) > 7 and row[7] else None
        actions.append({
            "id": row[0], "timestamp": row[1], "action_type": row[2],
            "command": row[3], "risk_tier": row[4], "status": row[5],
            "suggestion": suggestion["text"] if suggestion else None,
        })
    return render_template("index.html", actions=actions)


DECISIONS = {"approve": "approved", "reject": "rejected", "alternative": "alternative"}


@app.route("/resolve/<int:action_id>/<decision>", methods=["POST"])
@login_required
def resolve(action_id, decision):
    check_hook_token_not_approving()
    check_csrf()
    if decision not in DECISIONS:
        abort(400)

    # Check CRITICAL tier approval restriction
    if decision == "approve":
        actions = get_all_actions()
        action_row = next((r for r in actions if r[0] == action_id), None)
        if action_row:
            eff = action_row[11] if len(action_row) > 11 else ""
            base = action_row[4] if len(action_row) > 4 else ""
            if eff == "CRITICAL" or base == "CRITICAL":
                allowed, reason = can_approve_critical()
                if not allowed:
                    abort(403, description=reason)

    typed = request.form.get("typed_confirmation")
    success = decide_action(action_id, DECISIONS[decision], typed_confirmation=typed)
    if not success and decision == "approve":
        actions = get_all_actions()
        action_row = next((r for r in actions if r[0] == action_id), None)
        if action_row:
            eff = action_row[11] if len(action_row) > 11 else ""
            base = action_row[4] if len(action_row) > 4 else ""
            if eff == "CRITICAL" or base == "CRITICAL":
                abort(400)
    return redirect(url_for("dashboard"))


@app.route("/action/<int:action_id>")
def action_detail(action_id):
    init_db()
    actions = get_all_actions()
    action_row = next((r for r in actions if r[0] == action_id), None)
    if not action_row:
        abort(404)
    suggestion = json.loads(action_row[7]) if len(action_row) > 7 and action_row[7] else None
    return {
        "id": action_row[0],
        "timestamp": action_row[1],
        "action_type": action_row[2],
        "command": action_row[3],
        "risk_tier": action_row[4],
        "status": action_row[5],
        "suggestion": suggestion["text"] if suggestion else None,
        "effective_tier": action_row[11] if len(action_row) > 11 else action_row[4],
        "preview_hash": action_row[12] if len(action_row) > 12 else "",
    }

@app.route("/checkpoints")
def checkpoints():
    init_db()
    raw_rows = get_all_checkpoints()
    checkpoint_list = []
    for row in raw_rows:
        checkpoint_list.append({
            "id": row[0], "timestamp": row[1], "file_path": row[2],
            "snapshot_path": row[3], "description": row[4],
        })
    return render_template("checkpoints.html", checkpoints=checkpoint_list)


@app.route("/rollback/<int:checkpoint_id>", methods=["POST"])
def rollback(checkpoint_id):
    check_csrf()
    success, message = rollback_checkpoint(checkpoint_id)
    return render_template("rollback_result.html", success=success, message=message)


# ---------------------------------------------------------------------------
# Feature 14: Feedback & Wrong-Rating Queue Endpoints
# ---------------------------------------------------------------------------

@app.route("/flag/<int:action_id>", methods=["POST"])
def flag(action_id):
    """Flag an action's risk rating for human review."""
    check_csrf()
    reason = request.form.get("reason", "").strip()
    correct_tier = request.form.get("correct_tier", "").strip()
    notes = request.form.get("notes", "").strip()
    if not reason:
        abort(400)
    flag_id = flag_action(action_id, reason=reason, correct_tier=correct_tier, notes=notes)
    return jsonify({"success": True, "flag_id": flag_id})


@app.route("/flags")
def flags_queue():
    """List flagged actions in the review queue."""
    init_db()
    unreviewed_only = request.args.get("unreviewed", "1") == "1"
    flags = list_flagged_actions(unreviewed_only=unreviewed_only)
    return jsonify({"flags": flags})


@app.route("/flags/<int:flag_id>/resolve", methods=["POST"])
def resolve_flag(flag_id):
    """Review and resolve a flagged action."""
    check_csrf()
    resolution = request.form.get("resolution", "").strip()
    reviewer_notes = request.form.get("reviewer_notes", "").strip()
    corrected_tier = request.form.get("corrected_tier", "").strip() or None
    try:
        success = review_flag(
            flag_id=flag_id,
            resolution=resolution,
            corrected_tier=corrected_tier,
            reviewer_notes=reviewer_notes,
        )
    except ValueError:
        abort(400)
    if not success:
        abort(404)
    return jsonify({"success": True, "flag_id": flag_id, "resolution": resolution})


@app.route("/flags/export")
def export_flags():
    """Export reviewed flags as labeled calibration dataset."""
    init_db()
    dataset = export_flagged_dataset()
    return jsonify({"dataset": dataset})


# ---------------------------------------------------------------------------
# Feature 15: Alerts Endpoint
# ---------------------------------------------------------------------------

@app.route("/alerts")
@login_required
def alerts_list():
    """View alerts history and delivery statuses."""
    init_db()
    pending_only = request.args.get("pending", "0") == "1"
    alerts = get_alerts(pending_only=pending_only)
    return jsonify({"alerts": alerts})


@app.route("/events")
@login_required
def event_stream():
    """
    Feature 15: Live SSE endpoint for dashboard updates and browser notifications.
    Supports Last-Event-ID header and last_event_id query parameter for full resynchronization.
    Yields events in text/event-stream format:
      id: <event_id>
      event: <event_type>
      data: <json_data>
    """
    init_db()
    last_id = 0
    header_id = request.headers.get("Last-Event-ID")
    if header_id and header_id.isdigit():
        last_id = int(header_id)
    elif request.args.get("last_event_id", "").isdigit():
        last_id = int(request.args.get("last_event_id"))

    once = request.args.get("once", "0") == "1"

    def generate(start_id: int):
        current_id = start_id
        seen_events = set()
        iterations = 0
        max_iterations = 1 if once else 120
        while iterations < max_iterations:
            events = get_events_since(current_id, limit=50)
            if events:
                for ev in events:
                    ev_id = ev["id"]
                    dedup_key = (ev["action_id"], ev["event_type"])
                    if dedup_key in seen_events:
                        continue
                    seen_events.add(dedup_key)
                    current_id = max(current_id, ev_id)
                    data_json = json.dumps(ev)
                    yield f"id: {ev_id}\nevent: {ev['event_type']}\ndata: {data_json}\n\n"
            else:
                yield ": ping\n\n"
            if once:
                break
            time.sleep(0.5)
            iterations += 1

    return Response(
        generate(last_id),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


# ---------------------------------------------------------------------------
# Feature 16: Session Summaries & Audit Export Endpoints
# ---------------------------------------------------------------------------

@app.route("/session/<session_id>/summary")
def session_summary(session_id):
    """Get aggregated metrics and markdown summary for a session."""
    init_db()
    fmt = request.args.get("format", "json").lower()
    summary = generate_session_summary(session_id)
    if fmt == "markdown" or fmt == "md":
        md = format_session_summary_markdown(summary)
        return Response(md, mimetype="text/markdown")
    return jsonify(summary)


@app.route("/export")
def export_audit():
    """Export audit log in JSON or CSV with formula-injection defense."""
    init_db()
    fmt = request.args.get("format", "json").lower()
    session_id = request.args.get("session_id", "").strip() or None
    try:
        content = export_audit_log(session_id=session_id, format=fmt)
    except ValueError as e:
        abort(400, description=str(e))

    if fmt == "csv":
        filename = f"checkpoint_audit_{session_id or 'all'}.csv"
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    else:
        filename = f"checkpoint_audit_{session_id or 'all'}.json"
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)