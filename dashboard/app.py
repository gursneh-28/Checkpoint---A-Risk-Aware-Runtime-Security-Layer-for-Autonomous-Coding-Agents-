import sys
import os
import secrets
import json

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
)
from core.sandbox import rollback_checkpoint
from core.session_summary import generate_session_summary, format_session_summary_markdown
from storage.export import export_audit_log

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

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


@app.route("/")
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
def resolve(action_id, decision):
    check_csrf()
    if decision not in DECISIONS:
        abort(400)
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
def alerts_list():
    """View alerts history and delivery statuses."""
    init_db()
    pending_only = request.args.get("pending", "0") == "1"
    alerts = get_alerts(pending_only=pending_only)
    return jsonify({"alerts": alerts})


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