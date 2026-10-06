import sys
import os
import secrets
import json

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, redirect, url_for, session, request, abort
from storage.db import get_all_actions, init_db, set_action_status, get_all_checkpoints, decide_action
from core.sandbox import rollback_checkpoint

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
    decide_action(action_id, DECISIONS[decision])
    return redirect(url_for("dashboard"))

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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)