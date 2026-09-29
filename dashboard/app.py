import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, redirect, url_for
from storage.db import get_all_actions, init_db, set_action_status, get_all_checkpoints
from core.sandbox import rollback_checkpoint

app = Flask(__name__)


@app.route("/")
def dashboard():
    init_db()
    raw_rows = get_all_actions()
    actions = []
    for row in raw_rows:
        actions.append({
            "id": row[0], "timestamp": row[1], "action_type": row[2],
            "command": row[3], "risk_tier": row[4], "status": row[5],
        })
    return render_template("index.html", actions=actions)


@app.route("/resolve/<int:action_id>/<decision>")
def resolve(action_id, decision):
    if decision == "approve":
        set_action_status(action_id, "approved")
    elif decision == "reject":
        set_action_status(action_id, "rejected")
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


@app.route("/rollback/<int:checkpoint_id>")
def rollback(checkpoint_id):
    success, message = rollback_checkpoint(checkpoint_id)
    return render_template("rollback_result.html", success=success, message=message)


if __name__ == "__main__":
    app.run(debug=True, port=5000)