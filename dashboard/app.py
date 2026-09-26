import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, redirect, url_for
from storage.db import get_all_actions, init_db, set_action_status

app = Flask(__name__)


@app.route("/")
def dashboard():
    init_db()
    raw_rows = get_all_actions()

    actions = []
    for row in raw_rows:
        actions.append({
            "id": row[0],
            "timestamp": row[1],
            "action_type": row[2],
            "command": row[3],
            "risk_tier": row[4],
            "status": row[5],
        })

    return render_template("index.html", actions=actions)


@app.route("/resolve/<int:action_id>/<decision>")
def resolve(action_id, decision):
    if decision == "approve":
        set_action_status(action_id, "approved")
    elif decision == "reject":
        set_action_status(action_id, "rejected")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)