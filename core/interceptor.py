import subprocess
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage.db import init_db, log_action
from core.risk_classifier import classify_risk, classify_git_op


def intercept_and_run(command: str):
    # Route git commands through the git-specific classifier
    if command.strip().startswith("git "):
        risk_tier = classify_git_op(command)
        action_type = "git"
    else:
        risk_tier = classify_risk(command)
        action_type = "shell"

    print(f"[Checkpoint] Intercepted: {command}")
    print(f"[Checkpoint] Risk tier: {risk_tier}")

    if risk_tier == "LOW":
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(result.stdout)
        log_action(action_type, command, risk_tier, "executed", result.stdout)
    else:
        print(f"[Checkpoint] BLOCKED — tier {risk_tier} requires confirmation (not yet implemented).")
        log_action(action_type, command, risk_tier, "blocked")


if __name__ == "__main__":
    init_db()  # ensure the DB/table exist before logging anything

    intercept_and_run("echo Hello from inside Checkpoint")
    intercept_and_run("git commit -m 'test commit'")
    intercept_and_run("git push --force origin main")