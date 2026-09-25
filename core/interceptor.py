import subprocess
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage.db import init_db
from core.risk_classifier import classify_risk, classify_git_op
from core.confirmation import resolve_action


def intercept_and_run(command: str):
    if command.strip().startswith("git "):
        risk_tier = classify_git_op(command)
        action_type = "git"
    else:
        risk_tier = classify_risk(command)
        action_type = "shell"

    def execute():
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"[Checkpoint] STDERR: {result.stderr}")

        if result.returncode != 0:
            print(f"[Checkpoint] WARNING: command exited with code {result.returncode} (it may have failed).")

        # Combine both so the DB log shows the full picture, not just stdout
        combined = f"stdout: {result.stdout}\nstderr: {result.stderr}\nreturncode: {result.returncode}"
        return combined

    resolve_action(action_type, f"Intercepted: {command}", risk_tier, execute)


if __name__ == "__main__":
    init_db()

    intercept_and_run("echo Hello from inside Checkpoint")     # LOW -> auto
    intercept_and_run("git commit -m 'test commit'")             # LOW -> auto
    intercept_and_run("git push --force origin main")           # HIGH -> asks you