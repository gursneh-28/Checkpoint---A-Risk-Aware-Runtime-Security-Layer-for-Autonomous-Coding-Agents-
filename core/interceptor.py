import subprocess
import sys
import os
import shutil

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage.db import init_db
from core.risk_classifier import classify_risk, classify_git_op
from core.confirmation import resolve_action
from core.suggestions import suggest_alternative, move_to_trash


def _run(command: str):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(f"[Checkpoint] STDERR: {result.stderr}")
    if result.returncode != 0:
        print(f"[Checkpoint] WARNING: command exited with code {result.returncode} (it may have failed).")

    return f"stdout: {result.stdout}\nstderr: {result.stderr}\nreturncode: {result.returncode}"


def _trash_paths(paths):
    moved = []
    for p in paths:
        if os.path.exists(p):
            moved.append(f"{p} -> {move_to_trash(p)}")
        else:
            moved.append(f"{p} (not found, skipped)")
    return "moved to trash: " + "; ".join(moved)


def intercept_and_run(command: str):
    if command.strip().startswith("git "):
        risk_tier = classify_git_op(command)
        action_type = "git"
    else:
        risk_tier = classify_risk(command)
        action_type = "shell"

    suggestion = suggest_alternative(command)
    alternative_fn = None
    if suggestion:
        if suggestion["kind"] == "command":
            safer = suggestion["command"]
            alternative_fn = lambda: _run(safer)
        elif suggestion["kind"] == "trash":
            paths = suggestion["paths"]
            alternative_fn = lambda: _trash_paths(paths)

    resolve_action(action_type, f"Intercepted: {command}", risk_tier,
                   lambda: _run(command),
                   suggestion=suggestion, alternative_fn=alternative_fn)


if __name__ == "__main__":
    init_db()

    intercept_and_run("echo Hello from inside Checkpoint")     # LOW -> auto
    intercept_and_run("git commit -m 'test commit'")             # LOW -> auto
    intercept_and_run("git push --force origin main")           # HIGH -> offers --force-with-lease