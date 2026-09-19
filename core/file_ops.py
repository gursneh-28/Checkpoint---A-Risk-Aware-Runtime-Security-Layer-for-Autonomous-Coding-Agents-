import os
import shutil
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage.db import log_action
from core.risk_classifier import classify_file_op


def intercept_create(path: str, content: str = ""):
    action_desc = f"CREATE {path}"
    tier = classify_file_op("create", path)
    print(f"[Checkpoint] {action_desc} — risk tier: {tier}")

    if tier == "LOW":
        with open(path, "w") as f:
            f.write(content)
        log_action("file", action_desc, tier, "executed")
        print("Executed.")
    else:
        log_action("file", action_desc, tier, "blocked")
        print(f"Blocked — tier {tier} requires confirmation (not yet implemented).")


def intercept_write(path: str, content: str):
    action_desc = f"WRITE {path}"
    tier = classify_file_op("write", path)
    print(f"[Checkpoint] {action_desc} — risk tier: {tier}")

    if tier == "LOW":
        with open(path, "a") as f:
            f.write(content)
        log_action("file", action_desc, tier, "executed")
        print("Executed.")
    else:
        log_action("file", action_desc, tier, "blocked")
        print(f"Blocked — tier {tier} requires confirmation (not yet implemented).")


def intercept_delete(path: str):
    action_desc = f"DELETE {path}"
    tier = classify_file_op("delete", path)
    print(f"[Checkpoint] {action_desc} — risk tier: {tier}")

    if tier == "LOW":
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        log_action("file", action_desc, tier, "executed")
        print("Executed.")
    else:
        log_action("file", action_desc, tier, "blocked")
        print(f"Blocked — tier {tier} requires confirmation (not yet implemented).")


def intercept_move(src: str, dst: str):
    action_desc = f"MOVE {src} -> {dst}"
    tier = classify_file_op("move", src)
    print(f"[Checkpoint] {action_desc} — risk tier: {tier}")

    if tier == "LOW":
        shutil.move(src, dst)
        log_action("file", action_desc, tier, "executed")
        print("Executed.")
    else:
        log_action("file", action_desc, tier, "blocked")
        print(f"Blocked — tier {tier} requires confirmation (not yet implemented).")


if __name__ == "__main__":
    # Quick manual test
    intercept_create("test_file.txt", "hello from checkpoint\n")
    intercept_write("test_file.txt", "second line\n")
    intercept_delete("test_file.txt")