import os
import shutil
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.risk_classifier import classify_file_op
from core.confirmation import resolve_action
from core.sandbox import snapshot_file, diff_for_write, diff_for_delete, diff_for_move
from core.suggestions import move_to_trash


def intercept_create(path: str, content: str = ""):
    tier = classify_file_op("create", path)

    def execute():
        with open(path, "w") as f:
            f.write(content)
        # Snapshot AFTER creation too — this becomes the real "version 1"
        # checkpoint, so you can always get back to it later.
        snapshot_file(path, description=f"After creating {path}")
        return f"created {path}"

    resolve_action("file", f"CREATE {path}", tier, execute)


def intercept_write(path: str, content: str):
    tier = classify_file_op("write", path)

    def execute():
        snapshot_file(path, description=f"Before writing to {path}")
        with open(path, "a") as f:
            f.write(content)
        # Snapshot AFTER writing too — captures the resulting version, not
        # just the version right before this change. This is what makes the
        # LATEST state restorable too, not only earlier ones.
        snapshot_file(path, description=f"After writing to {path}")
        return f"wrote to {path}"

    description = f"WRITE {path}" if tier == "LOW" else diff_for_write(path, content)
    resolve_action("file", description, tier, execute)


def intercept_delete(path: str):
    tier = classify_file_op("delete", path)

    def execute():
        snapshot_file(path, description=f"Before deleting {path} (last version before deletion)")
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        return f"deleted {path}"

    suggestion = None
    alternative_fn = None
    if os.path.exists(path):
        suggestion = {"kind": "trash",
                      "text": "Move to the local trash folder instead: fully recoverable.",
                      "paths": [path], "command": None}
        alternative_fn = lambda: f"moved to trash: {move_to_trash(path)}"

    description = f"DELETE {path}" if tier == "LOW" else diff_for_delete(path)
    resolve_action("file", description, tier, execute,
                   suggestion=suggestion, alternative_fn=alternative_fn)


def intercept_move(src: str, dst: str):
    tier = classify_file_op("move", src)

    def execute():
        snapshot_file(src, description=f"Before moving {src} to {dst}")
        shutil.move(src, dst)
        # Snapshot the file at its NEW location after the move too
        snapshot_file(dst, description=f"After moving to {dst}")
        return f"moved {src} -> {dst}"

    description = f"MOVE {src} -> {dst}" if tier == "LOW" else diff_for_move(src, dst)
    resolve_action("file", description, tier, execute)