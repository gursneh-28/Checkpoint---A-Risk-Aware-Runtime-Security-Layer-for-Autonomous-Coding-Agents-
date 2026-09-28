import os
import shutil
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.risk_classifier import classify_file_op
from core.confirmation import resolve_action
from core.sandbox import snapshot_file, diff_for_write, diff_for_delete, diff_for_move


def intercept_create(path: str, content: str = ""):
    tier = classify_file_op("create", path)

    def execute():
        with open(path, "w") as f:
            f.write(content)
        return f"created {path}"

    resolve_action("file", f"CREATE {path}", tier, execute)


def intercept_write(path: str, content: str):
    tier = classify_file_op("write", path)

    def execute():
        snapshot_file(path)
        with open(path, "a") as f:
            f.write(content)
        return f"wrote to {path}"

    description = f"WRITE {path}" if tier == "LOW" else diff_for_write(path, content)
    resolve_action("file", description, tier, execute)


def intercept_delete(path: str):
    tier = classify_file_op("delete", path)

    def execute():
        snapshot_file(path)
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        return f"deleted {path}"

    description = f"DELETE {path}" if tier == "LOW" else diff_for_delete(path)
    resolve_action("file", description, tier, execute)


def intercept_move(src: str, dst: str):
    tier = classify_file_op("move", src)

    def execute():
        snapshot_file(src)
        shutil.move(src, dst)
        return f"moved {src} -> {dst}"

    description = f"MOVE {src} -> {dst}" if tier == "LOW" else diff_for_move(src, dst)
    resolve_action("file", description, tier, execute)


if __name__ == "__main__":
    intercept_create("test_file.txt", "hello from checkpoint\n")
    intercept_write("test_file.txt", "second line\n")
    intercept_delete("test_file.txt")