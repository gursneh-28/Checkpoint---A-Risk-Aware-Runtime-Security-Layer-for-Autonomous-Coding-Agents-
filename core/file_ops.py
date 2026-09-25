import os
import shutil
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.risk_classifier import classify_file_op
from core.confirmation import resolve_action


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
        with open(path, "a") as f:
            f.write(content)
        return f"wrote to {path}"

    resolve_action("file", f"WRITE {path}", tier, execute)


def intercept_delete(path: str):
    tier = classify_file_op("delete", path)

    def execute():
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        return f"deleted {path}"

    resolve_action("file", f"DELETE {path}", tier, execute)


def intercept_move(src: str, dst: str):
    tier = classify_file_op("move", src)

    def execute():
        shutil.move(src, dst)
        return f"moved {src} -> {dst}"

    resolve_action("file", f"MOVE {src} -> {dst}", tier, execute)


if __name__ == "__main__":
    intercept_create("test_file.txt", "hello from checkpoint\n")   # LOW -> auto
    intercept_write("test_file.txt", "second line\n")               # LOW -> auto
    intercept_delete("test_file.txt")                                # MEDIUM -> asks 