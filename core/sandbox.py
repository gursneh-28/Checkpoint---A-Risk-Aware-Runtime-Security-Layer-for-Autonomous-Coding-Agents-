import os
import shutil
import uuid
import difflib
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage.db import record_checkpoint, get_checkpoint

SHADOW_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "shadow_copies")


def _ensure_shadow_dir():
    os.makedirs(SHADOW_DIR, exist_ok=True)


def snapshot_file(path: str, description: str = "") -> str:
    """Copies the CURRENT state of a file into the shadow folder before it gets
    touched, and records it as a checkpoint in the database so it can be
    restored later. Returns the snapshot's path, or None if the file didn't
    exist yet (e.g. a brand-new file being created — nothing to checkpoint)."""
    if not os.path.isfile(path):
        return None

    _ensure_shadow_dir()
    snapshot_name = f"{uuid.uuid4().hex}_{os.path.basename(path)}"
    snapshot_path = os.path.join(SHADOW_DIR, snapshot_name)
    shutil.copy2(path, snapshot_path)

    record_checkpoint(file_path=path, snapshot_path=snapshot_path, description=description)
    return snapshot_path


def rollback_checkpoint(checkpoint_id: int):
    """Restores a file to exactly how it looked at the time a given checkpoint
    was saved. Returns (success: bool, message: str)."""
    row = get_checkpoint(checkpoint_id)
    if not row:
        return False, f"Checkpoint #{checkpoint_id} not found."

    # row columns: id, timestamp, file_path, snapshot_path, description
    _, timestamp, file_path, snapshot_path, description = row

    if not os.path.isfile(snapshot_path):
        return False, f"Snapshot file for checkpoint #{checkpoint_id} is missing on disk."

    shutil.copy2(snapshot_path, file_path)
    return True, f"Restored '{file_path}' to its state from checkpoint #{checkpoint_id} ({timestamp})."


def _read_text_safe(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, PermissionError):
        return "[binary or unreadable file — content preview unavailable]"


def diff_for_write(path: str, new_content: str) -> str:
    old_content = _read_text_safe(path)
    old_lines = old_content.splitlines(keepends=True)
    new_lines = (old_content + new_content).splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(
        old_lines, new_lines,
        fromfile=f"{path} (current)", tofile=f"{path} (after this action)", lineterm=""
    ))
    if not diff_lines:
        return f"No visible change to {path}."
    return "\n".join(diff_lines)


def diff_for_delete(path: str) -> str:
    if os.path.isdir(path):
        file_count = sum(len(files) for _, _, files in os.walk(path))
        return f"This will permanently delete the folder '{path}' and everything inside it ({file_count} file(s))."
    if not os.path.isfile(path):
        return f"'{path}' does not exist — nothing would actually be deleted."
    content = _read_text_safe(path)
    size = os.path.getsize(path)
    line_count = content.count("\n") + 1 if content else 0
    preview = "\n".join(content.splitlines()[:5])
    more = "\n... (truncated)" if line_count > 5 else ""
    return (f"This will permanently delete '{path}' ({size} bytes, {line_count} line(s)).\n"
            f"Preview of what will be lost:\n{preview}{more}")


def diff_for_move(src: str, dst: str) -> str:
    if not os.path.exists(src):
        return f"'{src}' does not exist — nothing would actually be moved."
    return f"This will move '{src}' to '{dst}'. The file will no longer exist at its original location."