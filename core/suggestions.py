"""
"Do this instead": a plain, hardcoded lookup of known safer equivalents for
risky commands. NOT AI and NOT the risk model. If nothing matches, returns
None and the dashboard shows only Approve / Reject.

A suggestion is only ever a proposal. It never runs by itself; it executes
only after an explicit user decision, through the same confirmation gate.
"""
import os
import re
import shutil
import uuid
import time

TRASH_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "trash")
CHAIN_RE = re.compile(r"&&|\|\||;|\|")


def suggest_alternative(command: str):
    """
    Returns None, or a dict:
      {"kind": "command", "text": plain-language explanation, "command": safer command}
      {"kind": "trash",   "text": plain-language explanation, "paths": [...], "command": None}
    Chained commands get no suggestion, because swapping part of a chain
    could change what the rest of it does.
    """
    if CHAIN_RE.search(command):
        return None
    tokens = command.split()
    if len(tokens) < 2:
        return None
    low = [t.lower() for t in tokens]

    if low[0] == "git":
        sub = low[1]
        if (sub == "push"
                and any(t in ("-f", "--force") for t in low)
                and not any(t.startswith("--force-with-lease") for t in low)):
            safer = ["--force-with-lease" if t.lower() in ("-f", "--force") else t
                     for t in tokens]
            return {
                "kind": "command",
                "text": "Use --force-with-lease instead: it fails safely rather than "
                        "silently overwriting someone else's work.",
                "command": " ".join(safer),
            }
        if sub == "reset" and "--hard" in low:
            return {
                "kind": "command",
                "text": "Stash the changes instead: they stay recoverable rather than "
                        "being discarded.",
                "command": "git stash",
            }
        return None

    if low[0] == "rm":
        paths = [t for t in tokens[1:] if not t.startswith("-")]
        if paths:
            return {
                "kind": "trash",
                "text": "Move to the local trash folder instead: fully recoverable.",
                "paths": paths,
                "command": None,
            }
    return None


def move_to_trash(path: str, trash_dir: str = TRASH_DIR) -> str:
    """Soft-delete: moves a file or folder into the trash folder under a
    guaranteed-unique name and returns where it went. Never overwrites
    anything already in the trash."""
    os.makedirs(trash_dir, exist_ok=True)
    base = os.path.basename(os.path.normpath(path))
    while True:
        name = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}_{base}"
        dest = os.path.join(trash_dir, name)
        if not os.path.exists(dest):
            break
    shutil.move(path, dest)
    return dest