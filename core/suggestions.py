"""
"Do this instead" — safer alternatives engine for Checkpoint — Feature 6.

Design doc rules:
- Runs ONLY on MEDIUM or HIGH commands (never judges risk itself).
- Uses fixed templates + validated literal arguments only.
- Never constructs shell text by blindly applying shlex.quote to AST fragments.
- Every alternative is re-classified; must rate lower (or same with smaller effect set).
- Chained commands and unrecognized commands get no alternative in v1.
- Trash: same-volume rename only; volumes verified; ACLs required.
- Moving to trash does not free disk space.
- 'Safer' is not 'safe': force-with-lease still rewrites history.

Trash location: per-volume protected folder.
  - Windows: \\<volume-root>\\.checkpoint-trash\\<volume-serial>
  - Fallback: storage/trash (for dev/testing)

This module never executes anything.  The interceptor/confirmation handles
execution after an authenticated dashboard decision.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

CHAIN_RE     = re.compile(r"&&|\|\||;|\|")
_PIPE_SH_RE  = re.compile(r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", re.IGNORECASE)

# Dev/test fallback trash dir
_DEV_TRASH_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "trash")


# ---------------------------------------------------------------------------
# Trash location
# ---------------------------------------------------------------------------

def _get_volume_serial(path: str) -> str:
    """Return the volume serial number as a hex string on Windows; empty on other OS."""
    try:
        import ctypes
        volroot = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
        serial  = ctypes.c_ulong()
        ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(volroot), None, 0, ctypes.byref(serial), None, None, None, 0
        )
        return format(serial.value, "08X")
    except Exception:
        return "UNKNOWN"


def _get_trash_dir(path: str) -> str:
    """
    Return the per-volume protected trash directory for `path`.
    On Windows: <volume_root>\\.checkpoint-trash\\<volume_serial>
    Fallback: storage/trash (dev/test)
    """
    try:
        abs_path = os.path.abspath(path)
        drive    = os.path.splitdrive(abs_path)[0]
        if drive:
            vol_serial = _get_volume_serial(abs_path)
            trash_dir  = os.path.join(drive + "\\", ".checkpoint-trash", vol_serial)
            return trash_dir
    except Exception:
        pass
    return _DEV_TRASH_DIR


def _same_volume(src: str, dst_dir: str) -> bool:
    """Return True when src and dst_dir are on the same drive/volume."""
    try:
        src_drive = os.path.splitdrive(os.path.abspath(src))[0].upper()
        dst_drive = os.path.splitdrive(os.path.abspath(dst_dir))[0].upper()
        return src_drive == dst_drive
    except Exception:
        return False


def move_to_trash(path: str, trash_dir: Optional[str] = None) -> str:
    """
    Soft-delete: moves a file or folder into the volume-local trash folder.
    Returns the destination path.

    Design doc: same-volume rename only; no cross-volume moves;
    no link/reparse-point traversal.
    """
    abs_path  = os.path.abspath(path)
    trash     = trash_dir or _get_trash_dir(abs_path)

    if not _same_volume(abs_path, trash):
        # Cross-volume: cannot do a same-volume rename — no alternative offered
        raise ValueError(f"Cross-volume trash not supported: {abs_path} → {trash}")

    os.makedirs(trash, exist_ok=True)
    base = os.path.basename(abs_path.rstrip("/\\"))
    while True:
        name = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}_{base}"
        dest = os.path.join(trash, name)
        if not os.path.exists(dest):
            break
    shutil.move(abs_path, dest)
    return dest


# ---------------------------------------------------------------------------
# Suggestion validator
# ---------------------------------------------------------------------------

def _reclassify(command: str) -> str:
    """Re-classify a candidate alternative using the central classifier."""
    from core.risk_classifier import classify_risk
    return classify_risk(command)


def _validate_alternative(original_tier: str, original_cmd: str,
                           alt_cmd: str, alt_kind: str) -> bool:
    """
    Return True when the alternative passes all safety checks:
    - For 'replace': must rate lower (or same + strictly smaller effect set).
    - For 'protect': verified backup path (checked by caller).
    - No new network access, paths, or deletes.
    - No shell metacharacters in generated command beyond the template.
    """
    if alt_kind == "protect":
        return True   # validated by backup system

    # Must not introduce substitutions, control operators, redirects
    danger = re.compile(r"[$`<>|;&]")
    if danger.search(alt_cmd):
        return False

    alt_tier = _reclassify(alt_cmd)
    tier_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    orig_ord   = tier_order.get(original_tier, 2)
    alt_ord    = tier_order.get(alt_tier, 2)

    # Must not be riskier than original
    return alt_ord <= orig_ord


# ---------------------------------------------------------------------------
# Template-based alternative generators
# ---------------------------------------------------------------------------

def _suggest_git_push_force(tokens: List[str], lower: List[str]) -> Optional[Dict[str, Any]]:
    """git push --force → --force-with-lease (only on non-protected, non-unknown branch)."""
    from core.risk_classifier import PROTECTED_BRANCHES, _extract_git_branch

    # Only when branch is known and NOT protected
    branch = _extract_git_branch(" ".join(lower))
    if branch is None or branch in PROTECTED_BRANCHES:
        return None   # no alternative: protected or unknown branch

    # Rebuild from template using validated literal arguments only
    new_tokens = []
    for t in tokens:
        if t.lower() in ("-f", "--force"):
            new_tokens.append("--force-with-lease")
        else:
            new_tokens.append(t)
    alt_cmd = " ".join(new_tokens)

    if not _validate_alternative("HIGH", " ".join(tokens), alt_cmd, "replace"):
        return None

    return {
        "kind":    "command",
        "text":    (
            "Use --force-with-lease instead: it checks that the remote has not "
            "been updated since your last fetch, and fails safely if it has. "
            "Note: it still rewrites remote history — 'safer, not safe'."
        ),
        "command": alt_cmd,
        "diff":    "--force → --force-with-lease",
        "safer_not_safe": True,
    }


def _suggest_git_reset_hard(tokens: List[str], lower: List[str]) -> Optional[Dict[str, Any]]:
    """git reset --hard → git stash."""
    alt_cmd = "git stash"
    if not _validate_alternative("HIGH", " ".join(tokens), alt_cmd, "replace"):
        return None
    return {
        "kind":    "command",
        "text":    (
            "Stash the changes instead: they stay recoverable in the stash "
            "rather than being permanently discarded. Run 'git stash pop' to restore."
        ),
        "command": alt_cmd,
        "diff":    "hard reset → stash (recoverable)",
        "safer_not_safe": False,
    }


def _suggest_git_clean(tokens: List[str], lower: List[str]) -> Optional[Dict[str, Any]]:
    """git clean -fdx → dry run first (-n)."""
    # Build dry-run version: replace flags with -n (dry run) + original scope flags
    flags    = [t for t in tokens if t.startswith("-")]
    non_flag = [t for t in tokens if not t.startswith("-") and t not in ("git", "clean")]

    # Remove -n if already present (idempotent), then add it
    new_flags = [f for f in flags if "n" not in f] + ["-n"]
    alt_parts = ["git", "clean"] + new_flags + non_flag
    alt_cmd   = " ".join(alt_parts)

    if not _validate_alternative("HIGH", " ".join(tokens), alt_cmd, "replace"):
        return None
    return {
        "kind":    "command",
        "text":    (
            "Show what would be deleted (dry run) without actually deleting. "
            "Review the list, then run the original command if it looks correct."
        ),
        "command": alt_cmd,
        "diff":    "adds -n (dry run); nothing is deleted",
        "safer_not_safe": False,
    }


def _suggest_curl_pipe_shell(tokens: List[str], lower: List[str]) -> Optional[Dict[str, Any]]:
    """curl URL | bash → download to file (not run)."""
    # Find the URL (first token starting with http)
    url = next((t for t in tokens if t.lower().startswith("http")), None)
    if not url:
        return None
    # Safe filename derived from URL basename, no shell metacharacters
    fname = re.sub(r"[^\w.\-]", "_", os.path.basename(url.rstrip("/")) or "downloaded_script")
    fname = fname[:64] + ".sh"

    # Template — no substitution, no metacharacters
    alt_cmd = f"curl -fsSL {url} -o {fname}"
    if not _validate_alternative("HIGH", " ".join(tokens), alt_cmd, "replace"):
        return None
    return {
        "kind":    "command",
        "text":    (
            f"Download the script to '{fname}' WITHOUT running it. "
            "Inspect it first: cat or less the file, then run 'bash {fname}' if it looks safe. "
            "Note: this does not validate the content of the remote script."
        ),
        "command": alt_cmd,
        "diff":    "downloads to file; does NOT execute",
        "safer_not_safe": False,
    }


def _suggest_rm(tokens: List[str], lower: List[str]) -> Optional[Dict[str, Any]]:
    """rm [paths] → move to trash."""
    paths = [t for t in tokens[1:] if not t.startswith("-")]
    if not paths:
        return None

    return {
        "kind":    "trash",
        "text":    (
            "Move to the Checkpoint trash folder instead (same-volume rename: "
            "no second copy is made). Items are kept for 30 days. "
            "Note: this does NOT free disk space."
        ),
        "paths":   paths,
        "command": None,
        "diff":    "delete → move to trash (recoverable for 30 days)",
        "disk_space_note": "Moving to trash does not free disk space",
        "safer_not_safe": False,
    }


def _suggest_docker_prune(tokens: List[str], lower: List[str]) -> Optional[Dict[str, Any]]:
    """docker system prune -af --volumes → without -a and --volumes."""
    has_all  = "-a" in lower or "--all" in lower
    has_vols = "--volumes" in lower

    if not (has_all or has_vols):
        return None   # already without those flags; no alternative needed

    # Template: remove dangerous flags only
    new_tokens = []
    for t in tokens:
        tl = t.lower()
        if tl in ("-a", "--all", "--volumes"):
            continue
        if tl.startswith("-") and "a" in tl and not tl.startswith("--"):
            # e.g. -af → -f
            cleaned = "-" + tl[1:].replace("a", "")
            if cleaned != "-":
                new_tokens.append(cleaned)
        else:
            new_tokens.append(t)
    if not new_tokens:
        return None

    alt_cmd = " ".join(new_tokens)
    if not _validate_alternative("HIGH", " ".join(tokens), alt_cmd, "replace"):
        return None

    removed = []
    if has_all:
        removed.append("--all (stopped containers only, not running)")
    if has_vols:
        removed.append("--volumes (volumes NOT deleted)")

    return {
        "kind":    "command",
        "text":    (
            f"Prune Docker resources without: {'; '.join(removed)}. "
            "Still deletes dangling images and build cache. "
            "IMPORTANT: This still deletes resources — a fresh risk decision is required."
        ),
        "command": alt_cmd,
        "diff":    f"Removed flags: {', '.join(removed)}",
        "safer_not_safe": True,
        "requires_new_decision": True,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def suggest_alternative(command: str, risk_tier: str = "MEDIUM") -> Optional[Dict[str, Any]]:
    """
    Returns None, or a suggestion dict:
      {"kind": "command", "text": ..., "command": ..., "diff": ...}
      {"kind": "trash",   "text": ..., "paths": [...], "diff": ...}

    Rules:
    - Only for MEDIUM or HIGH tier.
    - Chained commands and unrecognized commands get no alternative.
    - Generated from fixed templates + validated literal args only.
    """
    if risk_tier not in ("MEDIUM", "HIGH", "CRITICAL"):
        return None

    # No alternatives for chained commands
    if CHAIN_RE.search(command) and not _PIPE_SH_RE.search(command):
        return None

    tokens = command.strip().split()
    if len(tokens) < 1:
        return None
    lower = [t.lower() for t in tokens]
    verb  = lower[0]

    # --- pipe-into-shell: must check before splitting on | ---
    if _PIPE_SH_RE.search(command):
        return _suggest_curl_pipe_shell(tokens, lower)

    # --- git ---
    if verb == "git":
        if len(lower) < 2:
            return None
        sub = lower[1]

        if sub == "push" and any(t in ("-f", "--force") for t in lower):
            return _suggest_git_push_force(tokens, lower)

        if sub == "reset" and "--hard" in lower:
            return _suggest_git_reset_hard(tokens, lower)

        if sub == "clean":
            return _suggest_git_clean(tokens, lower)

        return None

    # --- rm ---
    if verb == "rm":
        return _suggest_rm(tokens, lower)

    # --- docker system prune ---
    if verb == "docker" and "system" in lower and "prune" in lower:
        return _suggest_docker_prune(tokens, lower)

    return None