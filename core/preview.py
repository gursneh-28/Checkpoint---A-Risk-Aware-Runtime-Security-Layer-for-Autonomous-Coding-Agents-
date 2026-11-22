"""
Plain-language preview builder for Checkpoint — Feature 5.

Generates a human-readable Preview from a CommandAnalysis/EffectManifest
and verified filesystem facts.  The preview is a PRESENTATION LAYER only;
it never sets the risk tier.

The structured CommandAnalysis/EffectManifest is shared with:
  - Safer option (Feature 6)
  - CRITICAL policy (Feature 9)
  - Impact report (Feature 12)

For unknown commands, shows "Checkpoint does not recognize this command;
effect unknown" — never shows unknown as an empty impact list.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Structured types
# ---------------------------------------------------------------------------

@dataclass
class AffectedResource:
    path:        str
    kind:        str    # "file", "directory", "git_branch", "remote", "volume"
    size_bytes:  int = 0
    item_count:  int = 0
    recoverable: bool = True
    notes:       str = ""


@dataclass
class EffectItem:
    verb:     str    # "delete", "overwrite", "move", "fetch", "execute", "modify"
    target:   str
    scope:    str    # "single_file", "directory_tree", "remote", "unknown"
    bounded:  bool = True
    reversible: bool = True
    notes:    str = ""


@dataclass
class CommandAnalysis:
    """Structured analysis — shared with feature 6, 9, 12."""
    command:            str
    parsed_ok:          bool
    tool_name:          str = ""
    sub_command:        str = ""
    flags:              List[str] = field(default_factory=list)
    targets:            List[str] = field(default_factory=list)
    effects:            List[EffectItem] = field(default_factory=list)
    affected_resources: List[AffectedResource] = field(default_factory=list)
    unsupported_constructs: List[str] = field(default_factory=list)
    coverage:           str = "full"   # "full", "partial", "unsupported", "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Preview:
    """The human-readable preview — stored as the exact content shown."""
    headline:          str
    details:           List[str] = field(default_factory=list)
    affected_summary:  str = ""
    effects_summary:   List[str] = field(default_factory=list)
    limitations:       List[str] = field(default_factory=list)
    undo_path:         str = ""
    is_unknown:        bool = False
    unknown_reason:    str = ""
    version:           int = 1

    # Hash of this exact preview (bound to approvals)
    preview_hash:      str = ""
    blast_radius:      Dict[str, Any] = field(default_factory=dict)
    target_fingerprints: Dict[str, str] = field(default_factory=dict)

    def compute_hash(self) -> str:
        blob = json.dumps({
            "headline": self.headline,
            "details":  self.details,
            "effects":  self.effects_summary,
            "blast_radius": self.blast_radius,
        }, sort_keys=True)
        self.preview_hash = hashlib.sha256(blob.encode()).hexdigest()[:16]
        return self.preview_hash

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_target_fingerprint(path: str) -> str:
    """Compute a lightweight state fingerprint (size:mtime) for a file or directory."""
    try:
        if not os.path.exists(path):
            return "non_existent"
        st = os.stat(path)
        return f"{st.st_size}:{st.st_mtime}"
    except OSError:
        return "error"


def verify_preview_fingerprints(preview: Preview) -> Tuple[bool, str]:
    """
    Verify whether on-disk target files have shifted since the preview was computed.
    Returns (is_valid, reason).
    """
    if not preview.target_fingerprints:
        return True, "No target fingerprints recorded"

    for path, original_fp in preview.target_fingerprints.items():
        current_fp = compute_target_fingerprint(path)
        if current_fp != original_fp:
            return False, f"Target '{path}' state modified since preview generated ({original_fp} -> {current_fp})"
    return True, "Target fingerprints intact"


# ---------------------------------------------------------------------------
# Template registry — one per HIGH pattern
# ---------------------------------------------------------------------------

def _count_items(path: str) -> int:
    """Safe item count for a path; returns 0 on any error."""
    try:
        if os.path.isdir(path):
            return sum(len(fs) + len(ds) for _, ds, fs in os.walk(path))
        return 1 if os.path.exists(path) else 0
    except OSError:
        return 0


def _size_str(path: str) -> str:
    try:
        if os.path.isdir(path):
            total = sum(
                os.path.getsize(os.path.join(root, f))
                for root, _, files in os.walk(path)
                for f in files
            )
            return _human_bytes(total)
        elif os.path.isfile(path):
            return _human_bytes(os.path.getsize(path))
    except OSError:
        pass
    return "unknown size"


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _preview_rm_rf(command: str, tokens: List[str]) -> Preview:
    targets = [t for t in tokens[1:] if not t.startswith("-")]
    details = []
    effects = []
    for t in targets:
        n = _count_items(t)
        s = _size_str(t)
        details.append(f"Permanently deletes '{t}' ({n} item(s), {s})")
        effects.append(f"DELETE {t} — {n} item(s), {s}, NOT recoverable without backup")
    return Preview(
        headline=f"Permanently delete {len(targets)} item(s): {', '.join(targets)}",
        details=details,
        effects_summary=effects,
        limitations=["Deleted files cannot be recovered unless a backup exists",
                     "File sizes and counts may change between preview and execution"],
        undo_path="Checkpoint backup (if approved and backup succeeds)",
        is_unknown=False,
    )


def _preview_git_push_force(command: str, tokens: List[str]) -> Preview:
    branch = next((t for t in reversed(tokens)
                   if not t.startswith("-") and t not in ("git", "push", "origin", "upstream")),
                  "unknown-branch")
    lease  = any("--force-with-lease" in t for t in tokens)
    flag   = "--force-with-lease" if lease else "--force"
    return Preview(
        headline=f"Force-push to '{branch}' ({flag}) — rewrites remote history",
        details=[
            f"Pushes your local commits to '{branch}', discarding any remote commits "
            "that are not in your local history.",
            "Collaborators who have fetched those remote commits will see diverged history.",
            "--force-with-lease fails safely if the remote has changed since your last fetch, "
            "but only if the tracking reference is current." if lease else
            "--force DOES NOT CHECK the remote state before overwriting.",
        ],
        effects_summary=[f"REWRITE remote history on '{branch}'"],
        limitations=["Does not create a local backup of remote state",
                     "May cause data loss for other contributors"],
        undo_path="git push origin <old-sha>:<branch> (requires knowing the old SHA)",
    )


def _preview_git_reset_hard(command: str, tokens: List[str]) -> Preview:
    ref = next((t for t in reversed(tokens)
                if not t.startswith("-") and t not in ("git", "reset", "--hard")), "HEAD")
    return Preview(
        headline=f"Hard reset to '{ref}' — discards all uncommitted changes",
        details=[
            f"Resets the working tree and index to '{ref}'.",
            "Uncommitted changes (staged and unstaged) are permanently discarded.",
            "Committed changes are NOT lost — they remain in Git history.",
        ],
        effects_summary=[f"DISCARD all uncommitted changes, reset to '{ref}'"],
        limitations=["Uncommitted changes are unrecoverable without a prior backup"],
        undo_path="git stash (before running) or Checkpoint backup",
    )


def _preview_git_clean(command: str, tokens: List[str]) -> Preview:
    flags = " ".join(t for t in tokens if t.startswith("-"))
    return Preview(
        headline=f"Remove all untracked files from the working tree ({flags})",
        details=[
            "Deletes files and directories not tracked by Git.",
            "-f removes untracked files; -d also removes directories; "
            "-x also removes ignored files.",
            "Untracked files are NOT in Git history and cannot be recovered.",
        ],
        effects_summary=["DELETE all untracked files (and ignored files if -x)"],
        limitations=["Untracked files have no Git history to restore from"],
        undo_path="Checkpoint backup (if approved and backup succeeds)",
    )


def _preview_curl_pipe_shell(command: str, tokens: List[str]) -> Preview:
    url = next((t for t in tokens if t.startswith("http")), "remote URL")
    return Preview(
        headline=f"Download and execute remote script from {url}",
        details=[
            f"Downloads content from '{url}' and pipes it directly into a shell.",
            "The downloaded content is executed immediately without inspection.",
            "Checkpoint cannot analyze the remote content before execution.",
        ],
        effects_summary=["EXECUTE unknown remote code — effects are unpredictable"],
        limitations=["Remote content is not visible until download; preview is incomplete",
                     "Safer option: download to a file first, then inspect"],
        undo_path="None — remote code execution cannot be predicted or undone",
    )


def _preview_docker_prune(command: str, tokens: List[str]) -> Preview:
    all_flag = "-a" in tokens or "--all" in tokens
    vol_flag = "--volumes" in tokens
    scope = "stopped containers"
    if all_flag:
        scope = "ALL containers (including running)"
    if vol_flag:
        scope += " + all volumes"
    return Preview(
        headline=f"Remove unused Docker resources: {scope}",
        details=[
            f"Prunes: {scope}.",
            "Also removes dangling images, build cache.",
            "Resource counts and sizes shown here may change before execution.",
        ],
        effects_summary=[f"DELETE Docker resources: {scope}"],
        limitations=["Cannot easily restore deleted Docker layers",
                     "Volume data may be unrecoverable"],
        undo_path="None for deleted layers; volume data may be in backup",
    )


def _preview_chmod_777(command: str, tokens: List[str]) -> Preview:
    targets = [t for t in tokens if not t.startswith("-") and t != "chmod" and t != "777"]
    recursive = "-r" in tokens or "--recursive" in tokens
    scope = "recursively" if recursive else ""
    return Preview(
        headline=f"Set world-writable permissions (777) on {', '.join(targets)} {scope}",
        details=[
            "Makes files readable, writable, and executable by EVERYONE on the system.",
            "This is a significant security risk for files containing sensitive data.",
        ],
        effects_summary=[f"MODIFY permissions to 777 on: {', '.join(targets)}"],
        limitations=["Original permissions are not automatically saved"],
        undo_path="chmod <original-mode> <path> (requires knowing original mode)",
    )


def _preview_git_push_delete(command: str, tokens: List[str]) -> Preview:
    branch = next((t for t in reversed(tokens)
                   if not t.startswith("-") and t not in ("git", "push", "origin")), "?")
    return Preview(
        headline=f"Delete remote branch '{branch}'",
        details=["Deletes the branch on the remote repository.",
                 "Other collaborators will lose access to the remote branch."],
        effects_summary=[f"DELETE remote branch '{branch}'"],
        limitations=["The branch can be re-pushed, but remote PR/MR history may be lost"],
        undo_path=f"git push origin <local-branch-ref>:{branch}",
    )


# ---------------------------------------------------------------------------
# Unknown command preview
# ---------------------------------------------------------------------------

def _preview_unknown(command: str, reason: str) -> Preview:
    p = Preview(
        headline="Checkpoint does not recognize this command; effect unknown",
        details=[
            f"Command: {command[:200]}",
            f"Reason coverage is incomplete: {reason}",
            "Checkpoint cannot predict what this command will do.",
        ],
        effects_summary=["UNKNOWN — cannot predict effects"],
        limitations=["No effect analysis available for this command family",
                     "Review the command carefully before approving"],
        undo_path="Unknown",
        is_unknown=True,
        unknown_reason=reason,
    )
    return p


# ---------------------------------------------------------------------------
# Main preview builder
# ---------------------------------------------------------------------------

_PIPE_SHELL_RE = re.compile(r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", re.IGNORECASE)


def generate_preview(command: str, cwd: str = "") -> Preview:
    """
    Build a Preview for the given command.
    Returns an unknown-preview for unrecognized commands; never guesses.
    """
    cmd   = command.strip()
    lower = cmd.lower()
    tokens = lower.split()

    if not tokens:
        p = _preview_unknown(cmd, "empty command")
        p.compute_hash()
        return p

    verb = tokens[0]

    # Pipe-into-shell
    if _PIPE_SHELL_RE.search(lower):
        p = _preview_curl_pipe_shell(cmd, tokens)
        p.compute_hash()
        return p

    # rm -rf
    if verb == "rm" and ("-r" in tokens or "--recursive" in tokens or
                         any("-" in t and "r" in t for t in tokens[1:] if t.startswith("-"))):
        p = _preview_rm_rf(cmd, tokens)
        p.compute_hash()
        return p

    # git
    if verb == "git" and len(tokens) >= 2:
        sub = tokens[1]

        if sub == "push" and any(t in ("-f", "--force") or "force" in t for t in tokens):
            p = _preview_git_push_force(cmd, tokens)
            p.compute_hash()
            return p

        if sub == "push" and "--delete" in tokens:
            p = _preview_git_push_delete(cmd, tokens)
            p.compute_hash()
            return p

        if sub == "reset" and "--hard" in tokens:
            p = _preview_git_reset_hard(cmd, tokens)
            p.compute_hash()
            return p

        if sub == "clean":
            p = _preview_git_clean(cmd, tokens)
            p.compute_hash()
            return p

    # docker system prune
    if verb == "docker" and "system" in tokens and "prune" in tokens:
        p = _preview_docker_prune(cmd, tokens)
        p.compute_hash()
        return p

    # chmod 777
    if verb == "chmod" and "777" in tokens:
        p = _preview_chmod_777(cmd, tokens)
        p.compute_hash()
        return p

    # dd
    if verb == "dd":
        p = Preview(
            headline="Low-level disk write (dd) — can overwrite raw devices",
            details=["dd copies data at the block level.",
                     "Writing to a device (of=/dev/...) can destroy the filesystem."],
            effects_summary=["LOW-LEVEL WRITE — potentially irreversible"],
            is_unknown=False,
            undo_path="None if a raw device is targeted",
        )
        p.compute_hash()
        return p

    # For recognized safe commands, generate a simple preview
    safe_verbs = {"ls", "pwd", "cat", "echo", "head", "tail", "wc", "tree",
                  "which", "whoami", "date", "git status", "git log", "git diff"}
    if verb in {"ls", "pwd", "echo", "which", "whoami", "date", "tree"}:
        p = Preview(
            headline=f"Read-only: {cmd[:100]}",
            details=["This command reads information and does not modify any files."],
            effects_summary=["READ only — no changes"],
            undo_path="N/A — no changes made",
        )
        p.compute_hash()
        return p

    if verb == "cat":
        targets = [t for t in tokens[1:] if not t.startswith("-")]
        p = Preview(
            headline=f"Display file contents: {', '.join(targets[:3])}",
            details=["Reads and displays file contents. No files are modified."],
            effects_summary=["READ — no changes"],
            undo_path="N/A",
        )
        p.compute_hash()
        return p

    # Fallback: unknown
    reason = "No adapter exists for this command family in v1"
    if any(c in cmd for c in ("$(", "`", "${", ">", "<")):
        reason = "Command contains shell substitution or redirection that cannot be fully analyzed"

    p = _preview_unknown(cmd, reason)
    p.compute_hash()
    return p


def generate_analysis(command: str) -> CommandAnalysis:
    """
    Generate structured CommandAnalysis for use by feature 6, 9, 12.
    Does not produce human text — that is Preview's job.
    """
    tokens = command.strip().split()
    if not tokens:
        return CommandAnalysis(command=command, parsed_ok=False, coverage="unknown")

    verb = tokens[0]
    sub  = tokens[1] if len(tokens) > 1 else ""
    flags   = [t for t in tokens if t.startswith("-")]
    targets = [t for t in tokens if not t.startswith("-") and t not in (verb, sub)]

    effects: List[EffectItem] = []
    if verb == "rm":
        for t in targets:
            effects.append(EffectItem(
                verb="delete", target=t,
                scope="directory_tree" if "-r" in " ".join(flags) else "single_file",
                bounded=True, reversible=False,
            ))
    elif verb == "git" and sub == "push":
        effects.append(EffectItem(
            verb="modify", target=f"remote/{' '.join(targets[:1])}",
            scope="remote", bounded=True, reversible=True,
        ))

    has_unsupported = any(c in command for c in ("$(", "`", "${"))
    return CommandAnalysis(
        command=command,
        parsed_ok=not has_unsupported,
        tool_name=verb,
        sub_command=sub,
        flags=flags,
        targets=targets,
        effects=effects,
        coverage="partial" if has_unsupported else "full",
        unsupported_constructs=["shell substitution"] if has_unsupported else [],
    )
