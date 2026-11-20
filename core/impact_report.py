"""
Impact report builder for Checkpoint — Feature 12.

Generates a full impact report for HIGH and CRITICAL actions,
including: exact targets, sizes, counts, Git state, reversibility,
and backup plan.

The EffectManifest is shared with:
  - Preview (Feature 5) — human-readable rendering
  - Safer option (Feature 6) — subset-of-effects check
  - CRITICAL policy (Feature 9) — gate for typed YES

The ImpactManifest and BackupPlan are SEPARATE from the ImpactManifest.
A planned backup ≠ completed backup.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# ImpactManifest — predicted effects (what WILL happen)
# ---------------------------------------------------------------------------

@dataclass
class TargetInfo:
    path:       str
    kind:       str    # "file", "directory", "git_ref", "remote", "device", "unknown"
    exists:     bool = False
    size_bytes: int  = 0
    item_count: int  = 0
    git_tracked: bool = False
    is_sensitive: bool = False
    notes:      str  = ""


@dataclass
class ImpactManifest:
    """Predicted effects of the action (before execution)."""
    command:          str
    targets:          List[TargetInfo] = field(default_factory=list)
    total_size_bytes: int   = 0
    total_item_count: int   = 0
    is_reversible:    bool  = True
    reversibility_notes: str = ""
    git_state:        Dict[str, Any] = field(default_factory=dict)
    has_unknown_effects: bool = False
    unknown_reason:   str = ""
    manifest_hash:    str = ""

    def compute_hash(self) -> str:
        blob = json.dumps({
            "command": self.command,
            "targets": [t.path for t in self.targets],
            "total_size": self.total_size_bytes,
        }, sort_keys=True)
        self.manifest_hash = hashlib.sha256(blob.encode()).hexdigest()[:16]
        return self.manifest_hash

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# BackupPlan — what will be backed up and how
# ---------------------------------------------------------------------------

@dataclass
class BackupItem:
    path:         str
    kind:         str   # "file", "directory", "git_bundle"
    size_bytes:   int   = 0
    is_required:  bool  = True
    can_skip:     bool  = False   # regenerable folders only
    skip_reason:  str   = ""


@dataclass
class BackupPlan:
    """What Checkpoint will back up before this action runs."""
    items:              List[BackupItem] = field(default_factory=list)
    total_size_bytes:   int  = 0
    requires_git_backup: bool = False
    estimated_duration_ms: int = 0
    will_exceed_quota:  bool = False
    quota_exceeded_reason: str = ""
    plan_hash:          str  = ""

    def compute_hash(self) -> str:
        blob = json.dumps({
            "items": [i.path for i in self.items],
            "total": self.total_size_bytes,
        }, sort_keys=True)
        self.plan_hash = hashlib.sha256(blob.encode()).hexdigest()[:16]
        return self.plan_hash

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dir_size_and_count(path: str):
    total_size, count = 0, 0
    try:
        for root, dirs, files in os.walk(path):
            count += len(dirs) + len(files)
            for f in files:
                try:
                    total_size += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except OSError:
        pass
    return total_size, count


def _get_git_state(cwd: str) -> Dict[str, Any]:
    state = {}
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            state["uncommitted_files"] = len(lines)
            state["has_uncommitted_changes"] = len(lines) > 0

        head = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        if head.returncode == 0:
            state["current_head"] = head.stdout.strip()

        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        if branch.returncode == 0:
            state["current_branch"] = branch.stdout.strip()

    except (OSError, subprocess.TimeoutExpired):
        state["error"] = "Could not read Git state"
    return state


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_impact_manifest(command: str, cwd: str = "") -> ImpactManifest:
    """
    Build a predicted ImpactManifest for the given command.
    Reads filesystem facts (sizes, counts, git state) at call time.
    Caller must revalidate immediately before execution (TOCTOU note).
    """
    tokens  = command.strip().split()
    verb    = tokens[0].lower() if tokens else ""
    targets: List[TargetInfo] = []

    if verb == "rm":
        raw_targets = [t for t in tokens[1:] if not t.startswith("-")]
        for t in raw_targets:
            exists = os.path.exists(t)
            if os.path.isdir(t):
                sz, cnt = _dir_size_and_count(t)
                targets.append(TargetInfo(
                    path=t, kind="directory", exists=exists,
                    size_bytes=sz, item_count=cnt, is_sensitive=False,
                ))
            elif os.path.isfile(t):
                try:
                    sz = os.path.getsize(t)
                except OSError:
                    sz = 0
                targets.append(TargetInfo(
                    path=t, kind="file", exists=exists, size_bytes=sz, item_count=1,
                ))
            else:
                targets.append(TargetInfo(path=t, kind="unknown", exists=False))

    elif verb == "git":
        sub = tokens[1].lower() if len(tokens) > 1 else ""
        if sub in ("push", "reset", "clean", "branch", "tag"):
            git_state = _get_git_state(cwd or os.getcwd())
            targets.append(TargetInfo(
                path="git-repository",
                kind="git_ref",
                exists=True,
                notes=f"branch={git_state.get('current_branch', '?')}, "
                      f"head={git_state.get('current_head', '?')}",
            ))
            manifest = ImpactManifest(
                command=command,
                targets=targets,
                is_reversible=sub not in ("push",),
                reversibility_notes=(
                    "Remote history cannot be un-rewritten without cooperation of all collaborators"
                    if sub == "push" else
                    "Local Git history is preserved; reset targets only the working tree"
                ),
                git_state=git_state,
            )
            manifest.compute_hash()
            return manifest

    total_size  = sum(t.size_bytes  for t in targets)
    total_count = sum(t.item_count  for t in targets)

    irreversible_verbs = {"rm", "dd", "mkfs", "truncate"}
    is_rev = verb not in irreversible_verbs

    manifest = ImpactManifest(
        command=command,
        targets=targets,
        total_size_bytes=total_size,
        total_item_count=total_count,
        is_reversible=is_rev,
        reversibility_notes=(
            "Requires Checkpoint backup" if not is_rev else "Recoverable via backup"
        ),
    )
    manifest.compute_hash()
    return manifest


def build_backup_plan(manifest: ImpactManifest) -> BackupPlan:
    """
    Given an ImpactManifest, produce a BackupPlan describing what will be
    copied before the action runs.  Does NOT perform the backup — that
    happens after approval, just before execution.
    """
    from core.path_module import is_regenerable_folder

    items: List[BackupItem] = []
    total = 0

    for target in manifest.targets:
        if target.kind == "git_ref":
            items.append(BackupItem(
                path=target.path,
                kind="git_bundle",
                size_bytes=0,  # unknown until bundle is created
                is_required=True,
            ))
            continue

        regen, reason = is_regenerable_folder(target.path)
        if regen:
            items.append(BackupItem(
                path=target.path, kind="directory",
                size_bytes=target.size_bytes,
                is_required=False, can_skip=True, skip_reason=reason,
            ))
        else:
            items.append(BackupItem(
                path=target.path,
                kind=target.kind,
                size_bytes=target.size_bytes,
                is_required=True,
            ))
            total += target.size_bytes

    # Check quota (simplified: 2 GB hard limit)
    QUOTA_BYTES = 2 * 1024 * 1024 * 1024
    exceeded = total > QUOTA_BYTES
    reason_str = f"Backup would require {total / 1e9:.2f} GB; quota is 2 GB" if exceeded else ""

    plan = BackupPlan(
        items=items,
        total_size_bytes=total,
        requires_git_backup=any(i.kind == "git_bundle" for i in items),
        will_exceed_quota=exceeded,
        quota_exceeded_reason=reason_str,
    )
    plan.compute_hash()
    return plan
