"""
Git safety net for Checkpoint — Feature 13.

Maintains a Checkpoint-controlled Git backup OUTSIDE the project repository.
Before any destructive Git metadata operation, Checkpoint must have a
verified external backup.

The design doc specifies:
- Git refs inside the workspace are NOT an independent backup.
- Separately snapshot staged, unstaged and untracked state.
- A Git bundle alone does not preserve uncommitted worktree/index state.
- The .git directory is never exempt from backup (unlike regenerable folders).
- If no verified Git backup exists, block the destructive operation.

This module never executes agent commands and never approves actions.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# External backup directory: outside the project, under AppData
_DEFAULT_BACKUP_ROOT = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "Checkpoint", "git-backups",
)


@dataclass
class GitBackupRecord:
    backup_id:     str
    project_path:  str
    timestamp:     float
    bundle_path:   str
    patch_path:    str    # for staged/unstaged changes (git diff output)
    untracked_tar: str    # for untracked files
    head_sha:      str
    branch:        str
    verified:      bool   = False
    verify_hash:   str    = ""


class GitSafetyNet:
    """
    Manages external Git backups for a project.
    One instance per service; backed by a simple JSON index file.
    """

    def __init__(self, backup_root: str = _DEFAULT_BACKUP_ROOT):
        self._root  = backup_root
        self._index: Dict[str, List[GitBackupRecord]] = {}   # project_path → records
        self._index_path = os.path.join(backup_root, "git_backup_index.json")
        os.makedirs(backup_root, exist_ok=True)
        self._load_index()

    # ------------------------------------------------------------------
    # Index persistence
    # ------------------------------------------------------------------

    def _load_index(self):
        try:
            if os.path.isfile(self._index_path):
                with open(self._index_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                self._index = {
                    k: [GitBackupRecord(**r) for r in v]
                    for k, v in raw.items()
                }
        except (OSError, json.JSONDecodeError, TypeError):
            self._index = {}

    def _save_index(self):
        try:
            tmp = self._index_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(
                    {k: [vars(r) for r in v] for k, v in self._index.items()},
                    f, indent=2,
                )
            os.replace(tmp, self._index_path)
        except OSError:
            pass   # non-fatal; backup still exists on disk

    # ------------------------------------------------------------------
    # Core backup
    # ------------------------------------------------------------------

    def create_backup(self, project_path: str) -> Tuple[bool, str, Optional[GitBackupRecord]]:
        """
        Create a full external Git backup of project_path.
        Returns (success, message, record).

        Steps:
        1. git bundle create <backup_root>/<id>.bundle --all
        2. git diff HEAD > <id>.patch  (staged + unstaged)
        3. Copy untracked files into a subdirectory
        4. Verify bundle by running git bundle verify
        """
        project_key = os.path.normcase(os.path.abspath(project_path))
        backup_id   = f"{int(time.time())}_{hashlib.sha256(project_key.encode()).hexdigest()[:8]}"
        backup_dir  = os.path.join(self._root, backup_id)
        os.makedirs(backup_dir, exist_ok=True)

        bundle_path   = os.path.join(backup_dir, "repo.bundle")
        patch_path    = os.path.join(backup_dir, "worktree.patch")
        untracked_dir = os.path.join(backup_dir, "untracked")

        try:
            # 1. Bundle (all refs)
            result = subprocess.run(
                ["git", "bundle", "create", bundle_path, "--all"],
                cwd=project_path, capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                return False, f"git bundle failed: {result.stderr.strip()}", None

            # 2. Staged + unstaged diff
            with open(patch_path, "w", encoding="utf-8") as pf:
                r2 = subprocess.run(
                    ["git", "diff", "HEAD"],
                    cwd=project_path, capture_output=True, text=True, timeout=30
                )
                pf.write(r2.stdout)

            # 3. Untracked files
            os.makedirs(untracked_dir, exist_ok=True)
            r3 = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=project_path, capture_output=True, text=True, timeout=30
            )
            for rel_path in r3.stdout.strip().splitlines():
                src = os.path.join(project_path, rel_path)
                dst = os.path.join(untracked_dir, rel_path)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    pass

            # 4. Verify bundle
            verify = subprocess.run(
                ["git", "bundle", "verify", bundle_path],
                cwd=project_path, capture_output=True, text=True, timeout=30
            )
            verified = verify.returncode == 0

            # Get HEAD SHA and branch
            head_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=project_path, capture_output=True, text=True, timeout=10
            ).stdout.strip()

            branch = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=project_path, capture_output=True, text=True, timeout=10
            ).stdout.strip()

            verify_hash = ""
            if os.path.isfile(bundle_path):
                h = hashlib.sha256()
                with open(bundle_path, "rb") as bf:
                    for chunk in iter(lambda: bf.read(65536), b""):
                        h.update(chunk)
                verify_hash = h.hexdigest()[:16]

            record = GitBackupRecord(
                backup_id=backup_id,
                project_path=project_key,
                timestamp=time.time(),
                bundle_path=bundle_path,
                patch_path=patch_path,
                untracked_tar=untracked_dir,
                head_sha=head_sha,
                branch=branch,
                verified=verified,
                verify_hash=verify_hash,
            )

            if project_key not in self._index:
                self._index[project_key] = []
            self._index[project_key].append(record)
            self._save_index()

            msg = f"Git backup created: {backup_id} (verified={verified})"
            return verified, msg, record

        except subprocess.TimeoutExpired:
            return False, "Git backup timed out", None
        except OSError as e:
            return False, f"Git backup OS error: {e}", None

    def latest_verified_backup(self, project_path: str) -> Optional[GitBackupRecord]:
        """Return the most recent verified backup for project_path, or None."""
        key = os.path.normcase(os.path.abspath(project_path))
        records = self._index.get(key, [])
        verified = [r for r in records if r.verified]
        if not verified:
            return None
        return max(verified, key=lambda r: r.timestamp)

    def has_verified_backup(self, project_path: str, max_age_seconds: int = 300) -> bool:
        """Return True when a fresh, verified backup exists."""
        rec = self.latest_verified_backup(project_path)
        if rec is None:
            return False
        return (time.time() - rec.timestamp) <= max_age_seconds

    def is_destructive_git_op(self, command: str) -> bool:
        """
        Return True when the command targets .git metadata destructively
        and therefore requires a verified external Git backup before running.
        """
        lower = command.lower().strip()
        tokens = lower.split()
        if not tokens or tokens[0] != "git":
            # Also catch direct manipulation of .git
            return ".git" in lower and any(v in tokens for v in ("rm", "mv", "cp", "del"))

        sub = tokens[1] if len(tokens) > 1 else ""
        destructive_subs = {
            "push",        # rewrites remote history (--force)
            "reset",       # --hard discards uncommitted changes
            "clean",       # removes untracked files
            "rebase",      # rewrites local history
            "gc",          # garbage-collects loose objects
            "prune",       # removes unreachable objects
            "filter-branch",  # rewrites history
            "filter-repo",
        }
        return sub in destructive_subs


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_net = GitSafetyNet()


def is_destructive_git_op(command: str) -> bool:
    return _net.is_destructive_git_op(command)


def has_verified_backup(project_path: str, max_age_seconds: int = 300) -> bool:
    return _net.has_verified_backup(project_path, max_age_seconds)


def create_backup(project_path: str) -> Tuple[bool, str, Optional[GitBackupRecord]]:
    return _net.create_backup(project_path)


def latest_backup(project_path: str) -> Optional[GitBackupRecord]:
    return _net.latest_verified_backup(project_path)
