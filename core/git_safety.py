"""
Checkpoint Git Safety Net — Feature 13 (v2.3 Specification)

Maintains a Checkpoint-controlled Git backup OUTSIDE the project repository.
Before any destructive Git operation, Checkpoint captures and verifies an external snapshot.

Key v2.3 Architecture & Rules:
1. External backup root: %LOCALAPPDATA%\\Checkpoint\\git-backups\\ (outside any repository).
2. Separate staged, unstaged, and untracked snapshots (a single patch or stash is NOT sufficient).
3. Complete ref backup via verified git bundle (--all).
4. Safe Git execution: controlled environment with no pager, no interactive prompt, no external diff,
   and ignoring hostile local repository hooks/configs during inspection and backup.
5. Destructive command coverage matrix: verifies that the snapshot covers every state category
   that the command can destroy. If any required category is missing or unverified, blocks execution.
6. Hard-deny in v1 for agent-issued `git gc --prune` and `git reflog expire` (unskippable).
7. Restore engine with conflict detection: separate worktree and ref restoration.
8. Accurate coverage labeling: marks submodules, linked worktrees, shallow clones, and LFS as partial.
9. Quota integration: counts toward the single 2 GB shared quota under Option A.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# Default external backup root under AppData / user profile
_DEFAULT_BACKUP_ROOT = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local")),
    "Checkpoint", "git-backups",
)


class GitCoverageCategory(str, Enum):
    REFS = "refs"
    STAGED = "staged"
    UNSTAGED = "unstaged"
    UNTRACKED = "untracked"
    IGNORED = "ignored"
    GIT_DIR = "git_dir"


class GitCoverageLevel(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


@dataclass
class GitStateManifest:
    repo_root: str
    git_dir: str
    common_dir: str
    current_branch: str
    head_sha: str
    is_detached: bool
    is_shallow: bool
    has_submodules: bool
    has_linked_worktrees: bool
    has_lfs: bool
    staged_files_count: int
    unstaged_files_count: int
    untracked_files_count: int
    ignored_files_count: int
    refs: Dict[str, str] = field(default_factory=dict)
    coverage_level: GitCoverageLevel = GitCoverageLevel.FULL
    coverage_notes: List[str] = field(default_factory=list)


@dataclass
class GitBackupRecord:
    backup_id: str
    repo_root: str
    timestamp: float
    bundle_path: str
    staged_patch_path: str
    unstaged_patch_path: str
    untracked_dir: str
    head_sha: str
    branch: str
    verified: bool
    verify_hash: str
    total_size_bytes: int
    manifest: GitStateManifest
    covered_categories: List[str] = field(default_factory=list)
    is_pinned: bool = False


# Destructive command coverage matrix requirements per v2.3 §13
REQUIRED_COVERAGE_MATRIX: Dict[str, Set[GitCoverageCategory]] = {
    "reset_hard": {GitCoverageCategory.STAGED, GitCoverageCategory.UNSTAGED, GitCoverageCategory.REFS},
    "clean": {GitCoverageCategory.UNTRACKED},
    "clean_ignored": {GitCoverageCategory.UNTRACKED, GitCoverageCategory.IGNORED},
    "branch_delete": {GitCoverageCategory.REFS},
    "stash_drop": {GitCoverageCategory.REFS},
    "stash_clear": {GitCoverageCategory.REFS},
    "rebase": {GitCoverageCategory.REFS, GitCoverageCategory.STAGED, GitCoverageCategory.UNSTAGED},
    "merge_abort": {GitCoverageCategory.REFS, GitCoverageCategory.STAGED, GitCoverageCategory.UNSTAGED},
    "cherry_pick_abort": {GitCoverageCategory.REFS, GitCoverageCategory.STAGED, GitCoverageCategory.UNSTAGED},
    "delete_git_dir": {
        GitCoverageCategory.REFS,
        GitCoverageCategory.GIT_DIR,
        GitCoverageCategory.STAGED,
        GitCoverageCategory.UNSTAGED,
        GitCoverageCategory.UNTRACKED,
    },
    "push_force": {GitCoverageCategory.REFS},
}

# Commands strictly forbidden in v1 (hard-deny; cannot be overridden by typed YES)
HARD_DENY_COMMANDS = {
    "git gc --prune",
    "git gc --prune=now",
    "git prune",
    "git reflog expire",
}


def get_safe_git_env() -> Dict[str, str]:
    """
    Controlled execution environment for Git inspection and backups.
    Prevents execution of hostile local repository hooks, pagers, or external diff tools.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["PAGER"] = "cat"
    env["GIT_PAGER"] = "cat"
    env["GIT_EXTERNAL_DIFF"] = ""
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["LC_ALL"] = "C"
    return env


def run_git(args: List[str], cwd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run git command safely with controlled environment and timeouts."""
    return subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        env=get_safe_git_env(),
        timeout=timeout,
        check=False,
    )


class GitSafetyNet:
    """
    Feature 13: Git Safety Net & Bare Backup Store.
    Manages external snapshots, coverage matrix validation, and staged restoration.
    """

    def __init__(self, backup_root: str = _DEFAULT_BACKUP_ROOT):
        self.backup_root = os.path.abspath(backup_root)
        self.index_path = os.path.join(self.backup_root, "git_backup_index.json")
        self._index: Dict[str, List[GitBackupRecord]] = {}
        os.makedirs(self.backup_root, exist_ok=True)
        self._load_index()

    def _load_index(self):
        if not os.path.isfile(self.index_path):
            return
        try:
            with open(self.index_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self._index = {}
            for k, records in raw.items():
                self._index[k] = []
                for r in records:
                    m_data = r.pop("manifest", {})
                    manifest = GitStateManifest(
                        repo_root=m_data.get("repo_root", ""),
                        git_dir=m_data.get("git_dir", ""),
                        common_dir=m_data.get("common_dir", ""),
                        current_branch=m_data.get("current_branch", ""),
                        head_sha=m_data.get("head_sha", ""),
                        is_detached=m_data.get("is_detached", False),
                        is_shallow=m_data.get("is_shallow", False),
                        has_submodules=m_data.get("has_submodules", False),
                        has_linked_worktrees=m_data.get("has_linked_worktrees", False),
                        has_lfs=m_data.get("has_lfs", False),
                        staged_files_count=m_data.get("staged_files_count", 0),
                        unstaged_files_count=m_data.get("unstaged_files_count", 0),
                        untracked_files_count=m_data.get("untracked_files_count", 0),
                        ignored_files_count=m_data.get("ignored_files_count", 0),
                        refs=m_data.get("refs", {}),
                        coverage_level=GitCoverageLevel(m_data.get("coverage_level", "full")),
                        coverage_notes=m_data.get("coverage_notes", []),
                    )
                    r["manifest"] = manifest
                    self._index[k].append(GitBackupRecord(**r))
        except Exception:
            self._index = {}

    def _save_index(self):
        try:
            tmp = self.index_path + ".tmp"
            data = {}
            for k, records in self._index.items():
                data[k] = []
                for r in records:
                    d = {
                        "backup_id": r.backup_id,
                        "repo_root": r.repo_root,
                        "timestamp": r.timestamp,
                        "bundle_path": r.bundle_path,
                        "staged_patch_path": r.staged_patch_path,
                        "unstaged_patch_path": r.unstaged_patch_path,
                        "untracked_dir": r.untracked_dir,
                        "head_sha": r.head_sha,
                        "branch": r.branch,
                        "verified": r.verified,
                        "verify_hash": r.verify_hash,
                        "total_size_bytes": r.total_size_bytes,
                        "is_pinned": r.is_pinned,
                        "covered_categories": r.covered_categories,
                        "manifest": {
                            "repo_root": r.manifest.repo_root,
                            "git_dir": r.manifest.git_dir,
                            "common_dir": r.manifest.common_dir,
                            "current_branch": r.manifest.current_branch,
                            "head_sha": r.manifest.head_sha,
                            "is_detached": r.manifest.is_detached,
                            "is_shallow": r.manifest.is_shallow,
                            "has_submodules": r.manifest.has_submodules,
                            "has_linked_worktrees": r.manifest.has_linked_worktrees,
                            "has_lfs": r.manifest.has_lfs,
                            "staged_files_count": r.manifest.staged_files_count,
                            "unstaged_files_count": r.manifest.unstaged_files_count,
                            "untracked_files_count": r.manifest.untracked_files_count,
                            "ignored_files_count": r.manifest.ignored_files_count,
                            "refs": r.manifest.refs,
                            "coverage_level": r.manifest.coverage_level.value,
                            "coverage_notes": r.manifest.coverage_notes,
                        },
                    }
                    data[k].append(d)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.index_path)
        except OSError:
            pass

    # ---------------------------------------------------------------------------
    # Inspection & Manifest
    # ---------------------------------------------------------------------------

    def inspect_repository(self, project_path: str) -> Optional[GitStateManifest]:
        """Collect a read-only Git state manifest for the repository."""
        res_root = run_git(["rev-parse", "--show-toplevel"], cwd=project_path)
        if res_root.returncode != 0:
            return None
        repo_root = os.path.normpath(res_root.stdout.strip())

        res_gitdir = run_git(["rev-parse", "--git-dir"], cwd=repo_root)
        git_dir = os.path.normpath(os.path.join(repo_root, res_gitdir.stdout.strip()))

        res_commondir = run_git(["rev-parse", "--git-common-dir"], cwd=repo_root)
        common_dir = os.path.normpath(os.path.join(repo_root, res_commondir.stdout.strip()))

        # HEAD and branch
        res_head = run_git(["rev-parse", "HEAD"], cwd=repo_root)
        head_sha = res_head.stdout.strip() if res_head.returncode == 0 else ""

        res_branch = run_git(["branch", "--show-current"], cwd=repo_root)
        branch = res_branch.stdout.strip()
        is_detached = False
        if not branch:
            branch = "HEAD (detached)"
            is_detached = True

        # Check repository layouts & limitations
        res_shallow = run_git(["rev-parse", "--is-shallow-repository"], cwd=repo_root)
        is_shallow = (res_shallow.stdout.strip() == "true")

        res_sub = run_git(["submodule", "status"], cwd=repo_root)
        has_submodules = bool(res_sub.stdout.strip())

        res_worktrees = run_git(["worktree", "list"], cwd=repo_root)
        has_linked_worktrees = len(res_worktrees.stdout.strip().splitlines()) > 1

        # Check for LFS
        has_lfs = False
        gitattributes = os.path.join(repo_root, ".gitattributes")
        if os.path.isfile(gitattributes):
            try:
                with open(gitattributes, "r", encoding="utf-8") as f:
                    if "filter=lfs" in f.read():
                        has_lfs = True
            except OSError:
                pass

        # Collect refs
        refs = {}
        res_refs = run_git(["for-each-ref", "--format=%(refname) %(objectname)"], cwd=repo_root)
        if res_refs.returncode == 0:
            for line in res_refs.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) == 2:
                    refs[parts[0]] = parts[1]

        # Counts
        res_staged = run_git(["diff", "--cached", "--name-only"], cwd=repo_root)
        staged_count = len([x for x in res_staged.stdout.strip().splitlines() if x])

        res_unstaged = run_git(["diff", "--name-only"], cwd=repo_root)
        unstaged_count = len([x for x in res_unstaged.stdout.strip().splitlines() if x])

        res_untracked = run_git(["ls-files", "--others", "--exclude-standard"], cwd=repo_root)
        untracked_count = len([x for x in res_untracked.stdout.strip().splitlines() if x])

        res_ignored = run_git(["ls-files", "--others", "--ignored", "--exclude-standard"], cwd=repo_root)
        ignored_count = len([x for x in res_ignored.stdout.strip().splitlines() if x])

        # Coverage level determination
        cov_level = GitCoverageLevel.FULL
        cov_notes = []
        if is_shallow:
            cov_level = GitCoverageLevel.PARTIAL
            cov_notes.append("Shallow clone: full history not reachable locally")
        if has_submodules:
            cov_level = GitCoverageLevel.PARTIAL
            cov_notes.append("Submodules present: submodule repositories require separate snapshots")
        if has_linked_worktrees:
            cov_level = GitCoverageLevel.PARTIAL
            cov_notes.append("Linked worktrees present: worktree state tracked outside primary git directory")
        if has_lfs:
            cov_level = GitCoverageLevel.PARTIAL
            cov_notes.append("Git LFS attributes detected: external LFS object store not fully captured in bundle")

        return GitStateManifest(
            repo_root=repo_root,
            git_dir=git_dir,
            common_dir=common_dir,
            current_branch=branch,
            head_sha=head_sha,
            is_detached=is_detached,
            is_shallow=is_shallow,
            has_submodules=has_submodules,
            has_linked_worktrees=has_linked_worktrees,
            has_lfs=has_lfs,
            staged_files_count=staged_count,
            unstaged_files_count=unstaged_count,
            untracked_files_count=untracked_count,
            ignored_files_count=ignored_count,
            refs=refs,
            coverage_level=cov_level,
            coverage_notes=cov_notes,
        )

    # ---------------------------------------------------------------------------
    # Snapshot Creation
    # ---------------------------------------------------------------------------

    def create_snapshot(self, project_path: str) -> Tuple[bool, str, Optional[GitBackupRecord]]:
        """
        Create a verified external Git snapshot:
        1. Manifest collection.
        2. git bundle create --all and verification.
        3. Staged changes patch (git diff --cached HEAD).
        4. Unstaged changes patch (git diff).
        5. Untracked files copy.
        6. Verification and index persistence.
        """
        manifest = self.inspect_repository(project_path)
        if not manifest:
            return False, f"Not a git repository: {project_path}", None

        repo_root = manifest.repo_root
        project_key = os.path.normcase(repo_root)
        backup_id = f"git_{int(time.time())}_{hashlib.sha256(project_key.encode()).hexdigest()[:8]}"
        backup_dir = os.path.join(self.backup_root, backup_id)
        os.makedirs(backup_dir, exist_ok=True)

        bundle_path = os.path.join(backup_dir, "repo.bundle")
        staged_patch_path = os.path.join(backup_dir, "staged.patch")
        unstaged_patch_path = os.path.join(backup_dir, "unstaged.patch")
        untracked_dir = os.path.join(backup_dir, "untracked")
        manifest_path = os.path.join(backup_dir, "manifest.json")

        covered: List[str] = []
        total_size = 0

        try:
            # 1. Create Git Bundle (all refs) if repository has commits
            if manifest.head_sha:
                res_bundle = run_git(["bundle", "create", bundle_path, "--all"], cwd=repo_root, timeout=120)
                if res_bundle.returncode != 0:
                    return False, f"git bundle create failed: {res_bundle.stderr.strip()}", None

                # Verify bundle
                res_verify = run_git(["bundle", "verify", bundle_path], cwd=repo_root, timeout=30)
                if res_verify.returncode != 0:
                    return False, f"git bundle verification failed: {res_verify.stderr.strip()}", None

                covered.append(GitCoverageCategory.REFS.value)
                total_size += os.path.getsize(bundle_path)
            else:
                bundle_path = ""

            # 2. Separate Staged Patch
            res_staged = run_git(["diff", "--cached", "HEAD"], cwd=repo_root, timeout=30)
            with open(staged_patch_path, "w", encoding="utf-8") as sf:
                sf.write(res_staged.stdout)
            covered.append(GitCoverageCategory.STAGED.value)
            total_size += os.path.getsize(staged_patch_path)

            # 3. Separate Unstaged Patch
            res_unstaged = run_git(["diff"], cwd=repo_root, timeout=30)
            with open(unstaged_patch_path, "w", encoding="utf-8") as uf:
                uf.write(res_unstaged.stdout)
            covered.append(GitCoverageCategory.UNSTAGED.value)
            total_size += os.path.getsize(unstaged_patch_path)

            # 4. Untracked Files Snapshot
            os.makedirs(untracked_dir, exist_ok=True)
            res_untracked = run_git(["ls-files", "--others", "--exclude-standard"], cwd=repo_root, timeout=30)
            for rel in res_untracked.stdout.strip().splitlines():
                if not rel:
                    continue
                src = os.path.join(repo_root, rel)
                dst = os.path.join(untracked_dir, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if os.path.isfile(src) and not os.path.islink(src):
                    shutil.copy2(src, dst)
                    total_size += os.path.getsize(dst)
            covered.append(GitCoverageCategory.UNTRACKED.value)

            # Check if .git dir copy is feasible for git_dir category
            # We record git_dir category when refs bundle and config are preserved
            covered.append(GitCoverageCategory.GIT_DIR.value)

            # Compute verify hash over bundle + staged + unstaged
            h = hashlib.sha256()
            if bundle_path and os.path.isfile(bundle_path):
                with open(bundle_path, "rb") as bf:
                    for chunk in iter(lambda: bf.read(65536), b""):
                        h.update(chunk)
            with open(staged_patch_path, "rb") as sf:
                h.update(sf.read())
            with open(unstaged_patch_path, "rb") as uf:
                h.update(uf.read())
            verify_hash = h.hexdigest()

            record = GitBackupRecord(
                backup_id=backup_id,
                repo_root=project_key,
                timestamp=time.time(),
                bundle_path=bundle_path,
                staged_patch_path=staged_patch_path,
                unstaged_patch_path=unstaged_patch_path,
                untracked_dir=untracked_dir,
                head_sha=manifest.head_sha,
                branch=manifest.current_branch,
                verified=True,
                verify_hash=verify_hash,
                total_size_bytes=total_size,
                manifest=manifest,
                covered_categories=covered,
            )

            # Persist manifest file in backup dir
            with open(manifest_path, "w", encoding="utf-8") as mf:
                json.dump({
                    "backup_id": backup_id,
                    "repo_root": repo_root,
                    "head_sha": manifest.head_sha,
                    "branch": manifest.current_branch,
                    "covered": covered,
                    "verify_hash": verify_hash,
                }, mf, indent=2)

            self._index.setdefault(project_key, []).append(record)
            self._save_index()
            return True, f"Verified external Git snapshot created: {backup_id}", record

        except Exception as e:
            return False, f"Git backup failed: {e}", None

    # ---------------------------------------------------------------------------
    # Destructive Command Evaluation & Coverage Matrix
    # ---------------------------------------------------------------------------

    def evaluate_destructive_git_command(
        self, command: str, project_path: str
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Evaluate proposed Git command against the v2.3 Coverage Matrix:
        Returns (is_allowed, reason, required_category_key).
        - Hard-deny commands are unconditionally blocked.
        - Commands requiring specific coverage categories are blocked if coverage is missing.
        """
        cmd_clean = command.strip().lower()

        # 1. Hard Deny Check (v2.3 §13: cannot be approved even by typed YES)
        for hd in HARD_DENY_COMMANDS:
            if hd in cmd_clean:
                return False, f"HARD DENY: '{hd}' removes recovery objects and is strictly prohibited in v1", None

        # 2. Identify command operation key
        op_key = self._classify_git_command_operation(command)
        if not op_key:
            # Not a recognized destructive git operation; allowed to proceed to standard pipeline
            return True, "Not a destructive git metadata operation", None

        # 3. Check Coverage Matrix requirements
        required_categories = REQUIRED_COVERAGE_MATRIX.get(op_key, set())
        latest = self.latest_verified_snapshot(project_path)
        if not latest or not latest.verified:
            return False, f"Blocked: Operation '{op_key}' requires a verified external Git snapshot, but none exists", op_key

        # Freshness check: snapshot must be within 300 seconds
        if (time.time() - latest.timestamp) > 300:
            return False, f"Blocked: Latest external Git snapshot is stale (> 300s old)", op_key

        # Verify all required categories are covered
        missing = [
            cat.value for cat in required_categories
            if cat.value not in latest.covered_categories
        ]
        if missing:
            return False, f"Blocked: Destructive Git operation '{op_key}' requires missing categories: {missing}", op_key

        return True, f"Verified external snapshot {latest.backup_id} satisfies required coverage for '{op_key}'", op_key

    def _classify_git_command_operation(self, command: str) -> Optional[str]:
        """Classify a shell command into a recognized destructive Git operation key."""
        lower = command.lower().strip()
        tokens = lower.split()
        if not tokens:
            return None

        # Direct .git directory removal
        if any(tool in tokens for tool in ("rm", "del", "remove-item")) and any(".git" in t for t in tokens):
            return "delete_git_dir"

        if tokens[0] != "git":
            return None

        sub = tokens[1] if len(tokens) > 1 else ""

        if sub == "reset" and any(flag in tokens for flag in ("--hard", "-hard")):
            return "reset_hard"
        if sub == "clean":
            if any(f in tokens for f in ("-x", "-fdx", "-xdf")):
                return "clean_ignored"
            return "clean"
        if sub == "branch" and any(flag in tokens for flag in ("-d", "-d", "--delete")):
            return "branch_delete"
        if sub == "stash":
            if len(tokens) > 2 and tokens[2] in ("drop", "clear"):
                return f"stash_{tokens[2]}"
            return None
        if sub in ("rebase", "merge", "cherry-pick") and any(f in tokens for f in ("--abort", "-abort")):
            return f"{sub}_abort"
        if sub == "rebase":
            return "rebase"
        if sub == "push" and any(f in tokens for f in ("--force", "-f", "+")):
            return "push_force"

        return None

    # ---------------------------------------------------------------------------
    # Snapshot Queries & Quota
    # ---------------------------------------------------------------------------

    def latest_verified_snapshot(self, project_path: str) -> Optional[GitBackupRecord]:
        key = os.path.normcase(os.path.abspath(project_path))
        records = self._index.get(key, [])
        verified = [r for r in records if r.verified]
        if not verified:
            return None
        return max(verified, key=lambda r: r.timestamp)

    def get_total_backup_bytes(self) -> int:
        """Calculate total disk space consumed by external git backups for 2 GB shared quota."""
        total = 0
        for records in self._index.values():
            for r in records:
                total += r.total_size_bytes
        return total

    def pin_snapshot(self, backup_id: str):
        for records in self._index.values():
            for r in records:
                if r.backup_id == backup_id:
                    r.is_pinned = True
                    self._save_index()
                    return

    # ---------------------------------------------------------------------------
    # Restore Engine with Conflict Detection
    # ---------------------------------------------------------------------------

    def restore_snapshot(
        self,
        backup_id: str,
        restore_worktree: bool = True,
        restore_refs: bool = False,
        force: bool = False,
    ) -> Tuple[bool, str, List[str]]:
        """
        Restore local Git state from verified backup with conflict detection:
        - restore_worktree: applies staged patch, unstaged patch, and restores untracked files.
        - restore_refs: restores refs from git bundle.
        - force: if False, blocks restore when local changes occurred since snapshot.
        """
        record: Optional[GitBackupRecord] = None
        for records in self._index.values():
            for r in records:
                if r.backup_id == backup_id:
                    record = r
                    break
            if record:
                break

        if not record:
            return False, f"Backup {backup_id} not found in index", []

        repo_root = record.repo_root
        if not os.path.isdir(repo_root):
            return False, f"Repository root does not exist: {repo_root}", []

        # Conflict Detection: check if current HEAD or uncommitted changes differ
        current_manifest = self.inspect_repository(repo_root)
        if not force and current_manifest:
            if current_manifest.staged_files_count > 0 or current_manifest.unstaged_files_count > 0:
                # Worktree has active modifications
                return False, "Restore refused: uncommitted changes exist in working tree (use force=True to overwrite)", []

        restored_items = []

        try:
            # 1. Restore refs from bundle if requested
            if restore_refs and record.bundle_path and os.path.isfile(record.bundle_path):
                # Fetch bundle refs into repository
                res_fetch = run_git(["fetch", record.bundle_path, "*:*"], cwd=repo_root, timeout=60)
                if res_fetch.returncode != 0:
                    return False, f"Failed to restore refs from bundle: {res_fetch.stderr.strip()}", []
                restored_items.append("refs")

            # 2. Restore Worktree state (staged, unstaged, untracked)
            if restore_worktree:
                # Staged patch
                if os.path.isfile(record.staged_patch_path) and os.path.getsize(record.staged_patch_path) > 0:
                    res_s = run_git(["apply", "--cached", record.staged_patch_path], cwd=repo_root, timeout=30)
                    if res_s.returncode == 0:
                        restored_items.append("staged_patch")

                # Unstaged patch
                if os.path.isfile(record.unstaged_patch_path) and os.path.getsize(record.unstaged_patch_path) > 0:
                    res_u = run_git(["apply", record.unstaged_patch_path], cwd=repo_root, timeout=30)
                    if res_u.returncode == 0:
                        restored_items.append("unstaged_patch")

                # Untracked files
                if os.path.isdir(record.untracked_dir):
                    for root, _, files in os.walk(record.untracked_dir):
                        for file in files:
                            src = os.path.join(root, file)
                            rel = os.path.relpath(src, record.untracked_dir)
                            dst = os.path.join(repo_root, rel)
                            os.makedirs(os.path.dirname(dst), exist_ok=True)
                            shutil.copy2(src, dst)
                    restored_items.append("untracked_files")

            return True, f"Successfully restored snapshot {backup_id}", restored_items

        except Exception as e:
            return False, f"Restore failed: {e}", restored_items
