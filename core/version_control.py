"""
Version control, file snapshotting, rollback, and Option A retention for Checkpoint.
Feature 7 / Milestone 1.

Specification rules:
- Content-addressed blob store holds unique file versions compressed.
- SQLite tables: blobs, versions, action_files, pins, trash_items, restore_journal.
- Explicit states: 'file', 'symlink', 'deleted' (deleted is never confused with an empty file).
- Before and after snapshots per action.
- Conflict detection before restore: detects if current file differs from snapshot state.
- Staged restore with recovery journal: safe atomic write on same disk, verified after write.
- Option A quota management:
  - 50 MB per file limit.
  - 2 GB shared recovery quota across blobs, external Git backups, and trash.
  - Cleanup checks begin at 80% (warning) and 95% (critical warning).
  - 30-day retention for unpinned snapshots and trash.
  - Quota reclamation NEVER purges unexpired data (< 30 days) early.
  - Reclaim order: (1) oldest expired trash items, then (2) oldest expired unpinned snapshots.
  - Pinned versions never purged.
  - If eligible cleanup cannot free required headroom, operation is safely blocked.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.blob_store import BlobStore, FileTooLargeError, MAX_FILE_BYTES, EMPTY_SHA256

# Option A policies
SHARED_QUOTA_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB
RETENTION_DAYS = 30
QUOTA_WARN_80 = 0.80
QUOTA_WARN_95 = 0.95


class VersionControlError(Exception):
    """Base exception for version control and rollback errors."""
    pass


class PathTraversalError(VersionControlError):
    """Raised when a path escapes the allowed workspace root."""
    pass


class RestoreConflictError(VersionControlError):
    """Raised when target file on disk differs from expected snapshot state."""
    pass


class QuotaExhaustedError(VersionControlError):
    """Raised when shared recovery quota cannot accommodate new backup even after eligible reclamation."""
    pass


@dataclass
class VersionRecord:
    id: int
    action_id: Optional[int]
    file_path: str
    blob_hash: Optional[str]
    state: str  # 'file', 'symlink', 'deleted'
    target: Optional[str]
    file_mode: Optional[int]
    mtime: Optional[float]
    created_at: str


@dataclass
class ConflictInfo:
    file_path: str
    reason: str
    disk_mtime: float
    expected_mtime: Optional[float]


@dataclass
class RestoreResult:
    success: bool
    restored_files: List[str] = field(default_factory=list)
    conflicts: List[ConflictInfo] = field(default_factory=list)
    message: str = ""


@dataclass
class QuotaUsage:
    total_quota: int
    used_bytes: int
    blob_bytes: int
    trash_bytes: int
    git_backup_bytes: int
    free_bytes: int
    percent_used: float
    warn_80: bool
    warn_95: bool


class VersionControl:
    """
    Manages snapshots, file versioning, rollback with conflict detection,
    and Option A quota enforcement.
    """

    def __init__(self, db_path: str, blob_store: BlobStore, workspace_root: str):
        self.db_path = os.path.abspath(db_path)
        self.blob_store = blob_store
        self.workspace_root = os.path.abspath(workspace_root)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _canonical_path(self, path: str) -> str:
        """Resolve path and verify it stays within workspace root (prevent traversal)."""
        abs_p = os.path.abspath(path)
        # Check traversal
        try:
            rel = os.path.relpath(abs_p, self.workspace_root)
            if rel.startswith("..") and not os.path.samefile(abs_p, self.workspace_root):
                raise PathTraversalError(
                    f"Path '{abs_p}' escapes permitted workspace root '{self.workspace_root}'"
                )
        except ValueError:
            # Different drive letters on Windows
            raise PathTraversalError(
                f"Path '{abs_p}' is on a different drive than workspace root '{self.workspace_root}'"
            )
        return abs_p

    # ---------------------------------------------------------------------------
    # Snapshotting API
    # ---------------------------------------------------------------------------

    def snapshot_file(self, file_path: str, action_id: Optional[int] = None) -> VersionRecord:
        """
        Snapshot a single file or symlink.
        If file does not exist, records explicit state='deleted'.
        """
        canon = self._canonical_path(file_path)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Check if symlink/reparse point
        if os.path.islink(canon):
            target = os.readlink(canon)
            st = os.lstat(canon)
            rec = self._insert_version(
                action_id=action_id,
                file_path=canon,
                blob_hash=None,
                state="symlink",
                target=target,
                file_mode=st.st_mode,
                mtime=st.st_mtime,
                created_at=ts
            )
            return rec

        if not os.path.exists(canon):
            # Deleted state
            rec = self._insert_version(
                action_id=action_id,
                file_path=canon,
                blob_hash=None,
                state="deleted",
                target=None,
                file_mode=None,
                mtime=None,
                created_at=ts
            )
            return rec

        # Regular file (including 0-byte file)
        st = os.stat(canon)
        blob_info = self.blob_store.put_file(canon)

        # Record blob in blobs table if not already present
        self._record_blob_metadata(blob_info.blob_hash, blob_info.original_size, blob_info.compressed_size)

        rec = self._insert_version(
            action_id=action_id,
            file_path=canon,
            blob_hash=blob_info.blob_hash,
            state="file",
            target=None,
            file_mode=st.st_mode,
            mtime=st.st_mtime,
            created_at=ts
        )
        return rec

    def snapshot_directory(self, dir_path: str, action_id: Optional[int] = None,
                           exclude_regenerable: bool = True) -> List[VersionRecord]:
        """Recursively snapshot all files and symlinks in a directory."""
        canon_dir = self._canonical_path(dir_path)
        records: List[VersionRecord] = []

        if not os.path.exists(canon_dir):
            return records

        regen_folders = {".venv", "venv", "node_modules", "__pycache__", "build", "dist"}

        for root, dirs, files in os.walk(canon_dir, followlinks=False):
            if exclude_regenerable:
                dirs[:] = [d for d in dirs if d not in regen_folders]

            for fname in files:
                fpath = os.path.join(root, fname)
                rec = self.snapshot_file(fpath, action_id=action_id)
                records.append(rec)

        return records

    def record_action_files(self, action_id: int, file_path: str,
                            before_blob_id: Optional[str], after_blob_id: Optional[str],
                            coverage: str = "complete"):
        """Record before/after mapping for an action."""
        canon = self._canonical_path(file_path)
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO action_files (action_id, file_path, before_blob_id, after_blob_id, coverage)
                VALUES (?, ?, ?, ?, ?)
            """, (action_id, canon, before_blob_id, after_blob_id, coverage))
            conn.commit()

    def _insert_version(self, action_id: Optional[int], file_path: str,
                        blob_hash: Optional[str], state: str,
                        target: Optional[str], file_mode: Optional[int],
                        mtime: Optional[float], created_at: str) -> VersionRecord:
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO versions (action_id, file_path, blob_hash, state, target, file_mode, mtime, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (action_id, file_path, blob_hash, state, target, file_mode, mtime, created_at))
            vid = cur.lastrowid
            conn.commit()

        return VersionRecord(
            id=vid,
            action_id=action_id,
            file_path=file_path,
            blob_hash=blob_hash,
            state=state,
            target=target,
            file_mode=file_mode,
            mtime=mtime,
            created_at=created_at
        )

    def _record_blob_metadata(self, blob_hash: str, original_size: int, compressed_size: int):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO blobs (blob_hash, original_size, compressed_size, created_at)
                VALUES (?, ?, ?, ?)
            """, (blob_hash, original_size, compressed_size, ts))
            conn.commit()

    def get_version(self, version_id: int) -> Optional[VersionRecord]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM versions WHERE id=?", (version_id,)).fetchone()
            if not row:
                return None
            return VersionRecord(
                id=row[0], action_id=row[1], file_path=row[2],
                blob_hash=row[3], state=row[4], target=row[5],
                file_mode=row[6], mtime=row[7], created_at=row[8]
            )

    # ---------------------------------------------------------------------------
    # Restore Engine with Conflict Detection
    # ---------------------------------------------------------------------------

    def detect_conflicts(self, version_id: int) -> List[ConflictInfo]:
        """
        Check if the target file currently on disk differs from the state when the version was captured.
        """
        ver = self.get_version(version_id)
        if not ver:
            raise VersionControlError(f"Version #{version_id} not found")

        conflicts: List[ConflictInfo] = []
        path = ver.file_path

        if ver.state == "file":
            if not os.path.exists(path):
                conflicts.append(ConflictInfo(
                    file_path=path,
                    reason="Target file was deleted after snapshot was taken",
                    disk_mtime=0.0,
                    expected_mtime=ver.mtime
                ))
            else:
                curr_mtime = os.path.getmtime(path)
                curr_size = os.path.getsize(path)
                # Compute current hash
                with open(path, "rb") as f:
                    curr_hash = hashlib.sha256(f.read()).hexdigest()

                if curr_hash != ver.blob_hash:
                    conflicts.append(ConflictInfo(
                        file_path=path,
                        reason="Target file on disk was modified after snapshot",
                        disk_mtime=curr_mtime,
                        expected_mtime=ver.mtime
                    ))

        elif ver.state == "deleted":
            if os.path.exists(path):
                conflicts.append(ConflictInfo(
                    file_path=path,
                    reason="File currently exists on disk but snapshot recorded deleted state",
                    disk_mtime=os.path.getmtime(path),
                    expected_mtime=None
                ))

        elif ver.state == "symlink":
            if not os.path.islink(path):
                conflicts.append(ConflictInfo(
                    file_path=path,
                    reason="Target path is not a symlink on disk",
                    disk_mtime=os.path.getmtime(path) if os.path.exists(path) else 0.0,
                    expected_mtime=ver.mtime
                ))

        return conflicts

    def restore_version(self, version_id: int, force: bool = False) -> RestoreResult:
        """
        Restore a version back to the workspace.
        Uses safe staging on the same drive and records a restore journal entry.
        """
        ver = self.get_version(version_id)
        if not ver:
            return RestoreResult(success=False, message=f"Version #{version_id} not found")

        path = ver.file_path
        conflicts = self.detect_conflicts(version_id)
        if conflicts and not force:
            return RestoreResult(
                success=False,
                conflicts=conflicts,
                message="Restore refused due to conflicts: target file was modified since snapshot"
            )

        restore_id = uuid.uuid4().hex[:12]
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Pre-restore safety backup
        backup_hash = None
        if os.path.exists(path) and not os.path.islink(path):
            backup_blob = self.blob_store.put_file(path)
            backup_hash = backup_blob.blob_hash

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO restore_journal (restore_id, action_id, file_path, staged_path, backup_blob_hash, status, timestamp)
                VALUES (?, ?, ?, ?, ?, 'staged', ?)
            """, (restore_id, ver.action_id, path, None, backup_hash, ts))
            conn.commit()

        try:
            if ver.state == "deleted":
                if os.path.exists(path) or os.path.islink(path):
                    os.remove(path)
            elif ver.state == "symlink":
                if os.path.exists(path) or os.path.islink(path):
                    os.remove(path)
                os.symlink(ver.target, path)
            elif ver.state == "file":
                data = self.blob_store.get_bytes(ver.blob_hash)
                # Staged write on same directory/volume
                parent_dir = os.path.dirname(path)
                os.makedirs(parent_dir, exist_ok=True)
                fd, tmp_stage = tempfile.mkstemp(dir=parent_dir, prefix="restore_staged_", suffix=".tmp")
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())

                os.replace(tmp_stage, path)

                # Restore file attributes/mtime if available
                if ver.mtime is not None:
                    try:
                        os.utime(path, (ver.mtime, ver.mtime))
                    except OSError:
                        pass

            # Verify on-disk file
            if ver.state == "file":
                with open(path, "rb") as f:
                    check_hash = hashlib.sha256(f.read()).hexdigest()
                if check_hash != ver.blob_hash:
                    raise VersionControlError(f"Restore verification failed for {path}")

            with self._connect() as conn:
                conn.execute("""
                    UPDATE restore_journal SET status='verified' WHERE restore_id=?
                """, (restore_id,))
                conn.commit()

            return RestoreResult(success=True, restored_files=[path], message=f"Restored {path}")

        except Exception as e:
            with self._connect() as conn:
                conn.execute("""
                    UPDATE restore_journal SET status='reversed' WHERE restore_id=?
                """, (restore_id,))
                conn.commit()
            return RestoreResult(success=False, message=f"Restore failed: {e}")

    # ---------------------------------------------------------------------------
    # Option A Quota & 30-Day Retention Management
    # ---------------------------------------------------------------------------

    def get_quota_usage(self, git_backup_bytes: int = 0) -> QuotaUsage:
        """
        Calculate the 2 GB shared quota usage across:
        1. Stored compressed blobs
        2. Logical bytes of active trash items
        3. External git backup bytes
        """
        with self._connect() as conn:
            blob_bytes = conn.execute("SELECT COALESCE(SUM(compressed_size), 0) FROM blobs").fetchone()[0]
            trash_bytes = conn.execute(
                "SELECT COALESCE(SUM(logical_size), 0) FROM trash_items WHERE purged_at IS NULL"
            ).fetchone()[0]

        used = blob_bytes + trash_bytes + git_backup_bytes
        free = max(0, SHARED_QUOTA_BYTES - used)
        pct = (used / SHARED_QUOTA_BYTES) * 100.0

        return QuotaUsage(
            total_quota=SHARED_QUOTA_BYTES,
            used_bytes=used,
            blob_bytes=blob_bytes,
            trash_bytes=trash_bytes,
            git_backup_bytes=git_backup_bytes,
            free_bytes=free,
            percent_used=pct,
            warn_80=(pct >= (QUOTA_WARN_80 * 100)),
            warn_95=(pct >= (QUOTA_WARN_95 * 100))
        )

    def record_trash_item(self, original_path: str, trash_path: str, logical_size: int):
        """Record an item moved to trash for quota tracking."""
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO trash_items (original_path, trash_path, logical_size, deleted_at)
                VALUES (?, ?, ?, ?)
            """, (original_path, trash_path, logical_size, ts))
            conn.commit()

    def pin_version(self, version_id: int, reason: str = "user_pinned"):
        """Protect a version from automatic retention cleanup."""
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO pins (version_id, pinned_at, reason)
                VALUES (?, ?, ?)
            """, (version_id, ts, reason))
            conn.commit()

    def unpin_version(self, version_id: int):
        """Unpin a version."""
        with self._connect() as conn:
            conn.execute("DELETE FROM pins WHERE version_id=?", (version_id,))
            conn.commit()

    def is_pinned(self, version_id: int) -> bool:
        with self._connect() as conn:
            res = conn.execute("SELECT 1 FROM pins WHERE version_id=?", (version_id,)).fetchone()
            return bool(res)

    def reclaim_quota(self, required_bytes: int, git_backup_bytes: int = 0) -> bool:
        """
        Option A Quota Policy:
        - NEVER purges unexpired data (< 30 days old).
        - NEVER purges pinned data.
        - Strict reclamation order:
          1. Oldest expired trash items (deleted_at > 30 days ago).
          2. Oldest expired unpinned snapshot actions (created_at > 30 days ago).
        - Returns True if sufficient space is available, False if operation must be blocked.
        """
        usage = self.get_quota_usage(git_backup_bytes)
        if usage.free_bytes >= required_bytes:
            return True

        needed = required_bytes - usage.free_bytes
        cutoff = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=RETENTION_DAYS)
        ).isoformat()

        with self._connect() as conn:
            # 1. Reclaim oldest expired trash items first
            expired_trash = conn.execute("""
                SELECT id, trash_path, logical_size FROM trash_items
                WHERE purged_at IS NULL AND deleted_at <= ?
                ORDER BY deleted_at ASC
            """, (cutoff,)).fetchall()

            for tid, tpath, size in expired_trash:
                if os.path.exists(tpath):
                    try:
                        if os.path.isdir(tpath):
                            shutil.rmtree(tpath)
                        else:
                            os.remove(tpath)
                    except OSError:
                        pass
                ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
                conn.execute("UPDATE trash_items SET purged_at=? WHERE id=?", (ts, tid))
                needed -= size
                if needed <= 0:
                    conn.commit()
                    return True

            # 2. Reclaim oldest expired unpinned snapshots
            expired_unpinned = conn.execute("""
                SELECT v.id, v.blob_hash, b.compressed_size
                FROM versions v
                JOIN blobs b ON v.blob_hash = b.blob_hash
                WHERE v.created_at <= ?
                  AND v.id NOT IN (SELECT version_id FROM pins)
                ORDER BY v.created_at ASC
            """, (cutoff,)).fetchall()

            for vid, bhash, comp_size in expired_unpinned:
                # Check if blob is used by any other non-expired or pinned version
                in_use = conn.execute("""
                    SELECT 1 FROM versions
                    WHERE blob_hash=? AND id != ?
                      AND (created_at > ? OR id IN (SELECT version_id FROM pins))
                """, (bhash, vid, cutoff)).fetchone()

                conn.execute("DELETE FROM versions WHERE id=?", (vid,))
                if not in_use:
                    self.blob_store.delete_blob(bhash)
                    conn.execute("DELETE FROM blobs WHERE blob_hash=?", (bhash,))
                    needed -= comp_size

                if needed <= 0:
                    conn.commit()
                    return True

            conn.commit()

        # If after reclaiming all eligible expired items we still don't have enough room:
        # Policy requires BLOCKING the operation rather than purging unexpired/pinned data
        return False
