import datetime
import os
import shutil
import sqlite3
import pytest

from core.blob_store import BlobStore, EMPTY_SHA256, FileTooLargeError
from core.version_control import (
    VersionControl, PathTraversalError, RestoreConflictError, SHARED_QUOTA_BYTES
)
from storage.db import init_db


@pytest.fixture
def vc_env(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store_dir = tmp_path / "checkpoint_blobs"
    db_file = tmp_path / "checkpoint_test.db"

    # Initialize SQLite schema
    monkeypatch.setattr("storage.db.DB_PATH", str(db_file))
    init_db()

    blob_store = BlobStore(str(store_dir))
    vc = VersionControl(
        db_path=str(db_file),
        blob_store=blob_store,
        workspace_root=str(workspace)
    )
    return vc, workspace, blob_store


def test_snapshot_file_and_deduplication(vc_env):
    vc, workspace, blob_store = vc_env
    test_file = workspace / "sample.py"
    test_file.write_text("print('version 1')", encoding="utf-8")

    # Insert action records so foreign keys are satisfied
    with vc._connect() as conn:
        conn.execute("INSERT INTO actions (timestamp, action_type, command, risk_tier, status) VALUES ('2026-01-01', 'Bash', 'a1', 'LOW', 'PENDING')")
        conn.execute("INSERT INTO actions (timestamp, action_type, command, risk_tier, status) VALUES ('2026-01-01', 'Bash', 'a2', 'LOW', 'PENDING')")
        conn.commit()

    rec1 = vc.snapshot_file(str(test_file), action_id=1)
    assert rec1.state == "file"
    assert rec1.blob_hash is not None
    assert blob_store.has_blob(rec1.blob_hash)

    # Identical content in another file deduplicates to the same blob_hash
    test_file2 = workspace / "sample_copy.py"
    test_file2.write_text("print('version 1')", encoding="utf-8")
    rec2 = vc.snapshot_file(str(test_file2), action_id=2)
    assert rec2.blob_hash == rec1.blob_hash


def test_empty_file_snapshot(vc_env):
    vc, workspace, blob_store = vc_env
    empty_file = workspace / "__init__.py"
    empty_file.write_text("", encoding="utf-8")

    rec = vc.snapshot_file(str(empty_file))
    assert rec.state == "file"
    assert rec.blob_hash == EMPTY_SHA256
    assert blob_store.get_bytes(rec.blob_hash) == b""


def test_deleted_file_snapshot(vc_env):
    vc, workspace, _ = vc_env
    non_existent = workspace / "deleted_file.txt"

    rec = vc.snapshot_file(str(non_existent))
    assert rec.state == "deleted"
    assert rec.blob_hash is None


def test_path_traversal_prevention(vc_env, tmp_path):
    vc, workspace, _ = vc_env
    outside_file = tmp_path / "secret.env"
    outside_file.write_text("SECRET=123")

    with pytest.raises(PathTraversalError):
        vc.snapshot_file(str(outside_file))


def test_snapshot_directory_and_regenerable_exclusion(vc_env):
    vc, workspace, _ = vc_env
    (workspace / "src").mkdir()
    (workspace / "src" / "main.py").write_text("main code")
    (workspace / "node_modules").mkdir()
    (workspace / "node_modules" / "dep.js").write_text("dependency")

    records = vc.snapshot_directory(str(workspace), exclude_regenerable=True)
    paths = [r.file_path for r in records]
    assert any("main.py" in p for p in paths)
    assert not any("dep.js" in p for p in paths)


def test_restore_file_without_conflict(vc_env):
    vc, workspace, _ = vc_env
    test_file = workspace / "config.json"
    test_file.write_text('{"env": "prod"}')

    rec = vc.snapshot_file(str(test_file))

    # Overwrite on disk
    test_file.write_text('{"env": "broken"}')

    # Force restore back to snapshot
    res = vc.restore_version(rec.id, force=True)
    assert res.success is True
    assert test_file.read_text() == '{"env": "prod"}'


def test_restore_conflict_detection(vc_env):
    vc, workspace, _ = vc_env
    test_file = workspace / "data.csv"
    test_file.write_text("a,b,c")

    rec = vc.snapshot_file(str(test_file))

    # Modify file on disk
    test_file.write_text("a,b,c,modified")

    # Attempt restore without force -> must refuse due to conflict
    conflicts = vc.detect_conflicts(rec.id)
    assert len(conflicts) == 1
    assert "modified after snapshot" in conflicts[0].reason

    res = vc.restore_version(rec.id, force=False)
    assert res.success is False
    assert "Restore refused due to conflicts" in res.message


def test_restore_deleted_state(vc_env):
    vc, workspace, _ = vc_env
    victim_path = workspace / "victim.txt"
    # Take snapshot when file does NOT exist (state = deleted)
    rec = vc.snapshot_file(str(victim_path))
    assert rec.state == "deleted"

    # Now create the file on disk
    victim_path.write_text("temporary file")
    assert victim_path.exists()

    # Restoring the deleted state should remove the file
    res = vc.restore_version(rec.id, force=True)
    assert res.success is True
    assert not victim_path.exists()


def test_pinning_prevents_reclamation(vc_env):
    vc, workspace, blob_store = vc_env
    test_file = workspace / "important.txt"
    test_file.write_text("vital version")

    rec = vc.snapshot_file(str(test_file))
    vc.pin_version(rec.id, reason="audit_pin")
    assert vc.is_pinned(rec.id) is True

    # Artificially age the version in the database to 40 days ago (> 30 days retention)
    old_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)).isoformat()
    with vc._connect() as conn:
        conn.execute("UPDATE versions SET created_at=? WHERE id=?", (old_time, rec.id))
        conn.commit()

    # Reclaim quota: should NOT purge the pinned version even though it's older than 30 days
    vc.reclaim_quota(required_bytes=1000)
    assert vc.get_version(rec.id) is not None
    assert blob_store.has_blob(rec.blob_hash) is True


def test_option_a_reclaim_order_and_unexpired_protection(vc_env, tmp_path):
    vc, workspace, blob_store = vc_env

    # 1. Create a dummy trash folder and expired trash item (> 30 days)
    trash_file = tmp_path / "trash_victim.txt"
    trash_file.write_text("trash item payload")
    trash_size = os.path.getsize(trash_file)

    expired_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=35)).isoformat()
    unexpired_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()

    # Record expired trash item
    with vc._connect() as conn:
        conn.execute("""
            INSERT INTO trash_items (original_path, trash_path, logical_size, deleted_at)
            VALUES (?, ?, ?, ?)
        """, (str(workspace / "v.txt"), str(trash_file), trash_size, expired_time))

    # Record unexpired snapshot (< 30 days)
    unexp_file = workspace / "fresh.txt"
    unexp_file.write_text("fresh snapshot")
    unexp_rec = vc.snapshot_file(str(unexp_file))
    with vc._connect() as conn:
        conn.execute("UPDATE versions SET created_at=? WHERE id=?", (unexpired_time, unexp_rec.id))
        conn.commit()

    # Record expired unpinned snapshot (> 30 days)
    exp_file = workspace / "old.txt"
    exp_file.write_text("old snapshot to reclaim")
    exp_rec = vc.snapshot_file(str(exp_file))
    with vc._connect() as conn:
        conn.execute("UPDATE versions SET created_at=? WHERE id=?", (expired_time, exp_rec.id))
        conn.commit()

    # Reclaim quota for needed space when quota is exhausted
    # Setting git_backup_bytes = SHARED_QUOTA_BYTES leaves 0 free bytes, forcing reclamation of expired items
    success = vc.reclaim_quota(required_bytes=10, git_backup_bytes=SHARED_QUOTA_BYTES)
    assert success is True

    # 1. Expired trash was reclaimed
    with vc._connect() as conn:
        purged = conn.execute("SELECT purged_at FROM trash_items").fetchone()[0]
        assert purged is not None
    assert not trash_file.exists()

    # 2. Unexpired snapshot (< 30 days) was NEVER purged (Option A rule)
    assert vc.get_version(unexp_rec.id) is not None
    assert blob_store.has_blob(unexp_rec.blob_hash) is True
