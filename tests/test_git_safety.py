import os
import shutil
import subprocess
import time
import pytest

from core.git_safety import (
    GitSafetyNet,
    GitCoverageCategory,
    GitCoverageLevel,
    get_safe_git_env,
    run_git,
    HARD_DENY_COMMANDS,
)


@pytest.fixture
def git_repo(tmp_path):
    """Create a real, temporary Git repository inside tmp_path."""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    cwd = str(repo_dir)

    # Initialize repo
    run_git(["init"], cwd=cwd)
    run_git(["config", "user.name", "TestUser"], cwd=cwd)
    run_git(["config", "user.email", "test@checkpoint.local"], cwd=cwd)

    # Initial commit
    file1 = repo_dir / "file1.txt"
    file1.write_text("initial commit content\n", encoding="utf-8")
    run_git(["add", "file1.txt"], cwd=cwd)
    run_git(["commit", "-m", "Initial commit"], cwd=cwd)

    backup_root = tmp_path / "git_backups_store"
    safety = GitSafetyNet(backup_root=str(backup_root))

    return cwd, repo_dir, safety, backup_root


def test_inspect_repository(git_repo):
    cwd, repo_dir, safety, _ = git_repo

    # Create staged change
    staged = repo_dir / "staged.txt"
    staged.write_text("staged content\n", encoding="utf-8")
    run_git(["add", "staged.txt"], cwd=cwd)

    # Create unstaged change
    file1 = repo_dir / "file1.txt"
    file1.write_text("modified content\n", encoding="utf-8")

    # Create untracked file
    untracked = repo_dir / "untracked.py"
    untracked.write_text("print('untracked')\n", encoding="utf-8")

    manifest = safety.inspect_repository(cwd)
    assert manifest is not None
    assert manifest.staged_files_count == 1
    assert manifest.unstaged_files_count == 1
    assert manifest.untracked_files_count == 1
    assert manifest.head_sha != ""
    assert manifest.coverage_level == GitCoverageLevel.FULL


def test_create_snapshot_separate_staged_unstaged_untracked(git_repo):
    cwd, repo_dir, safety, backup_root = git_repo

    # Set up dirty state
    file1 = repo_dir / "file1.txt"
    file1.write_text("unstaged change\n", encoding="utf-8")

    file2 = repo_dir / "file2.txt"
    file2.write_text("staged change\n", encoding="utf-8")
    run_git(["add", "file2.txt"], cwd=cwd)

    untracked = repo_dir / "new_untracked.txt"
    untracked.write_text("untracked payload\n", encoding="utf-8")

    success, msg, record = safety.create_snapshot(cwd)
    assert success is True
    assert record is not None
    assert record.verified is True

    # Verify separate files exist
    assert os.path.isfile(record.bundle_path)
    assert os.path.isfile(record.staged_patch_path)
    assert os.path.isfile(record.unstaged_patch_path)
    assert os.path.isdir(record.untracked_dir)

    # Verify untracked file content was backed up
    backed_untracked = os.path.join(record.untracked_dir, "new_untracked.txt")
    assert os.path.isfile(backed_untracked)
    assert "untracked payload" in open(backed_untracked).read()

    # Check covered categories
    assert GitCoverageCategory.REFS.value in record.covered_categories
    assert GitCoverageCategory.STAGED.value in record.covered_categories
    assert GitCoverageCategory.UNSTAGED.value in record.covered_categories
    assert GitCoverageCategory.UNTRACKED.value in record.covered_categories


def test_hard_deny_commands(git_repo):
    cwd, _, safety, _ = git_repo

    for cmd in HARD_DENY_COMMANDS:
        allowed, reason, _ = safety.evaluate_destructive_git_command(cmd, cwd)
        assert allowed is False
        assert "HARD DENY" in reason


def test_coverage_matrix_blocking_when_no_snapshot(git_repo):
    cwd, _, safety, _ = git_repo

    # No snapshot exists yet
    allowed, reason, op = safety.evaluate_destructive_git_command("git reset --hard HEAD~1", cwd)
    assert allowed is False
    assert "requires a verified external Git snapshot" in reason
    assert op == "reset_hard"

    allowed_clean, reason_clean, _ = safety.evaluate_destructive_git_command("git clean -fd", cwd)
    assert allowed_clean is False
    assert "requires a verified external Git snapshot" in reason_clean


def test_coverage_matrix_allows_when_verified_snapshot_exists(git_repo):
    cwd, _, safety, _ = git_repo

    # Create verified snapshot
    success, _, _ = safety.create_snapshot(cwd)
    assert success is True

    # Now reset --hard should be evaluated as covered
    allowed, reason, op = safety.evaluate_destructive_git_command("git reset --hard HEAD", cwd)
    assert allowed is True
    assert "satisfies required coverage" in reason
    assert op == "reset_hard"


def test_stale_snapshot_blocks_destructive_command(git_repo):
    cwd, _, safety, _ = git_repo

    success, _, record = safety.create_snapshot(cwd)
    assert success is True

    # Artificially age the snapshot beyond 300 seconds
    record.timestamp = time.time() - 400
    safety._save_index()

    allowed, reason, _ = safety.evaluate_destructive_git_command("git reset --hard HEAD", cwd)
    assert allowed is False
    assert "stale (> 300s old)" in reason


def test_restore_snapshot_with_conflict_detection(git_repo):
    cwd, repo_dir, safety, _ = git_repo

    # Create uncommitted untracked file
    doc = repo_dir / "important_note.txt"
    doc.write_text("crucial draft\n", encoding="utf-8")

    success, _, record = safety.create_snapshot(cwd)
    assert success is True

    # Simulate catastrophic accidental clean
    doc.unlink()
    assert not doc.exists()

    # Restore snapshot
    restored, msg, items = safety.restore_snapshot(record.backup_id, restore_worktree=True, force=True)
    assert restored is True
    assert doc.exists()
    assert "crucial draft" in doc.read_text(encoding="utf-8")


def test_quota_calculation_reflects_external_snapshots(git_repo):
    cwd, _, safety, _ = git_repo

    assert safety.get_total_backup_bytes() == 0
    success, _, record = safety.create_snapshot(cwd)
    assert success is True

    total_bytes = safety.get_total_backup_bytes()
    assert total_bytes > 0
    assert total_bytes == record.total_size_bytes


def test_hostile_git_config_isolation():
    env = get_safe_git_env()
    assert env.get("GIT_TERMINAL_PROMPT") == "0"
    assert env.get("PAGER") == "cat"
    assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
    assert env.get("GIT_EXTERNAL_DIFF") == ""
