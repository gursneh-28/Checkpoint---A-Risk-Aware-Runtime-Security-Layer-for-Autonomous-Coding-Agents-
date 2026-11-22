"""
tests/test_acl_cross.py — Integration test: Cross-account ACL boundary verification.

INTEGRATION TEST — requires Windows security prerequisites to be set up:
  1. CHECKPOINT_INTEGRATION=1 environment variable must be set.
  2. CheckpointSvc local account must exist.
  3. The .security_configured marker must be present and accessible.
  4. setup_security.ps1 must have been run as Administrator.

When prerequisites are absent (which is true in all dev/CI environments before
elevated setup), every test in this module skips cleanly with a descriptive reason.
No test ever falsely passes.

WHAT THESE TESTS VERIFY:
  - verify_security_cross.ps1 exits 0 (all checks pass) from the agent account.
  - Protected directories are inaccessible to the current user.
  - Journal-drop allows create but denies list/read/delete.
  - Git-backups allows read but denies write.

WHAT THESE TESTS CANNOT VERIFY:
  - That CheckpointSvc CAN access protected dirs (requires process running as that account).
  - DPAPI cross-account isolation (requires encrypting under CheckpointSvc profile).
  These are documented in KNOWN_LIMITATIONS.md.
"""
import os
import subprocess
import sys
import pytest
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Prerequisite guards
# ---------------------------------------------------------------------------

def _integration_enabled() -> bool:
    return os.getenv("CHECKPOINT_INTEGRATION") == "1"


def _service_account_exists() -> bool:
    if not IS_WINDOWS:
        return False
    result = subprocess.run(
        ["net", "user", "CheckpointSvc"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def _marker_exists() -> bool:
    if not IS_WINDOWS:
        return False
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    marker = Path(local_app_data) / "Checkpoint" / ".security_configured"
    try:
        return marker.is_file()
    except (PermissionError, OSError):
        # Marker is inaccessible — security boundary may be enforced.
        # From the agent's perspective this counts as configured.
        return True


def _require_integration(reason: str = ""):
    """Skip if integration prerequisites are not met."""
    if not _integration_enabled():
        pytest.skip(
            "CHECKPOINT_INTEGRATION=1 not set — integration tests require elevated setup. "
            + reason
        )
    if not IS_WINDOWS:
        pytest.skip("Cross-account ACL tests require Windows.")
    if not _service_account_exists():
        pytest.skip(
            "CheckpointSvc account does not exist — run setup_security.ps1 as Administrator first."
        )
    if not _marker_exists():
        pytest.skip(
            ".security_configured marker not found — run setup_security.ps1 as Administrator first."
        )


# ---------------------------------------------------------------------------
# Helper: locate verify_security_cross.ps1
# ---------------------------------------------------------------------------

def _cross_script() -> Path:
    project_root = Path(__file__).resolve().parent.parent
    return project_root / "scripts" / "verify_security_cross.ps1"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAclCrossAccountVerification:
    """Full cross-account ACL verification via verify_security_cross.ps1."""

    def test_prerequisites_checked(self):
        """Documents what prerequisites this module needs — always passes."""
        assert True, (
            "Integration tests in this file require: "
            "CHECKPOINT_INTEGRATION=1, CheckpointSvc account, .security_configured marker. "
            "They skip cleanly when any prerequisite is absent."
        )

    def test_cross_script_exists(self):
        """The verification script must exist in the scripts/ directory."""
        script = _cross_script()
        assert script.exists(), (
            f"verify_security_cross.ps1 not found at {script}. "
            "This is a code defect — the script must be present in the repository."
        )

    @pytest.mark.skipif(not IS_WINDOWS, reason="ACL tests require Windows")
    def test_cross_account_verification_script_passes(self):
        """
        Run verify_security_cross.ps1 from the agent account and assert exit 0.

        INTEGRATION: requires CHECKPOINT_INTEGRATION=1, CheckpointSvc account,
        and .security_configured marker.
        """
        _require_integration()
        script = _cross_script()
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass",
             "-File", str(script)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Print output for diagnosis on failure
        if result.returncode != 0:
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
        assert result.returncode == 0, (
            f"verify_security_cross.ps1 exited {result.returncode}.\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        assert "[FAIL]" not in result.stdout, (
            "verify_security_cross.ps1 reported FAIL checks even with exit 0.\n"
            f"Output:\n{result.stdout}"
        )

    @pytest.mark.skipif(not IS_WINDOWS, reason="ACL tests require Windows")
    def test_protected_dirs_deny_current_user(self):
        """
        Directly verify (from Python) that protected directories deny access.

        INTEGRATION: requires CHECKPOINT_INTEGRATION=1, CheckpointSvc account,
        and .security_configured marker.
        """
        _require_integration()
        import os as _os
        base = Path(_os.environ["LOCALAPPDATA"]) / "Checkpoint"
        protected = ["store", "db", "signing", "auth"]
        for d in protected:
            dir_path = base / d
            if not dir_path.exists():
                pytest.skip(f"{d}/ not found under {base} — setup may be incomplete")
            try:
                list(dir_path.iterdir())
                pytest.fail(
                    f"Agent account can list {d}/ — ACL not enforced. "
                    "This is a security boundary failure."
                )
            except PermissionError:
                pass  # Expected — boundary enforced

    @pytest.mark.skipif(not IS_WINDOWS, reason="ACL tests require Windows")
    def test_journal_drop_create_only(self):
        """
        Verify journal-drop allows CREATE but denies LIST and DELETE.

        INTEGRATION: requires CHECKPOINT_INTEGRATION=1, CheckpointSvc account,
        and .security_configured marker.
        """
        _require_integration()
        import os as _os, tempfile, uuid
        base = Path(_os.environ["LOCALAPPDATA"]) / "Checkpoint"
        drop = base / "journal-drop"
        if not drop.exists():
            pytest.skip("journal-drop/ not found — setup may be incomplete")

        uid = uuid.uuid4().hex[:8]
        test_file = drop / f"integration_test_{uid}.journal"

        # CREATE must succeed
        try:
            test_file.write_bytes(b"checkpoint_integration_test")
        except PermissionError:
            pytest.fail(
                "Agent account cannot create files in journal-drop/. "
                "ACL is too restrictive — CREATE-FILES must be allowed."
            )

        # LIST must fail
        try:
            list(drop.iterdir())
            # If listing succeeds the boundary is NOT enforced
            pytest.fail(
                "Agent account can list journal-drop/ contents. "
                "ACL is not restrictive enough — LIST must be denied."
            )
        except PermissionError:
            pass  # Expected

        # READ must fail
        try:
            test_file.read_bytes()
            pytest.fail(
                "Agent account can read files from journal-drop/. "
                "ACL is not restrictive enough — READ must be denied."
            )
        except PermissionError:
            pass  # Expected

        # DELETE must fail
        try:
            test_file.unlink()
            pytest.fail(
                "Agent account can delete files from journal-drop/. "
                "ACL is not restrictive enough — DELETE must be denied."
            )
        except PermissionError:
            pass  # Expected — service will clean up

    @pytest.mark.skipif(not IS_WINDOWS, reason="ACL tests require Windows")
    def test_git_backups_read_only(self):
        """
        Verify git-backups allows READ but denies WRITE.

        INTEGRATION: requires CHECKPOINT_INTEGRATION=1, CheckpointSvc account,
        and .security_configured marker.
        """
        _require_integration()
        import os as _os, uuid
        base = Path(_os.environ["LOCALAPPDATA"]) / "Checkpoint"
        git_backups = base / "git-backups"
        if not git_backups.exists():
            pytest.skip("git-backups/ not found — setup may be incomplete")

        # LIST must succeed
        try:
            list(git_backups.iterdir())
        except PermissionError:
            pytest.fail(
                "Agent account cannot list git-backups/ — restore UI would be broken. "
                "ACL is too restrictive."
            )

        # WRITE must fail
        uid = uuid.uuid4().hex[:8]
        test_file = git_backups / f"integration_test_{uid}.tmp"
        try:
            test_file.write_bytes(b"test")
            if test_file.exists():
                test_file.unlink()
            pytest.fail(
                "Agent account can write to git-backups/ — ACL not enforced. "
                "Write must be denied."
            )
        except PermissionError:
            pass  # Expected
