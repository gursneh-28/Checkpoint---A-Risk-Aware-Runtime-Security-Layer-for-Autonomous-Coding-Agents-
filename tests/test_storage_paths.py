"""
tests/test_storage_paths.py — Unit tests for core/storage_paths.py

Tests cover:
  1. _security_configured() behavior with missing, readable, and inaccessible markers.
  2. Production mode always raises SecurityConfigurationError when marker unavailable.
  3. Development mode falls back to workspace without raising.
  4. CheckpointPaths returns secure base when marker present.
  5. CheckpointPaths returns workspace base in dev mode when marker missing.
  6. force_workspace=True raises in production mode.
  7. force_workspace=True succeeds in dev mode.
  8. SecurityConfigurationError is importable standalone.
  9. reset_paths() / get_paths() singleton behavior.
 10. All path properties return paths under the expected base.
"""
import os
import sys
import types
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_module(dev_mode: bool):
    """Re-import storage_paths with CHECKPOINT_DEV_MODE forced to dev_mode."""
    import importlib
    import core.storage_paths as sp
    with patch.dict(os.environ, {"CHECKPOINT_DEV_MODE": "1" if dev_mode else "0"}, clear=False):
        # Force _DEVELOPMENT_MODE to reload
        sp._DEVELOPMENT_MODE = dev_mode
        sp.reset_paths()
    return sp


def _patch_marker(sp_module, exists: bool, raises_permission: bool = False):
    """Patch Path.is_file on the marker path."""
    original_is_file = Path.is_file

    def _mocked_is_file(self):
        if self == sp_module.CHECKPOINT_BASE_SECURE / ".security_configured":
            if raises_permission:
                raise PermissionError("WinError 5 Access is denied")
            return exists
        return original_is_file(self)

    return patch.object(Path, "is_file", _mocked_is_file)


# ---------------------------------------------------------------------------
# Import smoke test
# ---------------------------------------------------------------------------

def test_module_importable():
    import core.storage_paths as sp
    assert hasattr(sp, "SecurityConfigurationError")
    assert hasattr(sp, "CheckpointPaths")
    assert hasattr(sp, "get_paths")
    assert hasattr(sp, "_WINDOWS")


def test_security_configuration_error_is_runtime_error():
    from core.storage_paths import SecurityConfigurationError
    err = SecurityConfigurationError("test")
    assert isinstance(err, RuntimeError)
    assert "test" in str(err)


# ---------------------------------------------------------------------------
# _security_configured() behavior — non-Windows
# ---------------------------------------------------------------------------

def test_security_configured_non_windows_returns_false(monkeypatch):
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", False)
    # On non-Windows, always returns False regardless of marker
    assert sp._security_configured() is False


# ---------------------------------------------------------------------------
# _security_configured() — marker present
# ---------------------------------------------------------------------------

def test_security_configured_marker_present_returns_true(monkeypatch):
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", False)
    with _patch_marker(sp, exists=True):
        assert sp._security_configured() is True


def test_security_configured_marker_present_dev_mode_returns_true(monkeypatch):
    """Marker present → returns True in BOTH production and dev mode."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    with _patch_marker(sp, exists=True):
        assert sp._security_configured() is True


# ---------------------------------------------------------------------------
# _security_configured() — marker missing
# ---------------------------------------------------------------------------

def test_security_configured_marker_missing_production_raises(monkeypatch):
    """Production mode: missing marker → SecurityConfigurationError, never False."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", False)
    with _patch_marker(sp, exists=False):
        with pytest.raises(sp.SecurityConfigurationError, match="missing or inaccessible"):
            sp._security_configured()


def test_security_configured_marker_missing_dev_mode_returns_false(monkeypatch):
    """Dev mode: missing marker → False (workspace fallback allowed)."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    with _patch_marker(sp, exists=False):
        result = sp._security_configured()
    assert result is False


# ---------------------------------------------------------------------------
# _security_configured() — marker inaccessible (PermissionError)
# ---------------------------------------------------------------------------

def test_security_configured_marker_inaccessible_production_raises(monkeypatch):
    """Production mode: PermissionError on marker → SecurityConfigurationError."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", False)
    with _patch_marker(sp, exists=False, raises_permission=True):
        with pytest.raises(sp.SecurityConfigurationError, match="missing or inaccessible"):
            sp._security_configured()


def test_security_configured_marker_inaccessible_dev_mode_returns_false(monkeypatch):
    """Dev mode: PermissionError on marker → False (workspace fallback)."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    with _patch_marker(sp, exists=False, raises_permission=True):
        result = sp._security_configured()
    assert result is False


# ---------------------------------------------------------------------------
# CheckpointPaths — secure mode
# ---------------------------------------------------------------------------

def test_checkpoint_paths_secure_base(monkeypatch):
    """When marker is present, paths resolve under CHECKPOINT_BASE_SECURE."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", False)
    sp.reset_paths()
    with _patch_marker(sp, exists=True):
        paths = sp.CheckpointPaths()
    assert paths.is_secure is True
    assert paths.base == sp.CHECKPOINT_BASE_SECURE
    assert paths.database_dir == sp.CHECKPOINT_BASE_SECURE / "db"
    assert paths.database_path == sp.CHECKPOINT_BASE_SECURE / "db" / "checkpoint.db"
    assert paths.journal_drop == sp.CHECKPOINT_BASE_SECURE / "journal-drop"
    assert paths.signing_dir == sp.CHECKPOINT_BASE_SECURE / "signing"
    assert paths.auth_dir == sp.CHECKPOINT_BASE_SECURE / "auth"


# ---------------------------------------------------------------------------
# CheckpointPaths — dev mode fallback
# ---------------------------------------------------------------------------

def test_checkpoint_paths_dev_mode_workspace_fallback(monkeypatch):
    """Dev mode + missing marker → workspace fallback with warning."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    sp.reset_paths()
    with _patch_marker(sp, exists=False):
        paths = sp.CheckpointPaths()
    assert paths.is_secure is False
    assert paths.base == sp.CHECKPOINT_BASE_WORKSPACE
    assert paths.database_dir == sp.CHECKPOINT_BASE_WORKSPACE / "db"


# ---------------------------------------------------------------------------
# CheckpointPaths — production mode without marker → raises immediately
# ---------------------------------------------------------------------------

def test_checkpoint_paths_production_missing_marker_raises(monkeypatch):
    """Production mode: CheckpointPaths() with missing marker must raise."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", False)
    sp.reset_paths()
    with _patch_marker(sp, exists=False):
        with pytest.raises(sp.SecurityConfigurationError):
            sp.CheckpointPaths()


# ---------------------------------------------------------------------------
# force_workspace behavior
# ---------------------------------------------------------------------------

def test_force_workspace_raises_in_production(monkeypatch):
    """force_workspace=True must raise SecurityConfigurationError in production."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", False)
    sp.reset_paths()
    with pytest.raises(sp.SecurityConfigurationError, match="force_workspace"):
        sp.CheckpointPaths(force_workspace=True)


def test_force_workspace_succeeds_in_dev_mode(monkeypatch):
    """force_workspace=True in dev mode must succeed and use workspace base."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    sp.reset_paths()
    paths = sp.CheckpointPaths(force_workspace=True)
    assert paths.is_secure is False
    assert paths.base == sp.CHECKPOINT_BASE_WORKSPACE


# ---------------------------------------------------------------------------
# get_paths() singleton
# ---------------------------------------------------------------------------

def test_get_paths_returns_singleton(monkeypatch):
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    sp.reset_paths()
    with _patch_marker(sp, exists=False):
        p1 = sp.get_paths()
        p2 = sp.get_paths()
    assert p1 is p2


def test_reset_paths_clears_singleton(monkeypatch):
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", True)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    sp.reset_paths()
    with _patch_marker(sp, exists=False):
        p1 = sp.get_paths()
        sp.reset_paths()
        p2 = sp.get_paths()
    assert p1 is not p2


# ---------------------------------------------------------------------------
# Non-Windows always uses workspace (no security configured)
# ---------------------------------------------------------------------------

def test_non_windows_always_workspace(monkeypatch):
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", False)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", True)
    sp.reset_paths()
    paths = sp.CheckpointPaths()
    assert paths.is_secure is False
    assert paths.base == sp.CHECKPOINT_BASE_WORKSPACE


def test_non_windows_production_mode_uses_workspace(monkeypatch):
    """On non-Windows, production mode must still use workspace (no ACL enforcement)."""
    import core.storage_paths as sp
    monkeypatch.setattr(sp, "_WINDOWS", False)
    monkeypatch.setattr(sp, "_DEVELOPMENT_MODE", False)
    sp.reset_paths()
    # _security_configured() returns False on non-Windows without raising.
    # But production mode + non-Windows: CheckpointPaths.__init__ calls
    # _security_configured() which returns False. Since _DEVELOPMENT_MODE is False,
    # the raise block is NOT hit because _WINDOWS is False (checked first).
    paths = sp.CheckpointPaths()
    assert paths.is_secure is False
