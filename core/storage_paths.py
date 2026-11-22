"""
core/storage_paths.py — Checkpoint protected storage path manager.

Defines all paths under %LOCALAPPDATA%\\Checkpoint\\ that are subject to
Windows ACL isolation and DPAPI protection per the v2.3 specification.

Path layout:
  %LOCALAPPDATA%\\Checkpoint\\
    store\\          — content-addressed blob store (CheckpointSvc:F, all others: deny)
    db\\             — checkpoint.db + WAL files (CheckpointSvc:F, all others: deny)
    journal-drop\\   — agent creates files here, cannot list/read/delete (CreateFiles ACL only)
    git-backups\\    — bare Git repository backups (CheckpointSvc:F, gursn: ReadAndExecute)
    signing\\        — session signing key (DPAPI-encrypted, CheckpointSvc:F only)
    trash\\          — recoverable soft-delete trash (CheckpointSvc:F, gursn: Modify for restore)
    auth\\           — Argon2id credential store (CheckpointSvc:F only)

Security contract:
  - All paths are owned by CheckpointSvc (or SYSTEM) after setup_security.ps1 runs.
  - Developer/agent account has NO access to store\\, db\\, signing\\ or auth\\.
  - Developer/agent account has CREATE-ONLY access to journal-drop\\.
  - Trash and git-backups\\ are readable by the developer account for restore UI.

Mode semantics:
  - DEVELOPMENT MODE (CHECKPOINT_DEV_MODE=1):
      If the security marker is missing or inaccessible, falls back to workspace
      storage with a logged warning. Safe for local development before elevated setup.
  - PRODUCTION MODE (default, CHECKPOINT_DEV_MODE not set or not "1"):
      If the security marker is missing or inaccessible, raises SecurityConfigurationError
      immediately. The application never silently degrades to unprotected workspace paths.

IMPORTANT: force_workspace=True is only allowed in DEVELOPMENT MODE. In production
it also raises SecurityConfigurationError, preventing accidental unprotected use.
"""
from __future__ import annotations

import os
import sys
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("checkpoint.storage_paths")

# ---------------------------------------------------------------------------
# Platform flag
# ---------------------------------------------------------------------------

_WINDOWS: bool = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Mode flags (read once at import; tests may monkeypatch _DEVELOPMENT_MODE)
# ---------------------------------------------------------------------------

# Set CHECKPOINT_DEV_MODE=1 to allow workspace fallback during development.
# In production this must NOT be set.
_DEVELOPMENT_MODE: bool = os.getenv("CHECKPOINT_DEV_MODE") == "1"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SecurityConfigurationError(RuntimeError):
    """Raised when the application is started without required security configuration.

    In production mode (CHECKPOINT_DEV_MODE not set) the .security_configured marker
    under %LOCALAPPDATA%\\Checkpoint\\ must exist and be accessible before any path is
    resolved. If it is missing or access-denied, this error is raised immediately.
    The application must never silently fall back to unprotected workspace paths in
    production.
    """


# ---------------------------------------------------------------------------
# Base path resolution
# ---------------------------------------------------------------------------

def _localappdata() -> Path:
    """Return %LOCALAPPDATA% — always defined on Windows."""
    base = os.environ.get("LOCALAPPDATA", "")
    if base:
        return Path(base)
    # Fallback for non-Windows CI
    return Path.home() / ".local" / "share"


def _workspace_root() -> Path:
    """Project workspace root — used as fallback when security is not configured."""
    return Path(__file__).resolve().parent.parent


CHECKPOINT_BASE_SECURE: Path = _localappdata() / "Checkpoint"
CHECKPOINT_BASE_WORKSPACE: Path = _workspace_root() / "storage"


# ---------------------------------------------------------------------------
# Security state detection
# ---------------------------------------------------------------------------

def _security_configured() -> bool:
    """Return True if the security marker is present and accessible.

    Behaviour by mode:
      - Non-Windows: always returns False (no ACL enforcement possible).
      - Windows + marker accessible + is_file: returns True.
      - Windows + marker missing or PermissionError + DEVELOPMENT MODE: returns False.
      - Windows + marker missing or PermissionError + PRODUCTION MODE: raises
        SecurityConfigurationError (fail-closed).

    NOTE on Path.is_file() under Windows ACLs:
      When the PARENT directory denies ListDirectory to the current user, os.stat()
      raises PermissionError even though is_file() normally catches it. We therefore
      wrap the call explicitly and treat PermissionError as "marker inaccessible".
    """
    if not _WINDOWS:
        return False

    marker = CHECKPOINT_BASE_SECURE / ".security_configured"
    try:
        accessible = marker.is_file()
    except (PermissionError, OSError):
        accessible = False
        marker_exists = None  # indeterminate
    else:
        marker_exists = accessible

    if accessible:
        return True

    # Marker missing or inaccessible — apply mode policy.
    if _DEVELOPMENT_MODE:
        logger.debug(
            "Security marker not found/accessible at %s; running in DEVELOPMENT MODE "
            "(workspace fallback allowed).",
            marker,
        )
        return False

    # Production — fail closed.
    raise SecurityConfigurationError(
        f"Security marker missing or inaccessible at '{marker}'. "
        "In production mode Checkpoint requires that setup_security.ps1 has been run "
        "as Administrator before the application starts. "
        "To use workspace storage during development, set CHECKPOINT_DEV_MODE=1."
    )


def mark_security_configured() -> None:
    """Write the .security_configured marker after setup_security.ps1 completes."""
    CHECKPOINT_BASE_SECURE.mkdir(parents=True, exist_ok=True)
    marker = CHECKPOINT_BASE_SECURE / ".security_configured"
    marker.write_text(
        f"CheckpointSvc security configured via mark_security_configured()\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Path resolver
# ---------------------------------------------------------------------------

class CheckpointPaths:
    """Central accessor for all Checkpoint storage paths.

    When security is fully configured (setup_security.ps1 has been run and verified),
    all paths resolve to ACL-protected locations under %LOCALAPPDATA%\\Checkpoint\\.

    When security is NOT configured AND CHECKPOINT_DEV_MODE=1, paths fall back to the
    workspace storage\\ directory with a logged warning.

    In production (CHECKPOINT_DEV_MODE not set) any attempt to construct this object
    without a valid security marker immediately raises SecurityConfigurationError.
    force_workspace=True is likewise disallowed in production.
    """

    def __init__(self, force_workspace: bool = False) -> None:
        # Disallow forced workspace fallback in production — prevents accidental
        # bypass of the security boundary.
        if force_workspace and not _DEVELOPMENT_MODE:
            raise SecurityConfigurationError(
                "force_workspace=True is not allowed in production mode. "
                "Set CHECKPOINT_DEV_MODE=1 to enable workspace fallback for development."
            )

        # _security_configured() raises SecurityConfigurationError in production when
        # the marker is missing/inaccessible; in dev mode it returns False.
        if force_workspace:
            self._secure = False
        else:
            self._secure = _security_configured()

        self._base: Path = CHECKPOINT_BASE_SECURE if self._secure else CHECKPOINT_BASE_WORKSPACE

        if not self._secure:
            logger.warning(
                "SECURITY WARNING: Checkpoint storage is using the WORKSPACE fallback "
                "path (%s). No OS-level ACL isolation is in effect. "
                "Run scripts/setup_security.ps1 as Administrator to configure security "
                "boundaries. CRITICAL tier approvals remain disabled until security is "
                "configured.",
                self._base,
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_secure(self) -> bool:
        """True when paths point to ACL-protected secure storage."""
        return self._secure

    @property
    def base(self) -> Path:
        return self._base

    @property
    def blob_store(self) -> Path:
        """Content-addressed blob store. DENY all except CheckpointSvc after setup."""
        return self._base / "store"

    @property
    def database_dir(self) -> Path:
        """Directory containing checkpoint.db + WAL files. DENY all except CheckpointSvc."""
        return self._base / "db"

    @property
    def database_path(self) -> Path:
        return self.database_dir / "checkpoint.db"

    @property
    def journal_drop(self) -> Path:
        """Journal drop folder.
        Agent account: CREATE-FILES (AppendData) ONLY — cannot read, list, or delete.
        CheckpointSvc: FULL CONTROL.
        """
        return self._base / "journal-drop"

    @property
    def git_backups(self) -> Path:
        """Bare Git backup repository store. ReadAndExecute for agent after setup."""
        return self._base / "git-backups"

    @property
    def signing_dir(self) -> Path:
        """DPAPI-encrypted signing key storage. DENY all except CheckpointSvc."""
        return self._base / "signing"

    @property
    def signing_key_path(self) -> Path:
        """Path to the DPAPI-encrypted session signing key."""
        return self.signing_dir / "signing.key.dpapi"

    @property
    def signing_key_fallback(self) -> Path:
        """Plaintext fallback key path (workspace / dev mode ONLY — NOT secure)."""
        return self._base / "auth" / "session_signing.key"

    @property
    def trash(self) -> Path:
        """Recoverable soft-delete trash directory."""
        return self._base / "trash"

    @property
    def auth_dir(self) -> Path:
        """Argon2id credential store directory."""
        return self._base / "auth"

    def ensure_all(self) -> None:
        """Create all required directories if they do not exist."""
        for d in [
            self.blob_store,
            self.database_dir,
            self.journal_drop,
            self.git_backups,
            self.signing_dir,
            self.trash,
            self.auth_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    def describe(self) -> dict:
        return {
            "is_secure": self._secure,
            "base": str(self._base),
            "blob_store": str(self.blob_store),
            "database_dir": str(self.database_dir),
            "journal_drop": str(self.journal_drop),
            "git_backups": str(self.git_backups),
            "signing_dir": str(self.signing_dir),
            "trash": str(self.trash),
            "auth_dir": str(self.auth_dir),
        }


# ---------------------------------------------------------------------------
# Module-level singleton (lazy, so tests can monkeypatch before first access)
# ---------------------------------------------------------------------------

_paths: Optional[CheckpointPaths] = None


def get_paths(force_workspace: bool = False) -> CheckpointPaths:
    """Return the module-level CheckpointPaths singleton.

    Calling with force_workspace=True always creates a new instance and stores it,
    replacing the previous singleton. This is intentional — it is only used by
    development tooling and tests.
    """
    global _paths
    if _paths is None or force_workspace:
        _paths = CheckpointPaths(force_workspace=force_workspace)
    return _paths


def reset_paths() -> None:
    """Reset the singleton — for use in tests only."""
    global _paths
    _paths = None
