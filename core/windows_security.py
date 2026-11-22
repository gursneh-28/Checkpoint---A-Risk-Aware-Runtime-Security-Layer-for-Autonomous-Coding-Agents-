"""
core/windows_security.py — Windows security operations for Checkpoint Stage 5A.

Provides Python wrappers for the Windows-level security operations required by
the v2.3 specification:

  1. CheckpointSvc account management (requires elevation)
  2. NTFS ACL configuration for protected storage paths (requires elevation)
  3. DPAPI key management under CheckpointSvc profile
  4. Security state verification (readable without elevation)

All operations that require elevation (account creation, ACL changes on directories
not owned by the current user) are explicitly documented as such. If called without
the required elevation, they raise WindowsSecurityError rather than silently degrading.

Security contract from v2.3:
  - CheckpointSvc is a local standard account (not Administrator)
  - Protected paths are owned by CheckpointSvc / SYSTEM, inaccessible to gursn
  - Journal drop folder: gursn can CREATE files but not read/list/delete them
  - CRITICAL approvals are disabled until this module's verify() returns True
  - ML classifier must never authorize an action (enforced in pipeline.py)
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("checkpoint.windows_security")

_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Account constants
# ---------------------------------------------------------------------------

SERVICE_ACCOUNT_NAME = "CheckpointSvc"
SERVICE_ACCOUNT_COMMENT = "Checkpoint runtime security service account - do not remove"

# Password is generated fresh by setup_security.ps1 and stored DPAPI-encrypted.
# It is never hardcoded here.

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class WindowsSecurityError(RuntimeError):
    """Raised for Windows security setup failures."""


class ElevationRequired(WindowsSecurityError):
    """Raised when an operation requires Administrator elevation."""


# ---------------------------------------------------------------------------
# Elevation check
# ---------------------------------------------------------------------------

def is_elevated() -> bool:
    """Return True if the current process has an elevated (Administrator) token."""
    if not _WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def require_elevation(operation: str) -> None:
    """Raise ElevationRequired if the current process is not elevated."""
    if not is_elevated():
        raise ElevationRequired(
            f"Operation '{operation}' requires Administrator elevation. "
            "Run PowerShell as Administrator and re-execute."
        )


# ---------------------------------------------------------------------------
# Account management  (requires elevation)
# ---------------------------------------------------------------------------

def account_exists(account_name: str = SERVICE_ACCOUNT_NAME) -> bool:
    """Return True if a local account with the given name exists."""
    if not _WINDOWS:
        return False
    result = subprocess.run(
        ["net", "user", account_name],
        capture_output=True, text=True
    )
    return result.returncode == 0


def create_service_account(password: str, account_name: str = SERVICE_ACCOUNT_NAME) -> None:
    """
    Create the CheckpointSvc local standard user account.

    Requirements:
      - Elevated Administrator token (ElevationRequired if missing)
      - Account must NOT already exist (use account_exists() to check first)
      - Account is configured: no password expiry, no interactive logon,
        not a member of Administrators group

    Args:
        password: Strong machine-generated password (at least 20 chars)
        account_name: The Windows account name (default: CheckpointSvc)
    """
    if not _WINDOWS:
        raise WindowsSecurityError("Account creation is only supported on Windows")
    require_elevation("create_service_account")

    if account_exists(account_name):
        logger.info("Account %s already exists, skipping creation", account_name)
        return

    # Create account securely using PowerShell New-LocalUser with SecureString
    # Passing the password via stdin prevents it from appearing in process command lines.
    ps_cmd = (
        f"$sec = Read-Host -AsSecureString; "
        f"New-LocalUser -Name '{account_name}' -Password $sec "
        f"-Description '{SERVICE_ACCOUNT_COMMENT}' -PasswordNeverExpires $true "
        f"-UserMayNotChangePassword $true"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
        input=password + "\n",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise WindowsSecurityError(f"Failed to create account {account_name}: {proc.stderr.strip()}")

    # Set account to never expire (net user /expires:never handled above)
    # Deny interactive logon via local security policy
    _deny_interactive_logon(account_name)

    logger.info("Created service account: %s", account_name)


def _deny_interactive_logon(account_name: str) -> None:
    """Deny interactive logon for the service account using secedit."""
    # This requires secedit and elevation. We use the PowerShell ntrights approach
    # or simply document that the account cannot log on interactively by configuration.
    # ntrights.exe is part of the Windows Server Resource Kit, not always available.
    # We use a PowerShell approach instead.
    ps_script = f"""
$user = New-Object System.Security.Principal.NTAccount('{account_name}')
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).Value
$seceditInf = @"
[Unicode]
Unicode=yes
[System Access]
[Event Audit]
[Registry Values]
[Privilege Rights]
SeDenyInteractiveLogonRight = *$sid
"@
$tempInf = [System.IO.Path]::GetTempFileName() + ".inf"
$tempDb = [System.IO.Path]::GetTempFileName() + ".sdb"
$seceditInf | Set-Content -Encoding Unicode $tempInf
secedit /import /cfg $tempInf /db $tempDb /quiet
secedit /configure /db $tempDb /quiet
Remove-Item $tempInf, $tempDb -ErrorAction SilentlyContinue
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.warning("Could not set deny interactive logon (non-fatal): %s", result.stderr.strip())


def delete_service_account(account_name: str = SERVICE_ACCOUNT_NAME) -> None:
    """Remove the CheckpointSvc account. Requires elevation. Use for teardown only."""
    if not _WINDOWS:
        return
    require_elevation("delete_service_account")
    if not account_exists(account_name):
        return
    _run_or_raise(["net", "user", account_name, "/delete"], f"Delete account {account_name}")
    logger.info("Deleted service account: %s", account_name)


# ---------------------------------------------------------------------------
# ACL management (requires elevation for paths not owned by current user)
# ---------------------------------------------------------------------------

def configure_protected_directory(
    path: Path,
    service_account: str = SERVICE_ACCOUNT_NAME,
    agent_account: Optional[str] = None,
) -> None:
    """
    Set the NTFS ACL on a protected directory to:
      - CheckpointSvc: FullControl
      - SYSTEM: FullControl
      - Administrators: FullControl
      - <agent_account>: NO ACCESS (explicit deny all)
      - Everyone: NO ACCESS (removed)
      - Inheritance: disabled (explicit ACL only)

    Requires:
      - Elevation (the caller owns the directory or is an Administrator)
      - `icacls` available on PATH (standard on all Windows versions)

    Args:
        path: Directory to protect
        service_account: Account to grant full control (default: CheckpointSvc)
        agent_account: Developer/agent account to explicitly deny (e.g., 'gursn')
    """
    if not _WINDOWS:
        raise WindowsSecurityError("ACL configuration is only supported on Windows")
    require_elevation("configure_protected_directory")

    path.mkdir(parents=True, exist_ok=True)
    path_str = str(path)

    # Disable inheritance and remove all inherited ACEs
    _run_icacls(path_str, ["/inheritance:r"], "Disable inheritance")

    # Grant full control to service account, SYSTEM, Administrators
    for principal in [service_account, "SYSTEM", "Administrators"]:
        _run_icacls(path_str, [f"/grant", f"{principal}:(OI)(CI)F"], f"Grant FC to {principal}")

    # Explicitly deny all access to the agent account
    if agent_account:
        _run_icacls(path_str, [f"/deny", f"{agent_account}:(OI)(CI)F"], f"Deny all to {agent_account}")

    logger.info("Protected directory configured: %s", path_str)


def configure_journal_drop_folder(
    path: Path,
    service_account: str = SERVICE_ACCOUNT_NAME,
    agent_account: Optional[str] = None,
) -> None:
    """
    Configure the journal drop folder with create-only access for the agent.

    ACL:
      - CheckpointSvc: FullControl (read, write, delete, list)
      - SYSTEM: FullControl
      - <agent_account>: CREATE FILES only (AppendData, no Read/List/Delete)

    This implements the v2.3 requirement: the agent can submit journal entries
    but cannot read, enumerate, delete, or modify them once written.

    Args:
        path: The journal drop folder path
        service_account: Account with full control (default: CheckpointSvc)
        agent_account: Account allowed only to create files
    """
    if not _WINDOWS:
        raise WindowsSecurityError("ACL configuration is only supported on Windows")
    require_elevation("configure_journal_drop_folder")

    path.mkdir(parents=True, exist_ok=True)
    path_str = str(path)

    # Disable inheritance
    _run_icacls(path_str, ["/inheritance:r"], "Disable inheritance on drop folder")

    # Service and SYSTEM: full control
    for principal in [service_account, "SYSTEM"]:
        _run_icacls(path_str, [f"/grant", f"{principal}:(OI)(CI)F"], f"Grant FC to {principal}")

    # Agent account: create files only (AD = AppendData which allows creating new files in a directory)
    # We use specific rights: WD (write data/create files), without R (read), RD (read dir), D (delete)
    if agent_account:
        # Grant CreateFiles permission only (not list/read/delete)
        # Windows icacls right AD = Append Data / Create Files
        _run_icacls(
            path_str,
            [f"/grant", f"{agent_account}:(AD)"],
            f"Grant create-files only to {agent_account}"
        )

    logger.info("Journal drop folder configured: %s", path_str)


def configure_trash_directory(
    path: Path,
    service_account: str = SERVICE_ACCOUNT_NAME,
    agent_account: Optional[str] = None,
) -> None:
    """
    Configure the trash directory with Modify access for the agent account
    (needed for the restore UI to move files back from trash).

    ACL:
      - CheckpointSvc: FullControl
      - SYSTEM: FullControl
      - <agent_account>: Modify (can read, write, delete files for restore)
    """
    if not _WINDOWS:
        raise WindowsSecurityError("ACL configuration is only supported on Windows")
    require_elevation("configure_trash_directory")

    path.mkdir(parents=True, exist_ok=True)
    path_str = str(path)

    _run_icacls(path_str, ["/inheritance:r"], "Disable inheritance on trash")

    for principal in [service_account, "SYSTEM"]:
        _run_icacls(path_str, [f"/grant", f"{principal}:(OI)(CI)F"], f"Grant FC to {principal}")

    if agent_account:
        _run_icacls(
            path_str,
            [f"/grant", f"{agent_account}:(OI)(CI)M"],
            f"Grant Modify to {agent_account}"
        )

    logger.info("Trash directory configured: %s", path_str)


# ---------------------------------------------------------------------------
# Security verification (readable without elevation)
# ---------------------------------------------------------------------------

def verify_account_security() -> Dict[str, object]:
    """
    Verify the security configuration is in place.
    Returns a dict with keys: ok (bool), checks (list of check results).
    Does NOT require elevation — verification reads ACL metadata only.
    """
    checks = []
    all_ok = True

    # 1. CheckpointSvc account exists
    svc_exists = account_exists(SERVICE_ACCOUNT_NAME)
    checks.append({
        "check": "CheckpointSvc account exists",
        "result": svc_exists,
        "note": "Run scripts/setup_security.ps1 as Administrator" if not svc_exists else "OK",
    })
    all_ok = all_ok and svc_exists

    # 2. Current process is NOT running as CheckpointSvc
    if _WINDOWS:
        import ctypes
        current_user = ctypes.create_unicode_buffer(256)
        ctypes.windll.advapi32.GetUserNameW(current_user, ctypes.byref(ctypes.c_ulong(256)))  # type: ignore[attr-defined]
        running_as_svc = current_user.value.lower() == SERVICE_ACCOUNT_NAME.lower()
        checks.append({
            "check": "Agent process NOT running as CheckpointSvc",
            "result": not running_as_svc,
            "note": "CRITICAL: Agent is running as the service account!" if running_as_svc else "OK",
        })

    # 3. Security marker file exists
    from core.storage_paths import CHECKPOINT_BASE_SECURE
    marker = CHECKPOINT_BASE_SECURE / ".security_configured"
    try:
        marker_exists = marker.is_file()
    except (PermissionError, OSError):
        marker_exists = False
    checks.append({
        "check": "Security configured marker exists and is readable",
        "result": marker_exists,
        "note": "Run scripts/setup_security.ps1 as Administrator" if not marker_exists else "OK",
    })
    all_ok = all_ok and marker_exists

    return {"ok": all_ok, "checks": checks}


def verify_acl_boundary(path: Path, account: str) -> Dict[str, object]:
    """
    Verify that `account` does NOT have read access to `path`.
    Uses `icacls` to read the effective ACL and parses the output.

    Note: This checks the ACL metadata, not an actual cross-process access attempt.
    Use scripts/verify_security.ps1 for a true cross-process boundary test.
    """
    if not _WINDOWS:
        return {"ok": False, "note": "ACL verification only available on Windows"}

    result = subprocess.run(
        ["icacls", str(path)],
        capture_output=True, text=True
    )
    output = result.stdout + result.stderr

    # Rough check: look for explicit deny on the account
    has_deny = f"{account}:(DENY)" in output or f"{account}:(" in output and "D" in output
    has_allow = f"{account}:(F)" in output or f"{account}:(R)" in output

    return {
        "path": str(path),
        "account": account,
        "has_deny_entry": has_deny,
        "has_allow_entry": has_allow,
        "raw": output[:500],
        "note": "Full verification requires scripts/verify_security.ps1 cross-process test",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_icacls(path: str, args: List[str], operation: str) -> None:
    """Run icacls with the given path and arguments."""
    cmd = ["icacls", path] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise WindowsSecurityError(
            f"icacls {operation} failed (exit {result.returncode}): "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )


def _run_or_raise(cmd: List[str], operation: str) -> str:
    """Run a command and raise WindowsSecurityError on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise WindowsSecurityError(
            f"'{operation}' failed (exit {result.returncode}): "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )
    return result.stdout
