# scripts/setup_security.ps1
# Checkpoint Stage 5A: Host-Level Security Setup Script
#
# PURPOSE: Creates the CheckpointSvc Windows service account and configures
#          NTFS ACLs on all Checkpoint protected storage paths.
#
# REQUIREMENTS:
#   - Must be run as Administrator (elevated PowerShell session)
#   - Windows 10/11 or Windows Server 2016+
#   - icacls available (standard on all modern Windows)
#
# USAGE:
#   Run from an elevated PowerShell prompt:
#     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#     .\scripts\setup_security.ps1 [-AgentAccount <username>] [-DryRun]
#
# WHAT THIS SCRIPT DOES:
#   1. Verifies it is running elevated
#   2. Creates the CheckpointSvc local standard user account
#   3. Denies CheckpointSvc interactive logon via secedit
#   4. Creates all Checkpoint storage directories
#   5. Sets restrictive NTFS ACLs on each directory
#   6. Writes a .security_configured marker file
#   7. Prints a verification summary
#
# WHAT THIS SCRIPT DOES NOT DO:
#   - Push to GitHub or modify remote state
#   - Modify system-wide firewall or network settings
#   - Register a Windows Service (that is a separate optional step)
#   - Touch any agent/developer working files
#
# v2.3 Specification: Section "Phase 0 / Phase 1 Security Gates"

param(
    [string]$AgentAccount = $env:USERNAME,
    [switch]$DryRun = $false,
    [switch]$Teardown = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Elevation check
# ---------------------------------------------------------------------------
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error @"
ERROR: This script must be run as Administrator.

Open an elevated PowerShell prompt:
  Right-click PowerShell → 'Run as administrator'
  Then run: .\scripts\setup_security.ps1
"@
    exit 1
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$SvcAccount  = "CheckpointSvc"
# Generate a strong random password for initial account provisioning.
# IMPORTANT: The password is used ONCE to create the account.
# It is NOT stored to disk in any form — not plaintext, not DPAPI-encrypted —
# because DPAPI CurrentUser-encrypted data cannot be decrypted by CheckpointSvc
# and machine-scoped DPAPI allows any local account to decrypt it.
#
# Post-creation credential management strategy:
#   - Routine operation of Checkpoint does NOT require knowing this password.
#   - If the password must later be changed (e.g., policy rotation), run this
#     script again or use "Set-LocalUser -Name CheckpointSvc -Password" elevated.
#   - Verification scripts do NOT decrypt or redisplay the password.
$SvcPassword = -join ((65..90 + 97..122 + 48..57 + '!@#$%'.ToCharArray()) | Get-Random -Count 24 | ForEach-Object {[char]$_})
$BaseDir     = Join-Path $env:LOCALAPPDATA "Checkpoint"

$Dirs = @{
    "store"        = "blob store (CheckpointSvc:F, $AgentAccount:DENY)"
    "db"           = "database (CheckpointSvc:F, $AgentAccount:DENY)"
    "journal-drop" = "journal drop folder (CheckpointSvc:F, $AgentAccount:CREATE-ONLY)"
    "git-backups"  = "git backups (CheckpointSvc:F, $AgentAccount:ReadAndExecute)"
    "signing"      = "signing keys (CheckpointSvc:F, $AgentAccount:DENY)"
    "auth"         = "credential store (CheckpointSvc:F, $AgentAccount:DENY)"
    "trash"        = "recoverable trash (CheckpointSvc:F, $AgentAccount:Modify)"
}

# ---------------------------------------------------------------------------
# Teardown mode
# ---------------------------------------------------------------------------
if ($Teardown) {
    Write-Host "TEARDOWN MODE: Removing CheckpointSvc account and storage..." -ForegroundColor Yellow
    if (-not $DryRun) {
        try { net user $SvcAccount /delete 2>&1 | Out-Null } catch {}
        # Reset ACLs before removal
        if (Test-Path $BaseDir) {
            icacls $BaseDir /reset /T /Q 2>&1 | Out-Null
            Remove-Item $BaseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Teardown complete." -ForegroundColor Green
    } else {
        Write-Host "[DRY RUN] Would delete $SvcAccount and $BaseDir"
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
function Write-Step($msg) {
    Write-Host "  → $msg" -ForegroundColor Cyan
}

function Write-OK($msg) {
    Write-Host "  ✓ $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "  ⚠ $msg" -ForegroundColor Yellow
}

function Run-Or-Warn($cmd, $desc) {
    if ($DryRun) {
        Write-Host "  [DRY RUN] $desc"
        return
    }
    try {
        Invoke-Expression $cmd | Out-Null
        Write-OK $desc
    } catch {
        Write-Warn "Non-fatal: $desc failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Step 1: Create CheckpointSvc account
# ---------------------------------------------------------------------------
Write-Host "`n[Step 1] Creating CheckpointSvc service account..." -ForegroundColor White

$accountExists = (net user $SvcAccount 2>&1) -match $SvcAccount
if ($accountExists) {
    Write-OK "Account $SvcAccount already exists — skipping creation"
} else {
    if (-not $DryRun) {
        # Use New-LocalUser with SecureString so the password is never passed as
        # a plaintext command-line argument (visible in process lists, audit logs, etc.).
        $securePwd = ConvertTo-SecureString $SvcPassword -AsPlainText -Force
        try {
            New-LocalUser `
                -Name        $SvcAccount `
                -Password    $securePwd `
                -Description "Checkpoint runtime security service account - do not remove" `
                -PasswordNeverExpires $true `
                -UserMayNotChangePassword $true `
                -AccountNeverExpires `
                -ErrorAction Stop | Out-Null
        } finally {
            # Clear the SecureString from memory immediately after use.
            if ($securePwd) { $securePwd.Dispose() }
            # Zero out the plaintext password variable — it is no longer needed.
            # PowerShell cannot truly zero a string, but reassigning removes the reference.
            Remove-Variable -Name SvcPassword -Force -ErrorAction SilentlyContinue
            [System.GC]::Collect()
        }
        Write-OK "Created account: $SvcAccount (password NOT stored — not needed for routine operation)"
    } else {
        Write-Host "  [DRY RUN] Would create account $SvcAccount"
    }
}

# ---------------------------------------------------------------------------
# Step 2: Deny interactive logon via secedit
# ---------------------------------------------------------------------------
Write-Host "`n[Step 2] Denying interactive logon for $SvcAccount..." -ForegroundColor White

if (-not $DryRun) {
    try {
        $userSid = (New-Object System.Security.Principal.NTAccount($SvcAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $seceditInf = @"
[Unicode]
Unicode=yes
[System Access]
[Event Audit]
[Registry Values]
[Privilege Rights]
SeDenyInteractiveLogonRight = *$userSid
SeDenyNetworkLogonRight = *$userSid
SeDenyRemoteInteractiveLogonRight = *$userSid
"@
        $tempInf = [IO.Path]::GetTempFileName() + ".inf"
        $tempDb  = [IO.Path]::GetTempFileName() + ".sdb"
        $seceditInf | Set-Content -Encoding Unicode $tempInf
        secedit /import /cfg $tempInf /db $tempDb /quiet 2>&1 | Out-Null
        secedit /configure /db $tempDb /cfg $tempInf /quiet 2>&1 | Out-Null
        Remove-Item $tempInf, $tempDb -ErrorAction SilentlyContinue
        Write-OK "Denied interactive/network logon for $SvcAccount"
    } catch {
        Write-Warn "secedit configuration failed (non-fatal on some editions): $_"
    }
} else {
    Write-Host "  [DRY RUN] Would deny interactive logon for $SvcAccount"
}

# ---------------------------------------------------------------------------
# Step 3: Create protected directory structure
# ---------------------------------------------------------------------------
Write-Host "`n[Step 3] Creating protected directory structure under $BaseDir..." -ForegroundColor White

if (-not (Test-Path $BaseDir)) {
    if (-not $DryRun) {
        New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
    }
    Write-OK "Created base directory: $BaseDir"
} else {
    Write-OK "Base directory already exists: $BaseDir"
}

foreach ($dir in $Dirs.Keys) {
    $fullPath = Join-Path $BaseDir $dir
    if (-not $DryRun) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }
    Write-Step "Created: $fullPath ($($Dirs[$dir]))"
}

# ---------------------------------------------------------------------------
# Step 4: Configure ACLs
# ---------------------------------------------------------------------------
Write-Host "`n[Step 4] Configuring NTFS ACLs..." -ForegroundColor White

function Set-ProtectedAcl($path, $grantExtra) {
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would set protected ACL on: $path"
        return
    }
    # Disable inheritance, remove all inherited ACEs
    icacls $path /inheritance:r /Q 2>&1 | Out-Null
    # Grant full control to service account, SYSTEM, Administrators
    icacls $path /grant "${SvcAccount}:(OI)(CI)F" /Q 2>&1 | Out-Null
    icacls $path /grant "SYSTEM:(OI)(CI)F" /Q 2>&1 | Out-Null
    icacls $path /grant "Administrators:(OI)(CI)F" /Q 2>&1 | Out-Null
    # Apply any extra grants
    foreach ($g in $grantExtra) {
        icacls $path /grant $g /Q 2>&1 | Out-Null
    }
    # Explicitly deny developer/agent account all access
    icacls $path /deny "${AgentAccount}:(OI)(CI)F" /Q 2>&1 | Out-Null
    Write-OK "ACL set: $path"
}

# store\ — deny all to agent
Set-ProtectedAcl (Join-Path $BaseDir "store") @()

# db\ — deny all to agent
Set-ProtectedAcl (Join-Path $BaseDir "db") @()

# signing\ — deny all to agent
Set-ProtectedAcl (Join-Path $BaseDir "signing") @()

# auth\ — deny all to agent
Set-ProtectedAcl (Join-Path $BaseDir "auth") @()

# git-backups\ — read-only to agent (for restore UI)
Set-ProtectedAcl (Join-Path $BaseDir "git-backups") @("${AgentAccount}:(OI)(CI)RX")
# Note: the deny above will override — we must explicitly NOT deny here
if (-not $DryRun) {
    $gbPath = Join-Path $BaseDir "git-backups"
    # Remove the deny-all entry we just set, replace with read-only deny-modify
    icacls $gbPath /remove:d $AgentAccount /Q 2>&1 | Out-Null
    icacls $gbPath /deny "${AgentAccount}:(OI)(CI)W" /Q 2>&1 | Out-Null
    Write-OK "git-backups: set read-only for $AgentAccount (can read, cannot write/delete)"
}

# journal-drop\ — create-files only for agent (AppendData = AD in icacls)
if (-not $DryRun) {
    $dropPath = Join-Path $BaseDir "journal-drop"
    icacls $dropPath /inheritance:r /Q 2>&1 | Out-Null
    icacls $dropPath /grant "${SvcAccount}:(OI)(CI)F" /Q 2>&1 | Out-Null
    icacls $dropPath /grant "SYSTEM:(OI)(CI)F" /Q 2>&1 | Out-Null
    icacls $dropPath /grant "Administrators:(OI)(CI)F" /Q 2>&1 | Out-Null
    # AppendData on the directory = ability to create new files; not read/list/delete
    icacls $dropPath /grant "${AgentAccount}:(AD)" /Q 2>&1 | Out-Null
    Write-OK "journal-drop: $AgentAccount can create files only (no read/list/delete)"
} else {
    Write-Host "  [DRY RUN] Would set create-only ACL on journal-drop for $AgentAccount"
}

# trash\ — Modify access for agent (restore UI needs it)
if (-not $DryRun) {
    $trashPath = Join-Path $BaseDir "trash"
    icacls $trashPath /inheritance:r /Q 2>&1 | Out-Null
    icacls $trashPath /grant "${SvcAccount}:(OI)(CI)F" /Q 2>&1 | Out-Null
    icacls $trashPath /grant "SYSTEM:(OI)(CI)F" /Q 2>&1 | Out-Null
    icacls $trashPath /grant "Administrators:(OI)(CI)F" /Q 2>&1 | Out-Null
    icacls $trashPath /grant "${AgentAccount}:(OI)(CI)M" /Q 2>&1 | Out-Null
    Write-OK "trash: $AgentAccount has Modify access (for restore UI)"
} else {
    Write-Host "  [DRY RUN] Would set Modify ACL on trash for $AgentAccount"
}

# ---------------------------------------------------------------------------
# Step 5: Write security configured marker
# ---------------------------------------------------------------------------
Write-Host "`n[Step 5] Writing security configured marker..." -ForegroundColor White

if (-not $DryRun) {
    $marker = Join-Path $BaseDir ".security_configured"
    Set-Content -Path $marker -Value "CheckpointSvc security configured $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') agent=$AgentAccount"
    Write-OK "Marker written: $marker"
} else {
    Write-Host "  [DRY RUN] Would write .security_configured marker"
}

# ---------------------------------------------------------------------------
# Step 6: Summary and verification instructions
# ---------------------------------------------------------------------------
Write-Host "`n[Step 6] Verification..." -ForegroundColor White

if (-not $DryRun) {
    Write-Host "`n--- icacls output for key directories ---" -ForegroundColor Gray
    foreach ($dir in @("store", "db", "journal-drop", "signing")) {
        $p = Join-Path $BaseDir $dir
        Write-Host "`n$p :" -ForegroundColor Gray
        icacls $p
    }
}

Write-Host @"

============================================================
  Checkpoint Stage 5A Security Setup — COMPLETE
============================================================

  Service account : $SvcAccount
  Agent account   : $AgentAccount
  Base directory  : $BaseDir

  NEXT STEPS:
  1. Run the verification script to confirm ACL boundaries:
       .\scripts\verify_security.ps1
  2. Restart the Checkpoint application so it picks up the
     new storage paths from %LOCALAPPDATA%\Checkpoint\
  3. Run the full test suite to confirm nothing regressed:
       venv\Scripts\python.exe -m pytest tests\ -v
  4. CRITICAL tier approvals remain disabled until the
     verification script confirms all boundaries are enforced.
  5. Proceed to Stage 5B: Claude Code installation and
     live hook integration.
============================================================
"@ -ForegroundColor Green
