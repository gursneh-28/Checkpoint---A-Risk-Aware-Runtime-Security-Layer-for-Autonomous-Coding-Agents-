# scripts/verify_security_cross.ps1
# Checkpoint Stage 5A: Cross-Account ACL Verification Script
#
# PURPOSE:
#   Verifies that the NTFS ACL boundaries set by setup_security.ps1 are
#   ACTUALLY enforced at the Windows kernel level — not just present in
#   icacls output.
#
# STRATEGY:
#   This script does NOT attempt to impersonate CheckpointSvc (which would
#   require storing and passing a plaintext password — a security anti-pattern).
#   Instead it verifies the boundary from the CURRENT USER's perspective:
#     1. Confirm the current process identity.
#     2. Try concrete file-system operations (read, write, list, modify, delete)
#        against each protected directory.
#     3. Assert that operations the agent SHOULD be denied actually fail.
#     4. Assert that journal-drop CREATE succeeds but LIST/READ/DELETE fail.
#
# WHAT THIS SCRIPT CANNOT VERIFY WITHOUT ELEVATION:
#   - That CheckpointSvc CAN access protected dirs (requires running as that account).
#   - Cross-account DPAPI isolation (requires encrypting under CheckpointSvc profile).
#   These limitations are documented in KNOWN_LIMITATIONS.md and MILESTONE5_PLAN.md.
#
# USAGE:
#   Run as the agent/developer account (non-elevated) AFTER setup_security.ps1:
#     .\scripts\verify_security_cross.ps1 [-BaseDir <path>] [-AgentAccount <name>]
#
# EXIT CODE:
#   0 = all checks passed
#   1 = one or more checks failed

param(
    [string]$BaseDir      = (Join-Path $env:LOCALAPPDATA "Checkpoint"),
    [string]$AgentAccount = $env:USERNAME
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
$script:AllPassed = $true
$script:Results   = [System.Collections.Generic.List[PSCustomObject]]::new()

function Record-Result {
    param(
        [string]$Check,
        [bool]  $Pass,
        [string]$Detail,
        [bool]  $Fatal = $true  # Fatal failures block the final summary
    )
    $script:Results.Add([PSCustomObject]@{
        Check  = $Check
        Pass   = $Pass
        Detail = $Detail
    })
    if (-not $Pass -and $Fatal) {
        $script:AllPassed = $false
    }
    $color = if ($Pass) { "Green" } else { "Red" }
    $icon  = if ($Pass) { "[PASS]" } else { "[FAIL]" }
    Write-Host "  $icon $Check" -ForegroundColor $color
    Write-Host "         $Detail" -ForegroundColor Gray
}

function Try-Operation {
    param(
        [scriptblock]$Block,
        [bool]        $ExpectSuccess
    )
    try {
        & $Block | Out-Null
        return $true  # Succeeded
    } catch {
        return $false  # Failed
    }
}

# ---------------------------------------------------------------------------
# 0. Identity confirmation
# ---------------------------------------------------------------------------
Write-Host "`nCheckpoint Cross-Account ACL Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Identity  : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "Account   : $AgentAccount"
Write-Host "Base dir  : $BaseDir`n"

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Record-Result `
    -Check  "Running as expected agent account ($AgentAccount)" `
    -Pass   ($currentIdentity -like "*$AgentAccount*") `
    -Detail "Current identity: $currentIdentity"

if ($isElevated) {
    Write-Host "  [WARN] Process is ELEVATED (Administrator). Protected dir tests will" -ForegroundColor Yellow
    Write-Host "         pass for elevated even when ACL denies non-elevated users." -ForegroundColor Yellow
    Write-Host "         Re-run this script from a NON-elevated prompt for a valid test.`n" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 1. Base directory and marker existence
# ---------------------------------------------------------------------------
Write-Host "[1] Base directory and security marker" -ForegroundColor White

Record-Result `
    -Check  "Base directory exists" `
    -Pass   (Test-Path $BaseDir) `
    -Detail $BaseDir

$marker = Join-Path $BaseDir ".security_configured"
$markerExists = Test-Path $marker
$markerContent = if ($markerExists) { Get-Content $marker -Raw } else { "(not found)" }
Record-Result `
    -Check  "Security configured marker exists" `
    -Pass   $markerExists `
    -Detail "Content: $($markerContent.Trim())"

# ---------------------------------------------------------------------------
# 2. Protected directory access — agent must be DENIED
# ---------------------------------------------------------------------------
Write-Host "`n[2] Protected directory access (agent must be DENIED)" -ForegroundColor White

$protectedDirs = @("store", "db", "signing", "auth")

foreach ($dir in $protectedDirs) {
    $dirPath = Join-Path $BaseDir $dir

    if (-not (Test-Path $dirPath -ErrorAction SilentlyContinue)) {
        Record-Result `
            -Check  "Directory exists: $dir" `
            -Pass   $false `
            -Detail "FAIL: $dirPath does not exist — run setup_security.ps1 first"
        continue
    }

    # Test 1: LIST directory
    $uniqueId   = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $canList    = Try-Operation { Get-ChildItem $dirPath -ErrorAction Stop } -ExpectSuccess $false
    $expectDeny = -not $isElevated  # Elevated bypasses ACLs by design

    Record-Result `
        -Check  "Agent CANNOT list $dir" `
        -Pass   ($isElevated -or (-not $canList)) `
        -Detail $(if ($isElevated) { "ELEVATED: admin bypass expected; re-run non-elevated" } elseif (-not $canList) { "Correctly denied" } else { "FAIL: agent can list $dir — ACL not enforced" })

    # Test 2: CREATE file
    $testFile   = Join-Path $dirPath "verify_cross_${uniqueId}.tmp"
    $canCreate  = Try-Operation { [IO.File]::WriteAllText($testFile, "checkpoint_verify_$uniqueId") } -ExpectSuccess $false

    Record-Result `
        -Check  "Agent CANNOT create file in $dir" `
        -Pass   ($isElevated -or (-not $canCreate)) `
        -Detail $(if ($isElevated) { "ELEVATED: admin bypass expected" } elseif (-not $canCreate) { "Correctly denied" } else { "FAIL: agent can write to $dir — ACL not enforced" })

    # Clean up if we accidentally created a file (only expected in elevated mode)
    if ($canCreate -and (Test-Path $testFile)) {
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    }

    # Test 3: READ a file (create a temp one elevated if possible to test read denial)
    # We test read-denial by trying to open an existing path object
    $canRead = Try-Operation {
        $null = [IO.Directory]::GetFiles($dirPath)
    } -ExpectSuccess $false

    Record-Result `
        -Check  "Agent CANNOT read $dir contents" `
        -Pass   ($isElevated -or (-not $canRead)) `
        -Detail $(if ($isElevated) { "ELEVATED: admin bypass expected" } elseif (-not $canRead) { "Correctly denied" } else { "FAIL: agent has read access to $dir" })
}

# ---------------------------------------------------------------------------
# 3. Journal-drop — agent must CREATE but NOT list/read/delete
# ---------------------------------------------------------------------------
Write-Host "`n[3] Journal-drop: create-only boundary" -ForegroundColor White

$dropPath = Join-Path $BaseDir "journal-drop"

if (-not (Test-Path $dropPath -ErrorAction SilentlyContinue)) {
    Record-Result `
        -Check  "journal-drop directory exists" `
        -Pass   $false `
        -Detail "FAIL: $dropPath not found — run setup_security.ps1 first"
} else {
    $uid      = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $testFile = Join-Path $dropPath "verify_cross_${uid}.journal"

    # Test: CREATE file (agent SHOULD be allowed)
    $canCreate = Try-Operation {
        # Use AppendData-compatible write: open with FileShare.None, FileMode.Create
        $fs = [IO.File]::Open($testFile, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("checkpoint_journal_verify_$uid")
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Close()
    } -ExpectSuccess $true

    Record-Result `
        -Check  "Agent CAN create file in journal-drop" `
        -Pass   $canCreate `
        -Detail $(if ($canCreate) { "File created: $testFile" } else { "FAIL: agent cannot create in journal-drop — ACL misconfigured" })

    # Test: LIST directory (agent must NOT be allowed)
    $canList = Try-Operation { Get-ChildItem $dropPath -ErrorAction Stop } -ExpectSuccess $false
    Record-Result `
        -Check  "Agent CANNOT list journal-drop" `
        -Pass   ($isElevated -or (-not $canList)) `
        -Detail $(if ($isElevated) { "ELEVATED: admin bypass expected" } elseif (-not $canList) { "Correctly denied" } else { "FAIL: agent can list journal-drop" })

    # Test: READ specific file (agent must NOT be allowed to read back)
    if ($canCreate) {
        $canRead = Try-Operation {
            [IO.File]::ReadAllText($testFile) | Out-Null
        } -ExpectSuccess $false
        Record-Result `
            -Check  "Agent CANNOT read file from journal-drop" `
            -Pass   ($isElevated -or (-not $canRead)) `
            -Detail $(if ($isElevated) { "ELEVATED: admin bypass expected" } elseif (-not $canRead) { "Correctly denied" } else { "FAIL: agent can read journal files" })

        # Test: DELETE file (agent must NOT be allowed)
        $canDelete = Try-Operation { Remove-Item $testFile -Force -ErrorAction Stop } -ExpectSuccess $false
        Record-Result `
            -Check  "Agent CANNOT delete file from journal-drop" `
            -Pass   ($isElevated -or (-not $canDelete)) `
            -Detail $(if ($isElevated) { "ELEVATED: admin bypass expected; file may remain for service to clean" } elseif (-not $canDelete) { "Correctly denied" } else { "FAIL: agent can delete from journal-drop" })
    }
}

# ---------------------------------------------------------------------------
# 4. Git-backups — agent must READ but not MODIFY/DELETE
# ---------------------------------------------------------------------------
Write-Host "`n[4] Git-backups: read-only boundary for agent" -ForegroundColor White

$gitBackupsPath = Join-Path $BaseDir "git-backups"

if (-not (Test-Path $gitBackupsPath -ErrorAction SilentlyContinue)) {
    Record-Result `
        -Check  "git-backups directory exists" `
        -Pass   $false `
        -Detail "FAIL: $gitBackupsPath not found"
} else {
    # Read / list (should be allowed)
    $canList = Try-Operation { Get-ChildItem $gitBackupsPath -ErrorAction Stop } -ExpectSuccess $true
    Record-Result `
        -Check  "Agent CAN list git-backups" `
        -Pass   $canList `
        -Detail $(if ($canList) { "Correctly allowed" } else { "FAIL: agent cannot read git-backups — restore UI would be broken" })

    # Write (should be denied)
    $uid      = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $testFile = Join-Path $gitBackupsPath "verify_cross_${uid}.tmp"
    $canWrite = Try-Operation { [IO.File]::WriteAllText($testFile, "test") } -ExpectSuccess $false
    if ($canWrite -and (Test-Path $testFile)) { Remove-Item $testFile -Force -ErrorAction SilentlyContinue }
    Record-Result `
        -Check  "Agent CANNOT write to git-backups" `
        -Pass   ($isElevated -or (-not $canWrite)) `
        -Detail $(if ($isElevated) { "ELEVATED: admin bypass expected" } elseif (-not $canWrite) { "Correctly denied" } else { "FAIL: agent has write access to git-backups" })
}

# ---------------------------------------------------------------------------
# 5. DPAPI same-user round-trip (documents the limitation clearly)
# ---------------------------------------------------------------------------
Write-Host "`n[5] DPAPI same-user round-trip" -ForegroundColor White

try {
    Add-Type -AssemblyName System.Security
    $testBytes = [System.Text.Encoding]::UTF8.GetBytes("checkpoint_dpapi_verify_$(Get-Date -Format 'yyyyMMddHHmmss')")
    $entropy   = [System.Text.Encoding]::UTF8.GetBytes("Checkpoint-v2.3-ACL-DPAPI-scope-2026")
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        $testBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $dpApiWorks = ([System.Text.Encoding]::UTF8.GetBytes([System.Text.Encoding]::UTF8.GetString($decrypted)) -join ',') -eq ($testBytes -join ',')
    Record-Result `
        -Check  "DPAPI CurrentUser round-trip ($AgentAccount)" `
        -Pass   $dpApiWorks `
        -Detail $(if ($dpApiWorks) { "PASS: encrypt/decrypt works. NOTE: This only verifies same-user round-trip, not cross-account isolation." } else { "FAIL: DPAPI mismatch" })
} catch {
    Record-Result `
        -Check  "DPAPI CurrentUser round-trip ($AgentAccount)" `
        -Pass   $false `
        -Detail "FAIL: $_"
}

Write-Host "`n  [NOTE] Cross-account DPAPI isolation (CheckpointSvc blobs not readable by $AgentAccount)" -ForegroundColor Yellow
Write-Host "         CANNOT be verified without first running the application AS CheckpointSvc." -ForegroundColor Yellow
Write-Host "         See KNOWN_LIMITATIONS.md and MILESTONE5_PLAN.md for details.`n" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VERIFICATION RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($r in $script:Results) {
    $color = if ($r.Pass) { "Green" } else { "Red" }
    $icon  = if ($r.Pass) { "[PASS]" } else { "[FAIL]" }
    Write-Host "  $icon  $($r.Check)" -ForegroundColor $color
}

Write-Host ""
if ($script:AllPassed) {
    Write-Host "OVERALL: ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "The agent-account security boundary is enforced from this user's perspective." -ForegroundColor Green
    if ($isElevated) {
        Write-Host "WARNING: Script ran elevated — re-run as a NON-elevated agent session for valid results." -ForegroundColor Yellow
    }
    exit 0
} else {
    Write-Host "OVERALL: ONE OR MORE CHECKS FAILED" -ForegroundColor Red
    Write-Host "Security boundary is NOT confirmed. Do not enable CRITICAL tier approvals." -ForegroundColor Red
    exit 1
}
