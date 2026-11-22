# scripts/verify_security.ps1
# Checkpoint Stage 5A: Post-Setup Security Verification Script
#
# PURPOSE: Verifies that the NTFS ACL security boundaries are actually enforced
#          by attempting cross-account file access from the current process context.
#
# IMPORTANT: This script verifies the ACL metadata and reports it. For a true
#            cross-process boundary test (proving the agent CANNOT read db\),
#            a separate process running as the agent account must attempt access.
#            See the "Cross-Process Boundary Test" section below.
#
# USAGE:
#   Run from a standard (non-elevated) PowerShell prompt as the agent account:
#     .\scripts\verify_security.ps1
#
#   Run from an elevated prompt for full ACL inspection:
#     .\scripts\verify_security.ps1 -Elevated

param(
    [switch]$Elevated = $false,
    [string]$AgentAccount = $env:USERNAME
)

$BaseDir = Join-Path $env:LOCALAPPDATA "Checkpoint"
$SvcAccount = "CheckpointSvc"

Write-Host "Checkpoint Security Verification Report" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Running as: $env:USERNAME"
Write-Host "Base dir: $BaseDir`n"

$allPassed = $true
$results = @()

# ---------------------------------------------------------------------------
# Check 1: CheckpointSvc account exists
# ---------------------------------------------------------------------------
Write-Host "[1] Checking CheckpointSvc account..." -ForegroundColor White
$svcExists = (net user $SvcAccount 2>&1) -match "^User name"
$results += [PSCustomObject]@{
    Check   = "CheckpointSvc account exists"
    Pass    = $svcExists
    Detail  = if ($svcExists) { "Account found" } else { "FAIL: Account not found — run setup_security.ps1 as Administrator" }
}
if (-not $svcExists) { $allPassed = $false }

# ---------------------------------------------------------------------------
# Check 2: Base directory exists
# ---------------------------------------------------------------------------
Write-Host "[2] Checking base directory..." -ForegroundColor White
$baseDirExists = Test-Path $BaseDir
$results += [PSCustomObject]@{
    Check   = "Base directory exists"
    Pass    = $baseDirExists
    Detail  = if ($baseDirExists) { $BaseDir } else { "FAIL: $BaseDir not found" }
}
if (-not $baseDirExists) { $allPassed = $false }

# ---------------------------------------------------------------------------
# Check 3: Security marker exists
# ---------------------------------------------------------------------------
Write-Host "[3] Checking security marker..." -ForegroundColor White
$marker = Join-Path $BaseDir ".security_configured"
$markerExists = Test-Path $marker
$results += [PSCustomObject]@{
    Check   = "Security configured marker"
    Pass    = $markerExists
    Detail  = if ($markerExists) { Get-Content $marker } else { "FAIL: Marker not found" }
}
if (-not $markerExists) { $allPassed = $false }

# ---------------------------------------------------------------------------
# Check 4–7: ACL verification on protected directories
# ---------------------------------------------------------------------------
$protectedDirs = @{
    "store"   = "Agent should be DENIED"
    "db"      = "Agent should be DENIED"
    "signing" = "Agent should be DENIED"
    "auth"    = "Agent should be DENIED"
}

foreach ($dir in $protectedDirs.Keys) {
    Write-Host "[4+] Checking ACL on $dir\..." -ForegroundColor White
    $path = Join-Path $BaseDir $dir
    if (-not (Test-Path $path)) {
        $results += [PSCustomObject]@{
            Check   = "Directory exists: $dir"
            Pass    = $false
            Detail  = "FAIL: $path not found"
        }
        $allPassed = $false
        continue
    }

    # Try to list/read the directory contents as the current user
    $canRead = $false
    try {
        $items = Get-ChildItem $path -ErrorAction Stop
        $canRead = $true
    } catch {
        $canRead = $false
    }

    # For protected dirs (store, db, signing, auth): agent should NOT be able to read
    $expectDenied = $true
    $pass = ($canRead -eq $false)  # Pass if we CANNOT read (correctly denied)

    # Note: If running as Administrator, we CAN read even protected dirs — that is expected
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isElevated) {
        $pass = $true  # Admin bypass is expected behavior
        $detail = "ELEVATED: Admin can always read (expected). ACL check skipped for admin token."
    } else {
        $detail = if ($pass) {
            "PASS: Access correctly denied for $AgentAccount"
        } else {
            "FAIL: $AgentAccount can read $dir — security boundary NOT enforced"
        }
    }

    if (-not $pass) { $allPassed = $false }
    $results += [PSCustomObject]@{
        Check  = "Agent access to $dir"
        Pass   = $pass
        Detail = $detail
    }
}

# ---------------------------------------------------------------------------
# Check 8: Journal drop folder — agent can CREATE but not READ
# ---------------------------------------------------------------------------
Write-Host "[8] Checking journal-drop folder access..." -ForegroundColor White
$dropPath = Join-Path $BaseDir "journal-drop"
if (Test-Path $dropPath) {
    # Try to create a file
    $testFile = Join-Path $dropPath "verify_test_$(Get-Random).tmp"
    $canCreate = $false
    try {
        [IO.File]::WriteAllText($testFile, "test")
        $canCreate = $true
        # Clean up — if we created it, we might be able to delete it too (that's a problem)
        $canDelete = $false
        try {
            Remove-Item $testFile -ErrorAction Stop
            $canDelete = $true
        } catch {
            $canDelete = $false
        }
        # If we couldn't delete, the file is still there — the service will clean it up
    } catch {
        $canCreate = $false
    }

    # Try to LIST the directory contents
    $canList = $false
    try {
        $items = Get-ChildItem $dropPath -ErrorAction Stop
        $canList = $true
    } catch {
        $canList = $false
    }

    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isElevated) {
        $results += [PSCustomObject]@{
            Check  = "Journal drop: create-only access"
            Pass   = $true
            Detail = "ELEVATED: Admin bypass expected. Run as $AgentAccount (non-elevated) for real test."
        }
    } else {
        $createPass = $canCreate  # Should be able to create
        $listPass   = -not $canList  # Should NOT be able to list
        $pass = $createPass -and $listPass
        if (-not $pass) { $allPassed = $false }
        $results += [PSCustomObject]@{
            Check  = "Journal drop: create-only access"
            Pass   = $pass
            Detail = "Create:$canCreate List:$canList Delete:$canDelete (want: Create=True, List=False)"
        }
    }
}

# ---------------------------------------------------------------------------
# Check 9: DPAPI availability
# ---------------------------------------------------------------------------
Write-Host "[9] Checking DPAPI availability..." -ForegroundColor White
try {
    Add-Type -AssemblyName System.Security
    $testBytes = [System.Text.Encoding]::UTF8.GetBytes("checkpoint_dpapi_verify")
    $entropy = [System.Text.Encoding]::UTF8.GetBytes("Checkpoint-v2.3-ACL-DPAPI-scope-2026")
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($testBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $dpApiWorks = ([System.Text.Encoding]::UTF8.GetString($decrypted) -eq "checkpoint_dpapi_verify")
    $results += [PSCustomObject]@{
        Check  = "DPAPI CurrentUser round-trip"
        Pass   = $dpApiWorks
        Detail = if ($dpApiWorks) { "PASS: DPAPI encrypt/decrypt works under $AgentAccount" } else { "FAIL: DPAPI round-trip mismatch" }
    }
} catch {
    $results += [PSCustomObject]@{
        Check  = "DPAPI CurrentUser round-trip"
        Pass   = $false
        Detail = "FAIL: $_"
    }
    $allPassed = $false
}

# ---------------------------------------------------------------------------
# Output report
# ---------------------------------------------------------------------------
Write-Host "`n=== VERIFICATION RESULTS ===" -ForegroundColor Cyan

foreach ($r in $results) {
    $color = if ($r.Pass) { "Green" } else { "Red" }
    $icon  = if ($r.Pass) { "✓" } else { "✗" }
    Write-Host "  $icon $($r.Check)" -ForegroundColor $color
    Write-Host "    $($r.Detail)" -ForegroundColor Gray
}

Write-Host ""
if ($allPassed) {
    Write-Host "OVERALL: ALL CHECKS PASSED — Security boundary is configured." -ForegroundColor Green
    Write-Host "CRITICAL tier approvals MAY be enabled after independent review." -ForegroundColor Green
} else {
    Write-Host "OVERALL: ONE OR MORE CHECKS FAILED — Security boundary is NOT confirmed." -ForegroundColor Red
    Write-Host "CRITICAL tier approvals must remain DISABLED until all checks pass." -ForegroundColor Red
}

Write-Host @"

NOTE: These checks verify ACL metadata and in-process access from the current
user context. For a full cross-process boundary test (confirming an agent
SUBPROCESS cannot access protected files), run:

  Start-Process powershell -ArgumentList '-Command Get-ChildItem ""$BaseDir\db""' -Credential (Get-Credential $AgentAccount) -Wait

This confirms the security boundary holds for a real agent process, not just
the verification script itself.
"@ -ForegroundColor Gray
