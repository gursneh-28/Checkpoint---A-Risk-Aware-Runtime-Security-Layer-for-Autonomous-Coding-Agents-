# scripts/teardown_security.ps1
# Checkpoint Stage 5A: Security Teardown Script
#
# PURPOSE: Cleanly removes the CheckpointSvc account and all protected storage.
#          Use for uninstallation or test environment cleanup only.
#          THIS IS IRREVERSIBLE — backup the database before running.
#
# REQUIREMENTS: Must be run as Administrator (elevated PowerShell)
#
# USAGE:
#   .\scripts\teardown_security.ps1 [-Force]

param(
    [switch]$Force = $false
)

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Must be run as Administrator."; exit 1
}

$BaseDir    = Join-Path $env:LOCALAPPDATA "Checkpoint"
$SvcAccount = "CheckpointSvc"

if (-not $Force) {
    $confirm = Read-Host "This will DELETE $SvcAccount and all Checkpoint storage at $BaseDir. Type YES to confirm"
    if ($confirm -ne "YES") { Write-Host "Aborted."; exit 0 }
}

Write-Host "Removing CheckpointSvc account..."
net user $SvcAccount /delete 2>&1 | Out-Null
Write-Host "Done (or account did not exist)."

Write-Host "Resetting ACLs and removing Checkpoint storage..."
if (Test-Path $BaseDir) {
    icacls $BaseDir /reset /T /Q 2>&1 | Out-Null
    Remove-Item $BaseDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed: $BaseDir"
} else {
    Write-Host "Directory not found: $BaseDir"
}

Write-Host "Teardown complete." -ForegroundColor Green
