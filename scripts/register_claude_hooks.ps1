# scripts/register_claude_hooks.ps1
# Purpose: Register Claude Code hook scripts with the installed Claude Code CLI.
# This script is a no‑op if Claude Code is not installed.

param(
    [switch]$Force = $false,
    [switch]$DryRun = $false
)

function Write-Info($msg) {
    Write-Host "[INFO] $msg" -ForegroundColor Cyan
}

function Write-Warn($msg) {
    Write-Host "[WARN] $msg" -ForegroundColor Yellow
}

# Check for Claude Code executable
$claudeExe = Get-Command "claude" -ErrorAction SilentlyContinue
if (-not $claudeExe) {
    Write-Warn "Claude Code CLI not found in PATH. Skipping hook registration."
    exit 0
}

# Paths to hook adapters (we use the simulated adapter for now)
$hookAdapter = Join-Path $PSScriptRoot "..\core\claude_code_adapter.py"
if (-not (Test-Path $hookAdapter)) {
    Write-Warn "Hook adapter script not found at $hookAdapter. Cannot register."
    exit 1
}

# Register PreToolUse hook
if (-not $DryRun) {
    & $claudeExe hook register --event PreToolUse --script $hookAdapter
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Failed to register PreToolUse hook."
    } else {
        Write-Info "PreToolUse hook registered."
    }
    # Register PostToolUse hook similarly
    & $claudeExe hook register --event PostToolUse --script $hookAdapter
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Failed to register PostToolUse hook."
    } else {
        Write-Info "PostToolUse hook registered."
    }
} else {
    Write-Info "[DRY RUN] Would register PreToolUse and PostToolUse hooks."
}

Write-Info "Hook registration complete."
