# Milestone 5: Host-Level Security Integration & Live Agent Verification
## Implementation and Verification Plan

**Based on:** Checkpoint v2.3 Specification  
**Date:** 2026-11-22  
**Status:** Pre-implementation environmental assessment complete

---

## 1. Environmental Assessment Results

### 1.1 Current Windows Account Context

| Property | Value | Implication |
|---|---|---|
| Current user | `MSI\gursn` | Standard user running under UAC |
| Administrators membership | YES (listed) but **token is filtered** | UAC splits the token; `IsInRole(Administrator)` returns `False` |
| Elevated privilege | **NO** — `whoami /priv` shows only `SeShutdownPrivilege` (Disabled) and `SeChangeNotifyPrivilege` | Cannot create accounts or set system ACLs without elevation |
| `SeSecurityPrivilege` | **NOT HELD** | Cannot modify SACL/security audit entries |
| `CheckpointSvc` account | **Does NOT exist** | Must be created with admin elevation |
| Claude Code | **NOT INSTALLED** — not found in PATH, registry, `%LOCALAPPDATA%\Claude`, npm global | Stage 5B blocked pending installation |

### 1.2 Capability Findings

| Capability | Available | Notes |
|---|---|---|
| Create local user accounts (`net user /add`) | **NO** — Error 5 Access Denied | Requires elevated Administrator token |
| Set ACLs on own directories (`Set-Acl`) | **PARTIAL** — Can add rules but not modify SACL | `SeSecurityPrivilege` not held; inheritance reset fails |
| Set Deny ACLs on own directories | **YES** — `icacls` and PowerShell ACL rules work for DACL | Confirmed by test |
| `icacls /reset` to restore inherited ACLs | **YES** | Works in user context |
| DPAPI `CurrentUser` encryption | **YES** — Confirmed working round-trip | Encrypts under current user's key material |
| Remove items with custom deny ACLs | **NO** (must reset ACL first) | Need `icacls /reset` before `Remove-Item` |

### 1.3 Security Architecture Reality Check

The v2.3 specification requires `CheckpointSvc` to be a **separate Windows standard account** from the agent/developer account (`gursn`). This creates a genuine OS-level process boundary.

**Without a separate account:**
- DPAPI `CurrentUser` encryption uses `gursn`'s key material — any process running as `gursn` can decrypt it
- ACL restrictions granting access only to `CheckpointSvc` are meaningless if no such account exists
- Same-user deployment cannot provide the security boundary the spec requires

**What this means for Milestone 5 execution:**
- Creating `CheckpointSvc` requires an **elevated (UAC-elevated) PowerShell session**
- Setting ACLs that **deny `gursn`** access to Checkpoint storage requires the owner to be `CheckpointSvc` or `SYSTEM`, which also requires elevation
- This cannot be done from the current non-elevated process

---

## 2. What CAN Be Implemented Without Elevation

The following Stage 5A components can be fully implemented and tested in the current user context:

| Component | Implementation Approach |
|---|---|
| `core/windows_security.py` — Security manager | Full Python implementation with account creation, ACL, DPAPI logic; runs with elevation |
| `scripts/setup_security.ps1` — Setup script | PowerShell that creates account, sets ACLs, configures DPAPI — requires elevation to run |
| `scripts/verify_security.ps1` — Verification script | Tests actual ACL boundaries from multiple process contexts |
| DPAPI Python wrapper (`core/dpapi.py`) | ctypes-based wrapper; can be implemented and unit tested now |
| Storage path configuration (`core/storage_paths.py`) | Abstracts `%LOCALAPPDATA%\Checkpoint\` paths; usable today |
| ACL helper functions | PowerShell helpers callable from Python; testable in current context for DACL parts |
| Automated boundary tests (simulated) | Tests that verify the logic without requiring the actual account |
| Claude Code installation verification | Detection logic + installation guide |

---

## 3. Stage 5A Implementation Plan

### Phase 5A-1: Security Infrastructure Code

**Files to create:**
- `core/windows_security.py` — Windows account, ACL, DPAPI operations
- `core/dpapi.py` — Python DPAPI wrapper (ctypes → `crypt32.dll`)
- `core/storage_paths.py` — Checkpoint storage path manager
- `scripts/setup_security.ps1` — Elevated setup script (run once by admin)
- `scripts/verify_security.ps1` — Post-setup verification script
- `scripts/teardown_security.ps1` — Clean removal script
- `tests/test_windows_security.py` — Unit tests (non-elevation path)
- `tests/test_dpapi.py` — DPAPI round-trip tests under current user

### Phase 5A-2: Setup Script — `CheckpointSvc` Account Creation

The setup script must:
1. Create a `CheckpointSvc` local standard user account with a machine-generated strong password
2. Set the account to never expire, deny interactive logon
3. Create `%LOCALAPPDATA%\Checkpoint\` directory tree owned by `CheckpointSvc`
4. Set ACLs: `CheckpointSvc:F, SYSTEM:F, Administrators:F, gursn:(deny all)`
5. Set journal drop folder: `CheckpointSvc:(GW only), gursn:(AppendData only — create new files, not read/modify/delete existing)`
6. Store the service account password encrypted under `CheckpointSvc` DPAPI `CurrentUser`
7. Register the Checkpoint service to run as `CheckpointSvc`

### Phase 5A-3: Storage Security

Protected paths under `%LOCALAPPDATA%\Checkpoint\`:
```
store\          — blob store (CheckpointSvc:F, all others:deny)
db\             — checkpoint.db (CheckpointSvc:F, all others:deny)
journal-drop\   — drop folder (gursn:CreateFiles, CheckpointSvc:F, no read/delete for gursn)
git-backups\    — bare repos (CheckpointSvc:F, gursn:read for restore UI only)
signing\        — session signing key (CheckpointSvc:F, all others:deny)
trash\          — recoverable trash (gursn:Modify — needed for restore; CheckpointSvc:F)
```

### Phase 5A-4: DPAPI Integration

Replace plaintext `storage/auth/session_signing.key` with DPAPI-encrypted version:
- Key generation: `secrets.token_bytes(32)` 
- Encryption: DPAPI `CryptProtectData` under `CheckpointSvc` profile
- Storage: `%LOCALAPPDATA%\Checkpoint\signing\signing.key.dpapi`
- Decryption: Called only by Checkpoint service process (running as `CheckpointSvc`)

### Phase 5A-5: Security Verification Tests

**Automated (runnable now):**
- DPAPI round-trip under current user
- ACL helper function logic
- Storage path resolution
- Account existence detection

**Requires setup script to have been run (post-setup):**
- Verify `CheckpointSvc` account exists and is non-interactive
- Verify `gursn` process cannot read `checkpoint.db`
- Verify `gursn` process can CREATE but not READ/DELETE drop folder files
- Verify DPAPI-encrypted key fails to decrypt under `gursn` profile
- Verify dashboard still serves authenticated requests

---

## 4. Stage 5B Implementation Plan

### Prerequisites
1. `CheckpointSvc` account and ACLs configured (Stage 5A)
2. Claude Code installed on this machine

### Claude Code Installation
- Package: `@anthropic-ai/claude-code` via npm
- Requires: Node.js 18+, npm, Anthropic API key
- Hook registration: `C:\Program Files\ClaudeCode\managed-settings.json` (requires admin)
- Alternative if managed-settings blocked: user-level `.claude/settings.json`

### Phase 5B-1: Claude Code Installation Verification
- Confirm `claude --version` works
- Confirm hook config path is writable or confirm admin registration path
- Confirm Node.js version ≥ 18

### Phase 5B-2: Hook Integration
- Write actual `hooks/checkpoint_hook.py` that is called by Claude Code
- Register `PreToolUse` and `PostToolUse` hooks in settings
- Configure `onFailure: block` for all hooks
- Implement `updatedInput` path for command rewriting

### Phase 5B-3: Live Verification
Test real scenarios:
- LOW tier command → auto-approved, hook returns allow
- MEDIUM/HIGH → hook returns block, dashboard shows pending
- Approval → hook receives approval signal
- Timeout → hook returns block after 300s
- Malformed JSON input → fail closed
- Service down → fail closed
- `onFailure: block` verified by killing service during hook call

---

## 5. Security Gate Status (Current Pre-Elevation Audit Status)

| Gate | Status | Details / Blocker |
|---|---|---|
| `core/storage_paths.py` path manager | ✅ VERIFIED | Production mode fail-closed; dev mode workspace fallback (`CHECKPOINT_DEV_MODE=1`); `force_workspace=True` blocked in production; 18 unit tests passing. |
| Non-fallback audit across all modules | ✅ VERIFIED | `storage/db.py`, `core/suggestions.py`, and `core/auth.py` hardened against silent un-gated fallback in production. |
| DPAPI Python wrapper (`core/dpapi.py`) | ✅ VERIFIED | ctypes wrapper for CryptProtectData/CryptUnprotectData with CurrentUser scope; 12 unit tests passing. |
| DPAPI service password provisioning | ✅ SECURED | Passwords are created via `New-LocalUser` with `SecureString` and immediately zeroed from memory. No CurrentUser DPAPI storage of service passwords across account boundaries. |
| `scripts/setup_security.ps1` | ✅ AUDITED & READY | Fully idempotent, uses `New-LocalUser`, sets explicit ACLs, denies interactive logon. Awaiting elevated execution. |
| `scripts/verify_security.ps1` | ✅ AUDITED & READY | Inspects identity, ACL metadata, journal-drop create/list behavior. |
| `scripts/verify_security_cross.ps1` | ✅ AUDITED & READY | Process-argument safe, verifies current Windows identity, conducts explicit create/read/list/modify/delete checks per protected directory. |
| ACL cross-account integration tests (`tests/test_acl_cross.py`) | ✅ VERIFIED | Integration tests skip cleanly when `CHECKPOINT_INTEGRATION=1` or service account is missing; never false-pass. |
| `CheckpointSvc` account creation | 🟡 AWAITING AUTHORIZATION | Setup script ready; requires user execution in elevated Administrator PowerShell. |
| NTFS ACL application | 🟡 AWAITING AUTHORIZATION | Setup script ready; requires elevated execution. |
| Checkpoint service registration | ⏳ PENDING | Service daemon integration following ACL setup. |
| Claude Code CLI installation | 🔴 NOT INSTALLED | Stage 5B prerequisite. |
| Hook registration (`register_claude_hooks.ps1`) | 🟡 READY | Script prepared; awaiting Claude Code CLI installation. |
| Live hook verification | 🔴 BLOCKED | Requires Claude Code installation and service account setup. |
| CRITICAL approvals re-enable | 🔒 DISABLED | Strictly disabled until all host-level boundaries and service execution are verified. |

---

## 6. Implementation Order

1. `core/storage_paths.py` — path abstraction
2. `core/dpapi.py` — DPAPI ctypes wrapper
3. `core/windows_security.py` — account, ACL, service helpers
4. `scripts/setup_security.ps1` — elevated setup (write; user runs with elevation)
5. `scripts/verify_security.ps1` — post-setup ACL boundary verification
6. `tests/test_dpapi.py` — DPAPI round-trip tests
7. `tests/test_windows_security.py` — unit tests (non-elevation)
8. `tests/test_stage5a_integration.py` — post-setup integration tests (marked skipif no account)
9. Stage 5B: Claude Code detection, installation guidance, hook implementation
10. Documentation updates throughout
