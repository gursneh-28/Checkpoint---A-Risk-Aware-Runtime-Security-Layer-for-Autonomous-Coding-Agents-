# Checkpoint Known Limitations
**Assessed against v2.3 specification · 2026-11-21**

---

## 1. Claude Code Not Found in PATH

**Severity: CRITICAL — Blocks Phase 0**

`claude` is not in PATH and `C:\Program Files\ClaudeCode\` does not exist. The folders `%LOCALAPPDATA%\Claude-3p` and `%LOCALAPPDATA%\Claude Nest-3p` exist but are access-denied in the current environment. No `claude --version` can be run.

**Consequence:** 
- Cannot verify minimum version (v2.1.295 required for `onFailure: block`)
- Cannot capture real hook payload fixtures
- Cannot register hooks in managed settings
- Cannot test fail-closed behavior
- Cannot claim any live Claude Code integration

**Resolution:** Confirm whether Claude Code is installed and provide the path, or install it from https://claude.ai/download.

---

## 2. No Windows Service Account (`CheckpointSvc`)

**Severity: CRITICAL — Blocks Phase 0**

No dedicated `CheckpointSvc` local Windows account has been created. The Checkpoint service runs (conceptually) as the same user account as the Claude Code agent.

**Consequence:**
- No OS-account isolation between agent and Checkpoint service
- Agent can read Checkpoint secrets, database, and backup data
- DPAPI CurrentUser encryption cannot be scoped to a separate account
- CRITICAL approvals must remain disabled (per spec: "Require separate-account isolation for CRITICAL approvals; until it is configured and tested, disable CRITICAL approval")
- The spec explicitly states: "A local service running under the same Windows account as the agent is not a strong security boundary"

**Resolution:** Create `CheckpointSvc` with administrator rights, configure service ACLs. Requires explicit approval (see IMPLEMENTATION_LOG.md).

---

## 3. No DPAPI Encryption on Stored Data

**Severity: HIGH — Blocks Phase 0**

Backup blobs, stored action data, and sensitive records are stored in plaintext SQLite and plain files. The spec requires Windows DPAPI `CurrentUser` encryption under the dedicated service account.

**Consequence:**
- Any process with file system access can read all stored data
- Cannot claim security for backup storage
- Cannot implement the specified encryption until CheckpointSvc account exists

**Resolution:** Implement after CheckpointSvc account is created and functional.

---

## 4. Journal is SQLite (Not Create-Only Drop Folder)

**Severity: HIGH — Blocks Phase 0**

The spec requires a create-only journal drop folder: the agent account creates files but cannot list, read, modify, rename, or delete them. Currently, the journal is part of the main SQLite database, which the agent account can read and modify.

**Consequence:**
- An agent can delete or modify journal entries
- Chain integrity checks have no enforcement mechanism
- "Record first, then answer" guarantee is not met

**Resolution:** Requires Windows ACL setup on a dedicated folder. Blocked until CheckpointSvc account exists.

---

## 5. No Real Hook Client Executable

**Severity: HIGH — Blocks Phase 1**

There is no script or binary that Claude Code can invoke as a hook. `pipeline.py`'s `evaluate()` function is the right architecture but needs a thin wrapper (a shell script or compiled executable) that:
- Reads the hook JSON from stdin/environment
- Sends it to the Checkpoint service
- Returns the decision as JSON to stdout with the correct exit code
- Handles `onFailure: block` correctly

**Consequence:**
- No live interception of Claude Code actions
- No test of fail-closed behavior
- Cannot register hooks in Claude Code settings

---

## 6. No Dashboard Authentication

**Severity: HIGH — Blocks Phase 1**

The dashboard currently has no login. Any process on localhost can approve MEDIUM, HIGH, or CRITICAL actions. The spec requires Argon2id password hashing, authenticated sessions, HttpOnly/SameSite cookies, session expiry, logout, and rate limits.

**Consequence:**
- An agent running automated browser interactions could approve its own HIGH or CRITICAL actions
- "Typed YES is not proof of human presence" (spec) — CRITICAL approvals are meaningless
- CSRF protection exists but is not meaningful without authentication

**Missing packages:** `argon2-cffi` not in venv.

---

## 7. No Approval Binding

**Severity: HIGH — Blocks Phase 1**

Approvals are not cryptographically bound to the specific action parameters shown. The spec requires binding to: action ID, command hash, tool input hash, cwd, shell profile hash, parser/rule versions, preview hash, impact-manifest hash, backup-plan hash, alternative hash, effective tier, policy version, user session, expiry, and a single-use nonce.

**Consequence:**
- An approval for one action could theoretically be replayed or reused for a different action
- No staleness detection (command change, cwd change, etc.)
- Double-click and concurrent-tab races not cryptographically prevented

---

## 8. Trash Suggestion Broken (2 Test Failures)

**Severity: MEDIUM — Existing Bug**

`suggestions.py` returns `None` for `rm` commands instead of a trash suggestion. Tests `test_rm_suggests_trash_with_paths` and `test_rm_recursive_force_still_suggests_trash_for_the_path` both fail with `TypeError: 'NoneType' object is not subscriptable`.

**Root cause:** To be investigated — likely a code change in `suggestions.py` that broke the matching logic.

---

## 9. No bashlex Parser — Classifier Uses Regex

**Severity: MEDIUM — Phase 0 Requirement**

The spec requires a Bash parser adapter using `bashlex` (approved for private/local research use with GPL-3.0 notice preserved). Currently, the classifier uses regex string matching, which cannot correctly handle:
- Nested parentheses and subshells
- Complex quoting and escaping
- Arithmetic expansion `$(( ))`
- Here-documents
- Complex parameter expansions `${var##pattern}`
- Arrays

**Missing package:** `bashlex` not in venv.

**Risk:** A maliciously crafted command could bypass regex rules by using valid Bash syntax that the regex misparses.

---

## 10. Git Backup Root Path Incorrect

**Severity: LOW — Code Bug**

`git_safety.py` uses `%APPDATA%\Checkpoint\git-backups\` but the spec specifies `%LOCALAPPDATA%\Checkpoint\git-backups\` under the dedicated service account.

**Fix:** Change `os.environ.get("APPDATA", ...)` to `os.environ.get("LOCALAPPDATA", ...)`.

---

## 11. Confirmation.py Conflicts with Pipeline.py

**Severity: MEDIUM — Architecture Issue**

The old `confirmation.py` runs commands directly (via `subprocess`) and uses a terminal prompt for MEDIUM/HIGH decisions. The new `pipeline.py` correctly separates decide from execute and uses the dashboard. The old `confirmation.py` still exists and is imported by `interceptor.py`. Three tests in `test_confirmation.py` fail because the new flow has changed how the confirmation gate works.

**Consequence:** The old "run commands" path in `interceptor.py` and `confirmation.py` must not be confused with the new pipeline. The old code should be clearly marked as a demo/legacy path and not used for real enforcement.

---

## 12. Same-User Deployment Security Limitation

**Severity: HIGH — Fundamental (By Design Until Phase 0 Complete)**

As acknowledged in the spec: "A local service running under the same Windows account as the agent is not a strong security boundary: the agent may be able to read secrets, alter files, automate the dashboard, or reach the service."

Until `CheckpointSvc` is created and ACLs are configured:
- All security boundaries are advisory only
- An agent with browser automation could interact with the dashboard
- An agent could read/modify the SQLite database
- Classifier rules are defense-in-depth, not a security boundary

**This is an explicitly documented limitation in the spec, not a bug.** It becomes a resolved limitation once Phase 0 account isolation is proven.

---

## 13. 4 Test Failures in XPASS Category

Tests marked `xfail(strict=True)` that now unexpectedly pass indicate that the code improved and the test expectations are stale. These need to be updated to `xfail(strict=False)` or promoted to regular `assert` tests.

Affected:
- `test_known_model_gaps[classify_risk-args0-not LOW]` — XPASS
- `test_known_model_gaps[classify_risk-args1-HIGH]` — XPASS
- `test_known_model_gaps[classify_git_op-args2-HIGH]` — XPASS
- `test_known_model_gaps[classify_git_op-args3-HIGH]` — XPASS
- `test_known_rule_gaps[classify_git_op-args0-MEDIUM]` — XPASS(strict) → FAIL
- `test_known_rule_gaps[classify_file_op-args3-HIGH]` — XPASS(strict) → FAIL

---

## 14. No Frozen Labelled Test Set for Classifier

**Severity: MEDIUM — Dataset Quality**

The spec requires a hand-labelled frozen test set of ~1,000 examples, split by repository (not individual commands), with no overlap with training data. The current dataset (`commands_final.csv`) does not have:
- Repository-level train/val/test splits
- A frozen, separately stored test set
- Parser compatibility labels
- Near-duplicate review records
- Source/licence review records

---

## 15. Git Bash Version Capture Limitation in Sandbox

**Severity: LOW — Environment Note**

Running `bash --version` via `subprocess` in the sandbox fails with `NtCreateDirectoryObject` error. This is a sandbox isolation artifact. Git Bash 2.47 is confirmed installed; version capture should work correctly when run directly by Claude Code hooks or outside the sandbox.

---

## 16. Secret Key Regenerated on Dashboard Restart

**Severity: MEDIUM — Security Gap**

`dashboard/app.py` generates a new `SECRET_KEY` on every start. The spec requires the signing key to be persisted securely across restarts and rotated only through an explicit authenticated procedure. Currently, every restart invalidates all existing sessions and approval tokens.
