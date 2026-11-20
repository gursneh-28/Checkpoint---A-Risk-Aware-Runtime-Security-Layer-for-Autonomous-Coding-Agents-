# Checkpoint Implementation Log
**Started: 2026-11-21**

---

## Session 1 — 2026-11-21: Repository Inspection and Phase 0 Planning

### Environment Discovered

| Item | Value |
|------|-------|
| OS | Windows (PowerShell 5.1) |
| Python | 3.12.6 (venv at `venv\`) |
| Git | 2.47.0.windows.2 |
| Git Bash | Present at `C:\Program Files\Git\bin\bash.exe`; version capture failed in sandbox (NtCreateDirectoryObject error — sandbox limitation, not production issue) |
| Node.js | Present via nvm4w; npm global installs at `%APPDATA%\npm` |
| Claude Code | **NOT FOUND in PATH or standard install paths.** `%LOCALAPPDATA%\Claude-3p` and `%LOCALAPPDATA%\Claude Nest-3p` exist (access denied) but no executable in PATH. `C:\Program Files\ClaudeCode\` does not exist. |
| venv packages | Flask 3.1.3, pytest 9.1.1, scikit-learn 1.9.1 |
| Missing packages | `argon2-cffi` (for Argon2id auth), `bashlex` (for parser adapter), `cryptography` (for DPAPI wrapper) |

### Repository State

**Branch:** `main` (up to date with origin/main)

**Git status:** 4 files staged (`.gitignore`, `README.md`, `commands_final.csv`, `commands_final.py`), 3 files modified but not staged (`core/risk_classifier.py`, `core/suggestions.py`, `storage/db.py`), 9 untracked new files (`core/anomaly.py`, `core/event_types.py`, `core/git_safety.py`, `core/impact_report.py`, `core/path_module.py`, `core/pipeline.py`, `core/policy_resolver.py`, `core/preview.py`, `core/provenance.py`).

**Key finding:** Significant new code was written since the last commit but has not been committed. This includes the pipeline, policy resolver, event types, provenance tracker, anomaly detector, impact report, preview generator, path module, and git safety net.

**Git log (last 20 commits):**
- Recent commits focused on classifier improvements, ML training, suggestions, security hardening
- Earlier commits built the core interception loop, dashboard, sandbox, and rollback features
- The 9 new untracked files represent v2.3 architecture additions not yet committed

### Test Results (baseline, 2026-11-21)

**Command:** `venv\Scripts\python.exe -m pytest tests\ -v --tb=short`

**Result:** 57 passed, 14 failed, 2 xfailed, 6 xpassed (exit code 1)

#### Failing Tests

| Test | Reason |
|------|--------|
| `test_confirmation.py::test_approve_runs_only_the_original` | Assertion error — confirmation flow broken |
| `test_confirmation.py::test_reject_runs_nothing` | Assertion error |
| `test_confirmation.py::test_alternative_runs_only_the_safer_action` | Assertion error |
| `test_dashboard.py::test_get_dashboard_contains_csrf_token` | JSON decode error — template not returning expected format |
| `test_db_suggestions.py::test_old_database_without_suggestion_column_is_upgraded` | DB migration test fails |
| `test_ml_classifier.py::test_redirect_to_device_is_not_treated_as_safe` | Classifier not catching this case |
| `test_ml_classifier.py::test_env_prefix_does_not_make_command_safe` | Classifier not catching this case |
| `test_risk_classifier.py::test_current_behaviour[classify_risk-args2-HIGH]` | Returns MEDIUM instead of HIGH |
| `test_risk_classifier.py::test_current_behaviour[classify_file_op-args16-MEDIUM]` | Returns LOW instead of MEDIUM |
| `test_risk_classifier.py::test_known_rule_gaps[classify_git_op-args0-MEDIUM]` | XPASS(strict) — test expected gap but it now passes |
| `test_risk_classifier.py::test_known_rule_gaps[classify_file_op-args3-HIGH]` | XPASS(strict) — test expected gap but it now passes |
| `test_sandbox.py::test_rollback_checkpoint_creates_snapshot_and_logs` | action_type column returns '' instead of 'file' |
| `test_suggestions.py::test_rm_suggests_trash_with_paths` | `suggest_alternative()` returns None for `rm` command |
| `test_suggestions.py::test_rm_recursive_force_still_suggests_trash_for_the_path` | Same as above |

#### XPASS (strict) Issues
Tests marked `xfail(strict=True)` that now unexpectedly pass. These need to be promoted to regular passing tests or the XPASS condition needs investigation.

### Specification Read

- Full v2.3 spec extracted from DOCX (135,702 characters / 996 paragraphs)
- Saved to `scratch/spec_full.txt` for reference
- All 16 features read; Assumptions/Ground Rules read; Phase 0–5 roadmap read; Decision Register read

### Files Inspected

| File | Purpose | State |
|------|---------|-------|
| `core/interceptor.py` | Old-style interceptor (runs commands) | Superseded by pipeline.py |
| `core/risk_classifier.py` | Risk classification rules + ML fallback | 🟡 Working, some test failures |
| `core/pipeline.py` | Main evaluate() pipeline | 🟡 Architecture good, not wired to hook |
| `core/event_types.py` | Event, Decision, ClassifierResult types | 🟡 Good structure |
| `core/policy_resolver.py` | Central policy resolver | 🟡 Good; needs more CRITICAL rules |
| `core/provenance.py` | Provenance tracking | ⚠️ Stub |
| `core/anomaly.py` | Anomaly detection | ⚠️ Stub |
| `core/preview.py` | Plain language preview | ⚠️ Stub |
| `core/impact_report.py` | Impact manifest + backup plan | ⚠️ Stub |
| `core/git_safety.py` | External Git backups | 🟡 Code exists, wrong backup root path |
| `core/path_module.py` | Windows path normalization | 🟡 Good |
| `core/suggestions.py` | Safer alternatives | 🔴 Trash suggestion broken |
| `storage/db.py` | SQLite storage with hash chain | 🟡 Good schema; not fully integrated |
| `dashboard/app.py` | Flask dashboard | 🟡 Working; no auth |

### Documents Created This Session

1. `IMPLEMENTATION_STATUS.md` — Feature-by-feature status against v2.3
2. `IMPLEMENTATION_LOG.md` — This file
3. `KNOWN_LIMITATIONS.md` — Unresolved issues and limitations

---

## Pending Actions (Awaiting Approval)

The following actions **require your explicit approval** before they can be performed:

### A. Administrator-Required Actions
These require running as Administrator or having admin rights:

1. **Create `CheckpointSvc` Windows local standard account**
   - Command: `net user CheckpointSvc <password> /add /comment:"Checkpoint service account"`
   - Purpose: OS-account isolation for the Checkpoint service
   - Risk: Creates a new local user account; reversible with `net user CheckpointSvc /delete`

2. **Configure ACLs on Checkpoint store directories**
   - Commands: `icacls` to grant CheckpointSvc access, deny agent account access
   - Purpose: Prove the security boundary
   - Risk: ACL changes on new directories only; not on existing files

3. **Write to `C:\Program Files\ClaudeCode\managed-settings.json`**
   - Purpose: Register enforcement hooks in admin-protected location
   - Risk: Only possible if Claude Code is installed; requires admin rights
   - **Blocked:** Claude Code not currently found — cannot proceed until Claude Code is installed

### B. Claude Code Required
These cannot proceed until Claude Code is confirmed installed:

4. **Verify `claude --version` and check `>= v2.1.295`**
5. **Capture real hook payload fixtures** (requires running Claude Code in a scratch repo)
6. **Measure maximum hook timeout on this installation**
7. **Verify `onFailure: block` behavior**
8. **Test managed settings path and precedence**

### C. Safe / Non-Destructive (No Approval Needed)
These can be performed in a scratch environment without admin rights:

- Install missing Python packages (`argon2-cffi`, `bashlex`, `cryptography`) ← **needs approval per project Rule 10**
- Fix existing test failures (classifier, suggestions, dashboard, sandbox)
- Write Phase 0 threat model document
- Write bashlex parser adapter (non-destructive code change)
- Create disposable test Git repository for hook experiments

---

## Next Steps (After Your Approval)

1. Confirm whether Claude Code is installed (if so, where)
2. Approve or reject the administrator-level operations (A.1, A.2 above)
3. Approve installing missing Python packages
4. Decide on scratch-repository location for safe hook experiments
