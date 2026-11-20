# Checkpoint Implementation Log
**Started: 2026-11-21**

---

## Session 2 — 2026-11-21: Phase 0 Independent Implementation & Test Suite Stabilization

### User Guidance Received
- Clarified that Claude Code / Claude AI is not installed on this host.
- Instructed to proceed with all Phase 0 work that can be completed independently.
- Prepared integration interfaces and automated tests using fixtures, clearly distinguished from live verification.
- Explicitly barred from claiming live hook, managed-settings, or failure-blocking verification until tested against real application.
- Kept v2.3 specification and Claude Code integration intact within product scope.

### Completed Work

1. **Test Suite Stabilization & Bug Resolution (14 Failures -> 0 Failures)**
   - **`storage/db.py` Schema Upgrade**: Restored backward-compatible column order (`id`, `timestamp`, `action_type`, `command`, `risk_tier`, `status`, `output`, `suggestion`, ...) while incorporating new v2.3 fields (`tool_use_id`, `session_id`, `base_tier`, `effective_tier`, `preview_hash`, `manifest_hash`, `backup_hash`, `policy_version`, `cwd`).
   - Fixed `test_confirmation.py` failures (3 tests) by ensuring `get_all_actions()` maps cleanly to expected legacy indices.
   - Fixed `test_dashboard.py::test_get_dashboard_contains_csrf_token` by handling legacy and upgraded action rows in `dashboard/app.py`.
   - Fixed `test_db_suggestions.py::test_old_database_without_suggestion_column_is_upgraded` by updating `_upgrade_schema` to detect and add missing columns.
   - Fixed `test_sandbox.py::test_rollback_checkpoint_creates_snapshot_and_logs` by correcting action logging fields.
   - Fixed `core/suggestions.py` (2 tests): `suggest_alternative` now returns clean path lists without failing when files do not yet exist on disk at parse time.
   - Fixed `core/risk_classifier.py` and `tests/test_risk_classifier.py`:
     - Added `/dev/` and device write redirection to `SYSTEM_REDIRECT_RE` to properly classify `> /dev/sda` as `HIGH`.
     - Added `env` command prefix unwrapping in `classify_by_rules`.
     - Updated `classify_file_op` to protect against path traversals (`..`) and sensitive filenames.
     - Promoted resolved rule gap tests to standard passing assertions.

2. **Committed Architectural Baseline to Git**
   - Successfully committed all 20 foundation files (`core/event_types.py`, `core/pipeline.py`, `core/policy_resolver.py`, `core/provenance.py`, `core/anomaly.py`, `core/preview.py`, `core/impact_report.py`, `core/git_safety.py`, `core/path_module.py`, and tracking docs).
   - Commit hash: `0dee0f3`.

3. **Installed Required Phase 0 Dependencies**
   - `bashlex` (0.18): Python Bash AST parser.
   - `argon2-cffi` (25.1.0): Password hashing for dashboard authentication.
   - `cryptography` (50.0.2): OS encryption and cryptographic tokens.
   - Updated `requirements.txt`.

4. **Implemented Bash Parser Adapter (`core/parser_adapter.py`)**
   - Created `BashParserAdapter` with `ParserCoverage` enum (`FULL`, `PARTIAL`, `UNSUPPORTED`, `UNKNOWN`).
   - Implemented AST visitation for pipelines, redirects, command substitutions, operators (`&&`, `||`, `;`, `|`), and compound commands.
   - Verified that unsupported constructs and command substitutions gracefully fallback to `PARTIAL` or `UNSUPPORTED`.
   - Preserved GPL-3.0-or-later notice per specification §4.
   - Created comprehensive tests in `tests/test_parser_adapter.py` (6 tests, all passing).

5. **Implemented Claude Code Hook Client Interface (`core/claude_code_adapter.py`)**
   - Implemented `ClaudeCodeHookAdapter` supporting `PreToolUse`, `PostToolUse`, and `PostToolUseFailure`.
   - Maps hook JSON to Checkpoint `Event` and formats `Decision` into official Claude Code `hookSpecificOutput`.
   - Returns exit code 0 for allowed actions and exit code 2 for denied / malformed payloads (fail-closed).
   - Added simulated official hook fixture files in `tests/fixtures/claude_code/`.
   - Created simulated tests in `tests/test_claude_code_adapter.py` (3 tests, all passing).

6. **Refined Anomaly Detector Time Rule (`core/anomaly.py`)**
   - Removed unconfigured local clock midnight check (which previously caused daytime/late-night tests to trigger false anomaly alerts) in accordance with Section 11 limits-only requirements.

7. **Authored Comprehensive Threat Model (`docs/threat_model.md`)**
   - Detailed 4 threat actors, trust boundaries, and 6 security vectors: same-user access, journal drop-folder integrity, dashboard authentication, hook failure fail-open risk, parser evasion, and quota exhaustion DoS.

### Current Test Suite Results
- **88 passed** (82 unit tests + 6 model expectation xpasses), **0 failed**.
- Test runtime: ~4.95 seconds.

### Next Steps (Phase 0 Continuation & Gate Readiness)
- For the Windows service account (`CheckpointSvc`) and ACL proof: await administrator elevation / approval if the user wishes to proceed with local OS isolation.
- Keep live Claude Code tests explicitly blocked until the application is installed.
