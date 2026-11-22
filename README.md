# Checkpoint
**A Risk-Aware Runtime Security Layer for Autonomous Coding Agents**

Checkpoint is an independent runtime security layer designed to intercept tool, file, shell, and git operations from autonomous coding agents (such as Claude Code). It classifies each proposed operation by risk tier, permits verified safe operations to proceed via a fast path, and halts risky or destructive actions before execution to present simulated impact previews and safer alternatives for human approval.

---

## Current Project Status

- **Development Stage:** Application Feature Implementation Complete (Milestones 1, 2, 3, and 4 Complete).
- **Test Suite Status:** **154 tests passing (148 passed, 6 xpassed, 0 failed)** across all unit, classification, storage, version control, audit journal, git safety, preview, impact, anomaly, feedback, alert, and export tests.
- **Current Completed Baseline:** Milestones 1, 2, 3, & 4 (**Storage, Recovery, Previews, Impact, Safeguards, Anomaly Circuit Breaker, Operational Dashboard, Feedback, Alerts, and Audit Export**) are fully implemented and tested.
- **Next Milestone Task:** Milestone 5 (**Host-Level Security Integration & Live Agent Verification**).

### What is Implemented vs. Simulated vs. Deferred

| Component | Status | Details |
|---|---|---|
| **Risk Classification & AST Parsing** | ✅ Genuinely Implemented | Rules-first pipeline, ML model fallback, and `bashlex` AST parser adapter (`core/parser_adapter.py`) with support matrix coverage categories. |
| **Blob Store & Version Control (Task 1.1)** | ✅ Genuinely Implemented | SHA-256 sharded compressed blob store (`core/blob_store.py`), 50 MB file limit, conflict detection, staged restore, Option A 2 GB shared quota accounting, and 30-day retention with pin protection (`core/version_control.py`). |
| **Durable Audit Journal (Task 1.2)** | ✅ Genuinely Implemented | Write-ahead drop-folder ingestion (`storage/journal.py`), append-only global hash chain, sequence buffering, late event absorption, acyclic tombstone redaction, and chain-head anchoring. |
| **Git Safety Net (Task 1.3)** | ✅ Genuinely Implemented | Bare external backups (`core/git_safety.py`), staged/unstaged patches, untracked files, full bundle verification, destructive command coverage matrix, and safe environment isolation. |
| **Previews & Impact Analysis (Milestone 2)** | ✅ Genuinely Implemented | Blast radius modeling, deterministic `preview_hash`, target state fingerprint validation, composite safety scoring (0-100), and typed "YES" confirmation gate for CRITICAL actions. |
| **Anomaly Circuit Breaker (Milestone 3)** | ✅ Genuinely Implemented | High-risk burst detection ($\ge 5$ in 60s), repeated rejection trip ($\ge 3$), low quota breaker (< 5%), and unconditional "paused means paused" pipeline blocking. |
| **Feedback & Wrong-Rating Queue (Milestone 4)** | ✅ Genuinely Implemented | User flagging, review queue, journaled reviews, calibration dataset export, and immutable historical decisions (`storage/db.py`, `dashboard/app.py`). |
| **Alerts & Notifications (Milestone 4)** | ✅ Genuinely Implemented | Standardized webhook payload formatting, rate-limited desktop notifications (3.0s minimum interval), and DB delivery tracking (`core/alerts.py`). |
| **Session Summaries & Audit Export (Milestone 4)** | ✅ Genuinely Implemented | Multi-metric session summaries (JSON and Markdown), and universal audit log export with strict CSV Formula Injection defense (CWE-1236) (`core/session_summary.py`, `storage/export.py`). |
| **Safer Alternatives & Trash** | ✅ Genuinely Implemented | Safer command rewriting (e.g. `git push --force` → `--force-with-lease`, `git reset --hard` → `git stash`, recoverable soft delete to trash). |
| **Confirmation Gate & Operational Dashboard** | ✅ Genuinely Implemented | CSRF-protected Flask dashboard, idempotent action decision state transitions (Approve / Reject / Alternative), flags queue, alerts, session summaries, and export routes. |
| **Claude Code Interceptor Hooks** | ⚠️ Simulated / Contract Ready | Contract adapter implemented (`core/claude_code_adapter.py`) and verified against official Claude Code hook JSON fixtures. Live interception is **blocked/deferred** awaiting Claude Code installation on this host. |
| **Host-Level OS Account & ACL Isolation** | ⚠️ Deliberately Deferred | `CheckpointSvc` Windows service account, NTFS ACL isolation, and DPAPI service-profile encryption are deferred to the final Security Integration phase to prioritize complete application functionality first. |

---

## v2.3 Specification — 16-Feature Checklist

Status definitions:
- ✅ **DONE**: Fully implemented, tested, and passing according to v2.3 specification.
- 🟡 **PARTIAL**: Partially implemented, foundational code or test scaffolding exists.
- ⏳ **PENDING**: Scheduled for upcoming milestone.
- ⚠️ **SIMULATED / DEFERRED**: Implemented using simulated contracts or deliberately postponed to the security integration phase.

| # | Feature | Status | Implementation Details & Progress |
|---|---|:---:|---|
| **1** | **Interceptor and Real Agent Connection** | 🟡 PARTIAL / ⚠️ SIMULATED | `core/claude_code_adapter.py` implements PreToolUse/PostToolUse protocol, fail-closed handling (`onFailure: block`), and `updatedInput` replacement. Verified via simulated fixtures. Live hook connection deferred until Claude Code is installed. |
| **2** | **Risk Classifier** | ✅ DONE | Hard rules authoritative, ML fallback (never predicts LOW), chained command splitting, `.env` secret file protection, exact protected branch matching, and AST parser adapter (`core/parser_adapter.py`). 100% golden tests passing. |
| **3** | **Fast-Path Execution (Instant Run)** | ✅ DONE | Fast-path routing implemented in `core/pipeline.py` for rule-proven LOW actions with synchronous durable journal write. "Paused means paused" circuit-breaker stops even fast-path actions. |
| **4** | **Safer Alternatives ("Do this instead")** | ✅ DONE | `core/suggestions.py` maps destructive commands to safer equivalents (`--force-with-lease`, `git stash`, soft-delete to trash with deduplicated collision handling). |
| **5** | **Human Confirmation Gate** | ✅ DONE | `core/confirmation.py` & `dashboard/app.py`: Pause on MEDIUM/HIGH/CRITICAL tiers, CSRF tokens on all POST endpoints, idempotent single-use decisions, typed "YES" confirmation requirement for CRITICAL, plain-outcome display. |
| **6** | **Action Lifecycle & State Machine** | ✅ DONE | `core/event_types.py` models full lifecycle states (`received` → `classified` → `pending` → `approved` → `backing_up` → `backup_verified` → `execution_authorized` → `executed`/`failed`/`rejected`/`outcome_unknown`). Transition enforcement is integrated into pipeline. |
| **7** | **File History & Version Control** | ✅ DONE | `core/blob_store.py` & `core/version_control.py`: SHA-256 sharded compressed store, 50 MB per-file limit, conflict-aware staged atomic restore, Option A 2 GB shared quota accounting, 30-day retention, pin protection. (Completed in Milestone 1, Task 1.1). |
| **8** | **Full Action Log & Durable Journal** | ✅ DONE | `storage/journal.py`: Durable drop-folder ingestion (.tmp -> .journal) with fsync, append-only global hash chain, out-of-order buffering, late arrival absorption, acyclic tombstone redaction, and atomic external chain-head anchoring. |
| **9** | **Explicit High-Risk Typed Approvals** | ✅ DONE | `core/policy_resolver.py` & `storage/db.py`: CRITICAL tier policy classification (privilege elevation, download/pipe sh, disk formatting, .git deletion, protected branch force-push), mandatory exact typed "YES" confirmation, unskippable hard-denies. |
| **10** | **Sandbox & Dry-Run Preview** | ✅ DONE | `core/preview.py`: Plain-language preview generation, deterministic SHA-256 `preview_hash`, blast radius modeling, and target state fingerprint verification detecting shifted filesystem states. |
| **11** | **Impact Analysis & Safety Score** | ✅ DONE | `core/impact_report.py`: Predicted effects manifest, target sensitivity, and composite `compute_safety_score()` (0 to 100) evaluating reversibility, scope boundedness, and predictability. |
| **12** | **Anomaly Detection & Circuit Breaker** | ✅ DONE | `core/anomaly.py`: High-risk burst detection ($\ge 5$ in 60s), repeated rejection trip ($\ge 3$), low quota breaker (< 5%), and session-level "paused means paused" pipeline blocking. |
| **13** | **Git Safety Net** | ✅ DONE | `core/git_safety.py`: Bare external backup store under `%LOCALAPPDATA%\Checkpoint\git-backups\`, separate staged/unstaged patches and untracked files, verified git bundle (--all), destructive command coverage matrix, hard-deny for gc/prune, and conflict-aware restore engine. |
| **14** | **Feedback & Wrong-Rating Queue** | ✅ DONE | `storage/db.py` & `dashboard/app.py`: Flagging mechanism, review queue API, resolution tracking, calibration dataset export, and immutable historical decisions. |
| **15** | **Alerts & Notifications** | ✅ DONE | `core/alerts.py`: Standardized webhook formatting, rate-limited desktop notifications (3s interval), multi-channel delivery dispatch, and status tracking in `alerts` table. |
| **16** | **Session Summaries, Audit Export & Dashboard** | ✅ DONE | `core/session_summary.py` & `storage/export.py`: Multi-metric session summaries (JSON and Markdown), audit export with strict CSV Formula Injection defense (CWE-1236), and expanded dashboard endpoints. |

---

## Milestone Roadmap & Progress

- [x] **Milestone 1: Storage, Retention & Recovery**
  - [x] **Task 1.1:** Content-Addressed Blob Store & File History / Version Control (`core/blob_store.py`, `core/version_control.py`) — **COMPLETED & TESTED**
  - [x] **Task 1.2:** Durable Journal Ingestion & Audit Engine (`storage/journal.py`) — **COMPLETED & TESTED**
  - [x] **Task 1.3:** Git Safety Net & Bare Backup Store (`core/git_safety.py`) — **COMPLETED & TESTED**
- [x] **Milestone 2: Previews, Impact Analysis & Approval Safeguards** (Features 5, 9, 10, 11) — **COMPLETED & TESTED**
- [x] **Milestone 3: Intelligent Runtime Safety & Anomaly Detection** (Feature 12) — **COMPLETED & TESTED**
- [x] **Milestone 4: Operational Dashboard, Provenance, Feedback & Export** (Features 14, 15, 16) — **COMPLETED & TESTED**
- [ ] **Milestone 5: Host-Level Security Integration & Live Agent Verification** (Phase 0 / Phase 1 OS boundaries and Claude Code installation)

---

## Project Structure

```
checkpoint/
├── core/
│   ├── alerts.py              # Webhook formatting, desktop rate-limiting & alert delivery
│   ├── anomaly.py             # Rule-based anomaly detection & circuit breaker
│   ├── blob_store.py          # SHA-256 sharded compressed blob store (50 MB cap)
│   ├── claude_code_adapter.py # Claude Code hook client contract & JSON serialization
│   ├── confirmation.py        # Confirmation gate for interactive approval
│   ├── event_types.py         # Shared Event, Decision, RiskTier, and state data contracts
│   ├── file_ops.py            # Intercepted file operations
│   ├── git_safety.py          # Git safety net & backup operations
│   ├── impact_report.py       # Impact analysis and blast radius modeling
│   ├── interceptor.py         # Shell/command interception pipeline
│   ├── ml_classifier.py       # Fallback machine learning classifier
│   ├── ml_dataset.py          # Dataset generator for training
│   ├── ml_train.py            # Classifier training script
│   ├── parser_adapter.py      # bashlex Bash AST parser adapter
│   ├── path_module.py         # Cross-platform path handling (Windows, Git Bash, UNC)
│   ├── pipeline.py            # End-to-end evaluation & fast-path pipeline
│   ├── policy_resolver.py     # Hierarchical policy resolution engine
│   ├── preview.py             # Shadow-copy diff & preview generator
│   ├── provenance.py          # Origin tracking for prompt-injection defense
│   ├── risk_classifier.py     # Deterministic rules-first risk classification
│   ├── sandbox.py             # Staged dry-run execution & diffing
│   ├── session_summary.py     # Multi-metric session summaries & Markdown reports
│   ├── suggestions.py         # Safer alternative command suggestions & trash
│   └── version_control.py     # Snapshotting, staged restore, conflict detection, Option A quota
├── dashboard/
│   ├── app.py                 # Flask web dashboard with CSRF protection, flags, summaries, exports
│   └── templates/             # Dashboard HTML views
├── docs/
│   ├── Checkpoint_Synopsis.docx
│   └── threat_model.md        # Comprehensive 6-vector threat model
├── storage/
│   ├── checkpoint.db          # SQLite audit, actions, versions, and blob tracking database
│   ├── db.py                  # Database access layer and schema management
│   ├── export.py              # Universal audit export (JSON & CSV with formula injection defense)
│   ├── journal.py             # (Task 1.2) Durable journal ingestion & audit engine
│   └── trash/                 # Soft-delete recoverable trash directory
├── tests/
│   ├── fixtures/claude_code/  # Official Claude Code hook JSON payloads for testing
│   ├── test_blob_store.py     # Tests for content-addressed blob store
│   ├── test_claude_code_adapter.py # Tests for hook adapter contracts
│   ├── test_confirmation.py   # Tests for confirmation gate
│   ├── test_dashboard.py      # Tests for web dashboard
│   ├── test_db.py             # Tests for database operations
│   ├── test_db_suggestions.py # Tests for suggestion persistence
│   ├── test_git_safety.py     # Tests for git safety net & external backup store
│   ├── test_journal.py        # Tests for durable audit journal & hash chain
│   ├── test_milestone2.py     # Tests for previews, impact, blast radius & typed approvals
│   ├── test_milestone3.py     # Tests for anomaly circuit breakers & pause enforcement
│   ├── test_milestone4.py     # Tests for feedback queue, alerts, summaries & export
│   ├── test_ml_classifier.py  # Tests for ML fallback classifier
│   ├── test_parser_adapter.py # Tests for bashlex AST parsing
│   ├── test_risk_classifier.py# Golden table risk classification tests
│   ├── test_sandbox.py        # Tests for shadow-copying and diffs
│   ├── test_suggestions.py    # Tests for safer alternatives and trash
│   └── test_version_control.py# Tests for file history, restore, and Option A quota
├── IMPLEMENTATION_LOG.md      # Detailed session log of changes
├── IMPLEMENTATION_STATUS.md   # Feature-by-feature verification status
├── KNOWN_LIMITATIONS.md       # Documented system limits and deferred items
├── requirements.txt           # Python dependencies
└── README.md
```

---

## Running Tests

All unit and integration tests run within isolated temporary test fixtures (`tmp_path`) and do not modify host configuration or project files:

```bash
venv\Scripts\python.exe -m pytest tests/ -v
```
