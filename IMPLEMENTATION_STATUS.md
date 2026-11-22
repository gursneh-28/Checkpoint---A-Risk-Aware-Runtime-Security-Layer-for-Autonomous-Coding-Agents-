# Checkpoint Implementation Status
**Against v2.3 Specification · Updated 2026-11-21**

> [!IMPORTANT]
> Status is assessed by code inspection and test results, NOT by feature headings or README claims.
> A feature is **not complete** unless its implementation, tests, and failure behavior are verified.
> Requirements depending on Claude Code are explicitly marked **BLOCKED (Claude Code not installed)**.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ DONE | Implemented, tested, passing |
| 🟡 PARTIAL | Code exists but incomplete, broken tests, or missing security requirements |
| ❌ MISSING | Not implemented |
| 🔴 BROKEN | Implemented but tests failing or security boundary violated |
| ⚠️ SIMULATED / STUB | Prepared interface or mock/fixture — not live verified |

---

## Phase 0 — Compatibility and Security Proof

| Check | Status | Notes |
|-------|--------|-------|
| Claude Code version recorded | ⚠️ BLOCKED | Claude Code not installed on development host |
| `onFailure: block` verified on installed version | ⚠️ BLOCKED | Awaiting Claude Code installation |
| Hook schema fixtures captured | ⚠️ SIMULATED | Fixtures created from official docs (`tests/fixtures/claude_code/*.json`) |
| Managed settings path verified (`C:\Program Files\ClaudeCode\managed-settings.json`) | ⚠️ BLOCKED | Awaiting Claude Code installation |
| Managed settings write-protected from agent account | ⚠️ BLOCKED | Awaiting Claude Code installation |
| `CheckpointSvc` Windows service account created | ⚠️ BLOCKED | Requires manual Windows administrator approval |
| ACL isolation proven (agent cannot read/write Checkpoint store) | ⚠️ BLOCKED | Awaiting `CheckpointSvc` account creation |
| Scoped service account project access | ⚠️ BLOCKED | Awaiting `CheckpointSvc` account creation |
| Journal drop-folder create-only permissions | ⚠️ BLOCKED | Awaiting `CheckpointSvc` account creation |
| DPAPI CurrentUser encryption configured | ⚠️ BLOCKED | Awaiting `CheckpointSvc` account profile |
| DPAPI protect/unprotect round-trip tested | ⚠️ BLOCKED | Awaiting `CheckpointSvc` account profile |
| Git Bash version and grammar documented | ✅ DONE | Git Bash 2.47.0 installed |
| bashlex parser adapter implemented | ✅ DONE | `core/parser_adapter.py` created with AST visitors |
| bashlex GPL-3.0 notice preserved | ✅ DONE | Preserved in docstring per spec §4 and Decision Register 2 |
| Threat model written | ✅ DONE | `docs/threat_model.md` covering all 6 threat vectors |
| Hook timeout measured | ⚠️ BLOCKED | Awaiting Claude Code installation |
| Blocking-wait vs retry-after-approval decision | ⚠️ BLOCKED | Awaiting Claude Code timeout measurement |
| `statusMessage` behavior verified | ⚠️ BLOCKED | Awaiting Claude Code installation |
| Claude Code permission rule coverage verified | ⚠️ BLOCKED | Awaiting Claude Code installation |

**Phase 0 Gate: 🟡 IN PROGRESS (All independent work complete; system account and Claude Code live checks blocked)**

---

## Feature 1 — Interceptor and Real Agent Connection

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Event and Decision types | ✅ DONE | `core/event_types.py` (Event, Decision, ClassifierResult) |
| Claude Code adapter (hook JSON → Event → reply JSON) | ⚠️ SIMULATED | `core/claude_code_adapter.py` implemented and verified against fixtures |
| Hook client (thin binary/script) | ⚠️ SIMULATED | Command-line runnable entry point in `core/claude_code_adapter.py` |
| `onFailure: block` configured | ⚠️ BLOCKED | Awaiting Claude Code installation |
| PreToolUse enforcement hook | ⚠️ SIMULATED | Simulated in `tests/test_claude_code_adapter.py` |
| PostToolUse / PostToolUseFailure hooks | ⚠️ SIMULATED | Fixtures and schema prepared |
| `updatedInput` full-object replacement | ✅ DONE | Implemented in `Decision.to_hook_reply()` |
| Durable journal write before decision | ✅ DONE | `storage/db.py` logs event hash chain |
| Session idempotency (tool_use_id dedup) | ✅ DONE | Verified in `log_pending_action` |
| Local fast path (rule-proven LOW with journal write) | ✅ DONE | `core/pipeline.py` auto-authorizes LOW after synchronous journal write |
| Fail-closed on malformed JSON | ✅ DONE | Returns exit code 2 and deny |
| Fail-closed on unsupported tool | ✅ DONE | Returns exit code 2 and deny |

---

## Feature 2 — Risk Classifier

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Rules-first pipeline | ✅ DONE | Hard rules authoritative, ML fallback |
| ML model never produces LOW | ✅ DONE | Enforced in `classify_risk_full()` |
| Chained command splitting | ✅ DONE | Part-by-part with highest tier resolution |
| Secret file detection → MEDIUM min | ✅ DONE | `.env`, credentials, SSH keys |
| Protected branch exact match (not substring) | ✅ DONE | `PROTECTED_BRANCHES` exact match |
| `git push --force-with-lease` classification by branch | ✅ DONE | Target and branch policy verified |
| Windows path handling via path_module | ✅ DONE | `path_module.py` handles Windows, Git Bash, UNC |
| `git clean`, `curl\|bash`, `docker prune`, `mv/cp` rules | ✅ DONE | Verified |
| `classify_risk_full()` returns ClassifierResult | ✅ DONE | Verified |
| Bash AST parser (bashlex) | ✅ DONE | `BashParserAdapter` wraps AST |
| Parser adapter with support matrix | ✅ DONE | Coverage categories: FULL, PARTIAL, UNSUPPORTED, UNKNOWN |
| Golden test table | ✅ DONE | 100% passing across `test_risk_classifier.py` and `test_ml_classifier.py` |

---

## Feature 7 — File History & Version Control

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Content-addressed blob store | ✅ DONE | `core/blob_store.py`: SHA-256 sharded store, atomic writes via temp file + replace |
| 50 MB single file cap | ✅ DONE | Enforced in `core/blob_store.py` (`FileTooLargeError`) |
| zlib blob compression & decompression | ✅ DONE | Verified integrity on write/read with fallback handling |
| Version control engine | ✅ DONE | `core/version_control.py`: snapshot_file, snapshot_directory |
| Explicit file state tracking | ✅ DONE | Tracks `file`, `symlink`, and `deleted` states |
| Path traversal protection | ✅ DONE | Validates paths remain strictly within `workspace_root` |
| Exclude regenerable dependencies | ✅ DONE | Excludes `node_modules`, `.venv`, `__pycache__`, etc. |
| Conflict-aware restore | ✅ DONE | Compares current hash & mtime before restore; blocks if modified unless force=True |
| Staged restore & recovery journal | ✅ DONE | `restore_journal` table tracks staged, verified, and reversed restore attempts |
| Option A Quota (2 GB shared) | ✅ DONE | Tracks blob bytes, logical trash bytes, and external git backup bytes |
| Option A Strict Reclamation Order | ✅ DONE | Reclaims expired trash (>30 days) first, then expired unpinned snapshots (>30 days) |
| Pinning immunity | ✅ DONE | Pinned versions in `pins` table are never purged by automated reclamation |

---

## Feature 8 — Full Action Log & Durable Journal

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Durable journal drop-folder | ✅ DONE | `storage/journal.py`: Atomic write (.tmp -> .journal) with fsync |
| Append-only event store | ✅ DONE | SQLite triggers block DELETE and modification of cryptographic fields |
| Canonical event hashing ("1") | ✅ DONE | Deterministic SHA-256 hash binding all security-relevant fields |
| Ingestion & sequence buffering | ✅ DONE | Grace period buffers out-of-order files; unblocking missing sequences |
| Gap detection & session pause | ✅ DONE | Gap timeout pauses session; logs `session_sequence_gap` event |
| Late arrival absorption | ✅ DONE | Late events absorbed at chain tail preserving session sequence; explicit resume required |
| Acyclic tombstone redaction | ✅ DONE | Directional tombstone events, scrubbed payloads, verifiable hash continuity |
| Chain-head anchoring & reconciliation | ✅ DONE | `ChainHeadAnchor` interface with atomic `FileChainHeadAnchor` & rollback detection |
| Query read API with pagination | ✅ DONE | `query_events()` supports filters (session, action, event_type, date, pagination) |

---

## Feature 13 — Git Safety Net

| Sub-feature | Status | Notes |
|------------|--------|-------|
| External bare backup store | ✅ DONE | Stored outside project under `%LOCALAPPDATA%\Checkpoint\git-backups\` |
| Separate staged/unstaged snapshots | ✅ DONE | `core/git_safety.py`: Separate staged patch, unstaged patch, and untracked files |
| Verified git bundle (--all) | ✅ DONE | Full ref bundle created and verified via `git bundle verify` |
| Controlled Git environment | ✅ DONE | Safe env overrides hostile hooks, pagers, prompts, and external diffs |
| Coverage matrix validation | ✅ DONE | Blocks destructive operations if required coverage categories are absent |
| Hard-deny commands in v1 | ✅ DONE | `git gc --prune` and `git reflog expire` unconditionally blocked |
| Stale snapshot blocking | ✅ DONE | Snapshots older than 300s are rejected for destructive commands |
| Conflict-aware restore engine | ✅ DONE | Checks active uncommitted modifications before restoring patches and untracked files |
| Shared quota accounting | ✅ DONE | External git backup bytes count toward Option A 2 GB quota |

---

## Feature 9 — Explicit High-Risk Typed Approvals

| Sub-feature | Status | Notes |
|------------|--------|-------|
| CRITICAL tier policy classification | ✅ DONE | `core/policy_resolver.py`: Privilege elevation, download/sh, disk formatting, .git removal, protected branch force-push |
| Typed "YES" confirmation gate | ✅ DONE | `storage/db.py`: `decide_action()` enforces exact string "YES" (rejects lowercase "yes" or blank) |
| Hard-deny non-overrideable | ✅ DONE | Hard-deny conditions cannot be approved even by typing "YES" |

---

## Feature 10 — Sandbox & Dry-Run Preview

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Plain-language preview generation | ✅ DONE | `core/preview.py`: Human-readable summary of what will happen |
| Deterministic preview_hash | ✅ DONE | SHA-256 binding headline, details, effects, and blast radius |
| Blast radius modeling | ✅ DONE | Computes affected files, estimated bytes, and reversibility rating |
| Target state fingerprint check | ✅ DONE | `verify_preview_fingerprints()` detects on-disk shifts before execution |

---

## Feature 11 — Impact Analysis & Safety Score

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Impact manifest modeling | ✅ DONE | `core/impact_report.py`: Tracks targets, sizes, counts, and sensitivity |
| Composite safety score (0-100) | ✅ DONE | `compute_safety_score()` rates reversibility, boundedness, and sensitivity |

---

## Baseline Test Suite Summary

- **Total tests:** 139
- **Passed:** 133
- **XPassed (expected model improvements):** 6
- **Failed:** 0
- **Pass Rate:** 100%
