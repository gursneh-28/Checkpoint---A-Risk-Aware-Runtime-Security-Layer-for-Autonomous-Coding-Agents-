# Checkpoint Implementation Status
**Against v2.3 Specification · Assessed 2026-11-21**

> [!IMPORTANT]
> Status is assessed by code inspection and test results, NOT by feature headings or README claims.
> A feature is **not complete** unless its implementation, tests, and failure behavior are verified.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ DONE | Implemented, tested, passing |
| 🟡 PARTIAL | Code exists but incomplete, broken tests, or missing security requirements |
| ❌ MISSING | Not implemented |
| 🔴 BROKEN | Implemented but tests failing or security boundary violated |
| ⚠️ STUB | Mock/placeholder – not real security functionality |

---

## Phase 0 — Compatibility and Security Proof

| Check | Status | Notes |
|-------|--------|-------|
| Claude Code version recorded | ❌ MISSING | Claude Code not found in PATH or standard install paths. `claude --version` cannot be run. |
| `onFailure: block` verified on installed version | ❌ MISSING | Cannot verify — Claude Code not found |
| Hook schema fixtures captured | ❌ MISSING | No real hook payloads recorded |
| Managed settings path verified (`C:\Program Files\ClaudeCode\managed-settings.json`) | ❌ MISSING | File/directory does not exist |
| Managed settings write-protected from agent account | ❌ MISSING | Cannot verify — no Claude Code installation |
| `CheckpointSvc` Windows service account created | ❌ MISSING | Account not created; requires admin approval |
| ACL isolation proven (agent cannot read/write Checkpoint store) | ❌ MISSING | Not tested; same-user deployment |
| Scoped service account project access | ❌ MISSING | Not configured |
| Journal drop-folder create-only permissions | ❌ MISSING | Current journal is a single SQLite file, not a drop folder |
| DPAPI CurrentUser encryption configured | ❌ MISSING | No encryption on stored data |
| DPAPI protect/unprotect round-trip tested | ❌ MISSING | Not implemented |
| Git Bash version and grammar documented | ⚠️ STUB | Git Bash 2.47 found; `bash --version` fails in sandbox (NtCreateDirectoryObject error) |
| bashlex parser adapter implemented | ❌ MISSING | No parser adapter; risk classifier uses regex/string matching |
| bashlex GPL-3.0 notice preserved | ❌ MISSING | bashlex not installed in venv |
| Threat model written | ❌ MISSING | No threat model document |
| Hook timeout measured | ❌ MISSING | No Claude Code to test against |
| Blocking-wait vs retry-after-approval decision | ❌ MISSING | Pipeline code assumes blocking wait but no measurement |
| `statusMessage` behavior verified | ❌ MISSING | Cannot verify |
| Claude Code permission rule coverage verified | ❌ MISSING | Cannot verify |

**Phase 0 Gate: ❌ NOT PASSED**

---

## Feature 1 — Interceptor and Real Agent Connection

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Event and Decision types | 🟡 PARTIAL | `event_types.py` has `Event`, `Decision`, `ClassifierResult` etc. — good structure, but not tested against real hook payloads |
| Claude Code adapter (hook JSON → Event → reply JSON) | 🟡 PARTIAL | `pipeline.py` has evaluate() but no actual HTTP/command hook client executable |
| Hook client (thin binary/script) | ❌ MISSING | No hook client script that Claude Code can invoke |
| `onFailure: block` configured | ❌ MISSING | No Claude Code hook configuration exists |
| PreToolUse enforcement hook | ❌ MISSING | Not registered anywhere |
| PostToolUse / PostToolUseFailure hooks | ❌ MISSING | Not registered |
| `updatedInput` full-object replacement | 🟡 PARTIAL | `to_hook_reply()` supports REWRITE decision but untested |
| Durable journal write before decision | 🟡 PARTIAL | `log_pending_action()` exists in `db.py` but journal is SQLite in-process, not a drop-folder |
| Session idempotency (tool_use_id dedup) | 🟡 PARTIAL | DB has unique constraint check but not fully tested under concurrent load |
| Local fast path (rule-proven LOW with journal write) | ❌ MISSING | Pipeline evaluates but no verified fast path with fresh signed policy snapshot |
| Hook credential separate from dashboard auth | ❌ MISSING | No credential system exists |
| Fail-closed on service unreachable | ❌ MISSING | No hook client to test this |
| Retry-after-approval mode | ❌ MISSING | Pipeline assumes blocking wait; retry mode not implemented |
| Real fixture tests | ❌ MISSING | Tests use synthetic data, not real Claude Code hook payloads |

**Feature 1 Status: 🟡 PARTIAL (architecture exists; no live integration)**

---

## Feature 2 — Risk Classifier

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Rules-first pipeline | ✅ DONE | `risk_classifier.py` implements rules → ML fallback |
| ML model never produces LOW | ✅ DONE | Enforced in `classify_risk_full()` |
| Chained command splitting | ✅ DONE | `_split_chained()` with correct highest-tier logic |
| Secret file detection → MEDIUM min | ✅ DONE | `_touches_secret_path()` |
| Protected branch exact match (not substring) | ✅ DONE | `PROTECTED_BRANCHES` frozenset with exact matching |
| `git push --force-with-lease` classification by branch | ✅ DONE | Checks protected branch separately |
| Windows path handling via path_module | ✅ DONE | `path_module.py` exists |
| `git clean`, `curl\|bash`, `docker prune`, `mv/cp` rules | ✅ DONE | Added to classifier |
| `classify_risk_full()` returns ClassifierResult | ✅ DONE | Includes source, confidence, parser_coverage |
| Bash AST parser (bashlex) | ❌ MISSING | Classifier uses regex, not AST |
| Parser adapter with support matrix | ❌ MISSING | No parser adapter module |
| Shell state probing (aliases, PATH, dotglob, etc.) | ❌ MISSING | Not implemented |
| Golden test table | 🟡 PARTIAL | Tests exist but 4 failures: `chmod 777` classify, `classify_file_op` write, two XPASS strict |
| Known classifier bugs fixed | 🟡 PARTIAL | `chmod 777` path variant still fails 1 test |

**Feature 2 Status: 🟡 PARTIAL (regex rules done; AST parser missing; 4 test failures)**

---

## Feature 3 — Instant Run for Safe Commands

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Per-command flag allowlist | ✅ DONE | `_SAFE_COMMANDS` list with `frozenset` of flags |
| No redirects / substitution check | ✅ DONE | `_has_redirect()`, `_has_substitution()` |
| Chained command requires all parts safe | ✅ DONE | Highest-tier logic covers this |
| Trusted list (binding to executable identity, project scope, expiry) | ❌ MISSING | No trusted list mechanism |
| Local fast path with signed policy snapshot | ❌ MISSING | No hook client, no fast-path implementation |
| Durable journal write before allow | ❌ MISSING | No hook client |
| Session/provenance/anomaly check before fast-path | ❌ MISSING | Pipeline exists but no hook client |
| Burst guard (shared state file, Windows-safe locking) | ❌ MISSING | Not implemented |
| LOW instant-run only after durable journal tests pass | ⚠️ STUB | Phase 0 gate not met |

**Feature 3 Status: ❌ MISSING (classifier rules exist; no live fast-path)**

---

## Feature 4 — Human Decision for MEDIUM/HIGH Risk

| Sub-feature | Status | Notes |
|------------|--------|-------|
| MEDIUM/HIGH → pending state | 🟡 PARTIAL | `log_pending_action()` exists; dashboard shows pending |
| Hook waits for dashboard decision | ❌ MISSING | No real hook waiting; `confirmation.py` uses terminal prompt |
| Approval binding (action ID, command hash, cwd, shell profile, versions, expiry) | ❌ MISSING | No approval binding system in DB |
| Single-use approval token | ❌ MISSING | Current DB uses `decide_action()` with idempotency but no cryptographic token |
| 300-second expiry (server-authoritative) | ❌ MISSING | Pipeline code has `APPROVAL_TIMEOUT_SECONDS = 300` but no enforcement |
| Stale approval detection (command/cwd/preview hash change) | ❌ MISSING | No hash binding |
| Dashboard auth required for approval | 🟡 PARTIAL | CSRF token exists; but no authentication (passwordless) |
| Dashboard login (Argon2id) | ❌ MISSING | No login system |
| Rate limits on approval endpoint | ❌ MISSING |  |
| Rejection feedback reason to agent | ❌ MISSING | No hook client to receive it |
| Double-click / two-tab idempotency | ✅ DONE | `decide_action()` checks existing decision |

**Feature 4 Status: 🟡 PARTIAL (dashboard exists; auth missing; no live hook waiting)**

---

## Feature 5 — Plain Language Preview

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `generate_preview()` function | 🟡 PARTIAL | `preview.py` exists with structured output |
| CommandAnalysis / EffectManifest | 🟡 PARTIAL | Basic structure in `preview.py` |
| Filesystem facts (resolved targets, counts, sizes) | ❌ MISSING | Not implemented in preview |
| Versioned Preview object stored per action | ❌ MISSING | Not stored separately in DB |
| Preview hash (for approval binding) | ❌ MISSING | No hash computed |
| "Effect unknown" for unsupported syntax | 🟡 PARTIAL | Partial — falls back to raw command |
| bashlex AST-based analysis | ❌ MISSING | Regex-based only |
| Golden tests per template | ❌ MISSING | No preview tests |
| Dashboard shows preview (headline first, raw command one-click away) | ❌ MISSING | Dashboard shows raw command directly |

**Feature 5 Status: 🟡 PARTIAL (stub exists; not wired to dashboard; no stored versioned Preview)**

---

## Feature 6 — Safer Option ("Do This Instead")

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Suggestion engine (input = parsed command + tier) | 🟡 PARTIAL | `suggestions.py` exists but 2 test failures (trash suggestion returns None) |
| `rm -rf` → trash (same-volume, ACL-verified) | 🔴 BROKEN | Test fails: `suggest_alternative()` returns None for `rm` |
| `git push --force` → `--force-with-lease` | ✅ DONE | Tests passing |
| `git reset --hard` → `git stash` | ✅ DONE | Tests passing |
| `git clean -fdx` → dry run (`-n`) | ❌ MISSING |  |
| `curl \| bash` → download to file | ❌ MISSING |  |
| `docker prune` → no-volumes alternative | ❌ MISSING |  |
| Trash location: protected per-volume folder with ACL | ❌ MISSING | Current trash is in `storage/trash/` with no ACL protection |
| Volume serial selection and file-ID verification | ❌ MISSING |  |
| Suggestion validator (re-classify, effects subset check) | ❌ MISSING | No validator |
| Server rebuilds alternative at approval time | ❌ MISSING | No server-side rebuild |
| Alternative hash bound to approval | ❌ MISSING |  |
| Backup execution after approval, before run | ❌ MISSING | Current code runs backup in old confirmation.py flow |
| Fixed template + validated literal args (no arbitrary shlex.quote) | ❌ MISSING | Current code uses f-strings |
| Status flow: backing_up → backup_verified → execution_authorized | ❌ MISSING |  |

**Feature 6 Status: 🔴 BROKEN (partial; 2 test failures; major security gaps)**

---

## Feature 7 — Version History Control and Rollback

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Content-addressed blob store (SHA-256, compressed, rename-write) | ❌ MISSING | Current `sandbox.py` uses `shadow_copies/` with simple file copy |
| SQLite tables: blobs, versions, action_files, pins, backups | ❌ MISSING | Current DB has basic `checkpoints` table only |
| Deleted file explicit state (not empty blob) | ❌ MISSING |  |
| Before/after snapshots per action | 🟡 PARTIAL | `sandbox.py` has `snapshot_file()` but 1 test failure |
| Rollback with conflict detection + recovery journal | ❌ MISSING | Basic rollback exists but no conflict detection or journal |
| 2 GB shared quota enforcement | ❌ MISSING |  |
| 50 MB per-file cap | ❌ MISSING |  |
| 30-day retention for unpinned snapshots | ❌ MISSING |  |
| Pinned versions (never expire) | ❌ MISSING |  |
| Regenerable-folder exemptions with lockfile check | ❌ MISSING |  |
| ACL-protected store (outside workspace) | ❌ MISSING | Store is `storage/` inside the project |
| DPAPI encryption on blob store | ❌ MISSING |  |
| Hash chain on action_events | 🟡 PARTIAL | `db.py` has hash chain structure but not fully integrated |
| Option A quota reclamation (expired trash first, then snapshots) | ❌ MISSING |  |
| 80% / 95% storage warnings | ❌ MISSING |  |
| Early release (authenticated, single action, logged) | ❌ MISSING |  |

**Feature 7 Status: 🟡 PARTIAL (basic shadow_copies exist; no content-addressed store; no quota; no ACLs)**

---

## Feature 8 — Full Action Log (Storage)

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `actions` table | ✅ DONE | Exists with searchable fields |
| `action_events` append-only with SHA-256 hash chain | 🟡 PARTIAL | Table exists; hash chain not fully verified |
| `action_files` before/after per path | 🟡 PARTIAL | Table exists; rollback test fails |
| Secret scrubbing before write | ✅ DONE | `_scrub_secrets()` in `db.py` |
| Output cap (1 MB, first+last) | ✅ DONE | `_truncate_output()` |
| Record FIRST, then answer | 🟡 PARTIAL | Pipeline calls `log_pending_action()` before decision — but journal is not a durable drop folder |
| Journal drop folder (agent create-only, no read/list/modify/delete) | ❌ MISSING | Journal is SQLite accessible to agent |
| Service ingests journal entries in order, verifies chain | ❌ MISSING | No separate service process |
| WAL mode | ✅ DONE | `PRAGMA journal_mode=WAL` set |
| Idempotent tool_use_id within session | 🟡 PARTIAL | `get_or_create_action_id()` attempted but `log_pending_action()` doesn't use it consistently |
| Read API (no direct table queries) | 🟡 PARTIAL | Functions exist but some callers use ad-hoc queries |
| Hash chain anchor outside main DB | ❌ MISSING |  |
| Metadata retention 365 days | ❌ MISSING | No retention job |
| Output retention 30 days | ❌ MISSING | No retention job |
| Alert system (feature 15) | ⚠️ STUB | `create_alert()` exists; no delivery |

**Feature 8 Status: 🟡 PARTIAL (good schema foundation; journal not secure; no retention; no service separation)**

---

## Feature 9 — Write YES for Very High-Risk Commands (CRITICAL)

| Sub-feature | Status | Notes |
|------------|--------|-------|
| CRITICAL tier definition and rules | 🟡 PARTIAL | `policy_resolver.py` has CRITICAL tier but rules incomplete |
| Server-side decision (never trusts browser tier) | 🟡 PARTIAL | Policy resolver runs server-side |
| Approval binding with single-use nonce | ❌ MISSING |  |
| Typed YES validation (exact "YES", trim ASCII spaces only) | ❌ MISSING | No typed-YES UI or validation |
| Dedicated full-page CRITICAL confirmation screen | ❌ MISSING | No dedicated screen |
| Dashboard authentication (Argon2id login) | ❌ MISSING | Currently passwordless |
| HttpOnly/SameSite cookies, session expiry, logout | ❌ MISSING |  |
| Rate limits | ❌ MISSING |  |
| Hook credential cannot approve | ❌ MISSING | No credential separation |
| CRITICAL disabled until account isolation proven | ❌ MISSING | CRITICAL path exists in code without safety gate |
| CRITICAL events through Feature 8 event service | ❌ MISSING |  |

**Feature 9 Status: ❌ MISSING (CRITICAL tier exists in policy but no enforcement, no auth, no typed-YES UI)**

---

## Feature 10 — Provenance Tracking

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `provenance.py` module | 🟡 PARTIAL | File exists with basic structure |
| `context_ingestions` table | ❌ MISSING | No table in DB schema |
| `action_provenance_evidence` table | ❌ MISSING |  |
| UserPromptSubmit hook capture | ❌ MISSING | No hook registered |
| Entity matcher (domain, URL, package, path, IP) | ❌ MISSING |  |
| Two-stage processing (sync ledger + async enrichment) | ❌ MISSING |  |
| Tier escalation via policy resolver | 🟡 PARTIAL | `policy_resolver.py` accepts `ProvenanceSignal` |
| Dashboard "where this came from" panel | ❌ MISSING |  |

**Feature 10 Status: ⚠️ STUB (placeholder module; no real implementation)**

---

## Feature 11 — Anomaly Detection

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `anomaly.py` module | 🟡 PARTIAL | File exists with basic structure |
| Session state engine (live counters, effect fingerprints) | ❌ MISSING |  |
| Retry-after-rejection detection | ❌ MISSING |  |
| Dangerous sequence detection | ❌ MISSING |  |
| Family-capped scoring | ❌ MISSING |  |
| Circuit breaker (pause flag) | ❌ MISSING |  |
| Fast-path guard (shared state file, atomic Windows-safe locking) | ❌ MISSING |  |
| Session tables in DB | ❌ MISSING |  |
| Tier escalation via policy resolver | 🟡 PARTIAL | `policy_resolver.py` accepts `AnomalySignal` |
| Dashboard "why this looks unusual" panel | ❌ MISSING |  |

**Feature 11 Status: ⚠️ STUB (placeholder module; no real implementation)**

---

## Feature 12 — Impact Report (HIGH/CRITICAL only)

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `impact_report.py` module | 🟡 PARTIAL | File exists |
| `ImpactManifest` (predicted effects, hash, confidence, completeness) | 🟡 PARTIAL | Basic dataclass |
| `BackupPlan` (per-item already_backed_up / will_attempt / cannot_back_up) | 🟡 PARTIAL | Basic structure |
| `BackupManifest` (actual results, separate from plan) | ❌ MISSING | Not separated |
| Impact manifest hash (for approval binding) | ❌ MISSING |  |
| File-identity check without reading content | ❌ MISSING |  |
| Recoverability labels | ❌ MISSING |  |
| Dashboard HIGH/CRITICAL impact panel | ❌ MISSING |  |

**Feature 12 Status: ⚠️ STUB (data structures exist; no real filesystem analysis)**

---

## Feature 13 — Git Safety Net

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `git_safety.py` module | 🟡 PARTIAL | File exists with `GitSafetyNet` class |
| External Git backup root (`%LOCALAPPDATA%\Checkpoint\git-backups\`) | 🟡 PARTIAL | Uses `%APPDATA%\Checkpoint\git-backups\` — wrong path (should be `%LOCALAPPDATA%`) |
| Git bundle creation | 🟡 PARTIAL | Code exists; not tested end-to-end |
| Staged/unstaged/untracked state preservation | 🟡 PARTIAL | Code attempts `git diff`; not fully tested |
| Backup verified before destructive git op | 🟡 PARTIAL | `has_verified_backup()` called in pipeline |
| `.git` never exempt (not a regenerable folder) | ✅ DONE | Documented in git_safety.py |
| JSON index for backup records | 🟡 PARTIAL | Exists but not ACL-protected |
| Backup root under service account (not agent account) | ❌ MISSING | No service account |
| Quota counting for Git backup data | ❌ MISSING |  |
| 30-day retention for external Git backups | ❌ MISSING |  |

**Feature 13 Status: 🟡 PARTIAL (code skeleton; not securely configured)**

---

## Feature 14 — Flag Wrong Rating

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `flag_events` table | ✅ DONE | Table in DB schema |
| Dashboard flag button | ❌ MISSING | Not in dashboard templates |
| Human review queue | ❌ MISSING |  |
| Flags never change current decision | ✅ DONE | Flags only write to flag_events |
| Offline model evaluation/promotion loop | ❌ MISSING |  |

**Feature 14 Status: 🟡 PARTIAL (storage exists; no UI or workflow)**

---

## Feature 15 — Pending Approval Alert

| Sub-feature | Status | Notes |
|------------|--------|-------|
| `alerts` table | ✅ DONE | In DB schema |
| `create_alert()` function | ✅ DONE | Exists |
| Dashboard live updates | 🟡 PARTIAL | Auto-refresh in `index.html` but no WebSocket/SSE |
| In-browser notification (Notification API) | ❌ MISSING |  |
| Alert never approves or extends action | ✅ DONE | By design |
| Notification delivery separate from authorization | ✅ DONE | By design |

**Feature 15 Status: 🟡 PARTIAL (storage exists; no live notification delivery)**

---

## Feature 16 — Overall Summary / Reporting

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Dashboard summary view | ❌ MISSING |  |
| Filters (time, tier, status, session, decision, flagged) | ❌ MISSING |  |
| Export | ❌ MISSING |  |
| Summary distinguishes attempted/authorized/executed/failed/rejected/outcome-unknown | ❌ MISSING |  |

**Feature 16 Status: ❌ MISSING**

---

## Dashboard (cross-feature)

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Flask app running | ✅ DONE | `dashboard/app.py` |
| Action table with risk tier color-coding | ✅ DONE | `index.html` |
| Auto-refresh | ✅ DONE | JavaScript polling |
| Approve/Reject/Alternative buttons | ✅ DONE | With CSRF protection |
| CSRF token on state-changing requests | ✅ DONE | Implemented |
| Bind to 127.0.0.1 | ✅ DONE | `host='127.0.0.1'` |
| Dashboard authentication (login, Argon2id, sessions) | ❌ MISSING | Currently no login |
| HttpOnly/SameSite cookies | ❌ MISSING |  |
| Strict Host/Origin validation | ❌ MISSING |  |
| Rate limits | ❌ MISSING |  |
| Secret signing key persisted securely (not regenerated on restart) | ❌ MISSING | Currently uses random key |
| Dashboard test: CSRF token in page | 🔴 BROKEN | 1 test failing (JSON decode error) |
| Rollback UI | 🟡 PARTIAL | `checkpoints.html` and `rollback_result.html` exist; rollback test failing |

---

## Dataset (Feature 2 / Feature 7 of spec)

| Sub-feature | Status | Notes |
|------------|--------|-------|
| Raw command pool (34,843 commands) | ✅ DONE | `commands_filtered.jsonl` (34,843 records) |
| Pool is immutable | ✅ DONE | Documented |
| Derived dataset with dedup, near-dup review, source/licence check | ❌ MISSING | Only `commands_final.csv` with basic labels |
| Repository-level train/val/test splits | ❌ MISSING | No repo-level splits |
| Frozen hand-labelled test set (~1,000 examples) | ❌ MISSING | No frozen test set |
| Written label guidelines | ❌ MISSING |  |
| Parser compatibility labels per row | ❌ MISSING |  |
| HIGH-to-LOW error reporting | ❌ MISSING |  |
| Calibrated linear model vs rules-only baseline | 🟡 PARTIAL | Model exists (`storage/risk_model.pkl`) but not calibrated; no rules-only comparison |

---

## Overall Phase Readiness

| Phase | Status | Blocking Issues |
|-------|--------|----------------|
| **Phase 0** — Compatibility & Security Proof | ❌ NOT STARTED | Claude Code not found, no CheckpointSvc account, no DPAPI, no hook fixtures |
| **Phase 1** — Durable Gate Foundation | ❌ NOT STARTED | Phase 0 gate not passed |
| **Phase 2** — Analysis & Recoverability | ❌ NOT STARTED | Phase 1 gate not passed |
| **Phase 3** — Controlled Execution | ❌ NOT STARTED | Phase 2 gate not passed |
| **Phase 4** — Context & Behavior | ❌ NOT STARTED | Phase 3 gate not passed |
| **Phase 5** — Feedback & Reporting | ❌ NOT STARTED | Phase 4 gate not passed |

**Current state:** The repository contains a well-structured prototype with real code for the classifier, policy resolver, pipeline, storage, and dashboard. This prototype demonstrates the design correctly. However, **none of the security boundaries specified in v2.3 have been implemented or verified**, and **live Claude Code integration does not exist**. The project is at the design/prototype stage relative to v2.3 requirements.
