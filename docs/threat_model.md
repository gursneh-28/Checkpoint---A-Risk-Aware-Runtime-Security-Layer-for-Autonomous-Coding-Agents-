# Checkpoint Threat Model
**Specification Authority: v2.3 Section 3, Section 5, Section 9, Phase 0 Checklist**
*Date: 2026-11-21 · Author: Lead Software Engineer*

---

## 1. System Overview and Trust Boundaries

Checkpoint acts as a risk-aware runtime security mediation layer between an autonomous coding agent (Claude Code in the v2.3 scope) and the host operating system.

### Trust Domains

```
┌─────────────────────────────────────────────────────────────┐
│ Untrusted / Semi-Trusted Domain: Agent Execution Context    │
│ - Agent Process (Claude Code CLI / subagents)               │
│ - Agent Environment variables & scratch space               │
│ - Project Workspace (files, repositories, node_modules)     │
│ - External inputs (prompt text, fetched web pages, PR diffs)│
└──────────────────────────────┬──────────────────────────────┘
                               │ [Hook Interceptor / IPC]
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Trust Boundary: Checkpoint Mediation Layer                  │
│ - Policy Resolver (deterministic escalation)                │
│ - Classifier (Rules-first + ML fallback)                    │
│ - Parser Adapter (bashlex AST + syntax validation)          │
│ - Journal / Event Store (append-only hash chain)            │
│ - Version History Store (content-addressed blobs)           │
│ - Git Safety Net (external bare repository backups)         │
│ - Human Approval Gate (authenticated dashboard)             │
└──────────────────────────────┬──────────────────────────────┘
                               │ [Admin / OS Isolation]
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Trusted Host Environment & Protected Storage                │
│ - Dedicated Windows Standard Account (CheckpointSvc)        │
│ - Restrictive Windows ACLs (%LOCALAPPDATA%\Checkpoint\store)│
│ - Windows DPAPI CurrentUser Encryption                      │
│ - Authenticated User Browser Session                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Threat Actors and Capabilities

| Threat Actor | Access Level | Primary Goals | Inherent Capabilities |
|---|---|---|---|
| **Autonomous Coding Agent (Compromised or Hallucinating)** | User Account (Standard) | Execute destructive actions, exfiltrate credentials, modify source files, delete history | Invokes Bash tools, file read/write, environment inspect, network requests |
| **Indirect Prompt Injector (External Web / PR)** | Content Ingestion | Trick agent into invoking high-risk commands (reverse shell, `curl \| bash`, credential theft) | Influences agent reasoning via injected instructions in retrieved files/pages |
| **Local Malicious Process (Co-located on host)** | User Account | Bypass Checkpoint approval, tamper with journal or backup snapshots | Can access localhost sockets, attempt file edits on unprotected folders |
| **Malicious Repository Artifacts** | Repository files | Exploit git hooks, `.git/config`, `node_modules` scripts | Run malicious code automatically upon git checkout, status, or test commands |

---

## 3. Threat Scenarios & Mitigations

### 3.1 Same-User Access & Host Isolation

- **Threat:** If Checkpoint service runs under the exact same Windows user account as the agent, the agent process has identical OS permissions and can directly access the SQLite database (`checkpoint.db`), modify or delete shadow copies / backup files, read the session secret key, or kill the service process.
- **V2.3 Requirement & Mitigation:**
  - Dedicated local Windows service account (`CheckpointSvc`).
  - Strict Windows ACLs stripping permissions for the agent account and granting full control only to `CheckpointSvc` and `SYSTEM`.
  - Backup storage and sensitive credentials encrypted with DPAPI `CurrentUser` under `CheckpointSvc`.
  - Scoped project access: CheckpointSvc receives only read access for backups and modify rights strictly where trash moves and restores occur.
  - *Honest Security Limit:* Until `CheckpointSvc` account creation and ACLs are configured, same-user deployment cannot guarantee a process-level security boundary; all in-process protections are defense-in-depth only. CRITICAL tier approval must remain disabled.

### 3.2 Journal Drop-Folder Integrity & Tampering

- **Threat:** An agent realizes its actions are audited in the journal and attempts to edit, delete, or re-order journal files to conceal unauthorized or destructive commands.
- **V2.3 Requirement & Mitigation:**
  - Create-only agent-writable drop folder with Windows ACL `(GW)` (Generic Write / create file) without Read `(R)`, List `(RD)`, Delete `(D)`, or Write DAC `(WDAC)`.
  - Per-session strictly increasing sequence numbers.
  - SHA-256 hash chains connecting each journal event to the previous event hash.
  - Checkpoint service ingests files in sequence order, verifies the chain, and alerts/pauses the session immediately upon detection of any gap, re-ordering, or modification.
  - "Record first, then answer" enforcement: no decision is returned to the agent until the journal entry is durably flushed.

### 3.3 Dashboard Authentication & Approval Tampering

- **Threat:** An agent with terminal tools or browser capabilities attempts to automate HTTP requests to `http://127.0.0.1:5000/resolve/...` or forge approvals claiming `approved=True`.
- **V2.3 Requirement & Mitigation:**
  - Localhost binding (`127.0.0.1`) and Host header validation are defense-in-depth, **not** authentication.
  - Mandatory dashboard user login using Argon2id password hashing and session tokens.
  - Single-use server-side approval tokens bound to a cryptographic hash of: action ID, exact command hash, cwd, shell profile, parser version, preview hash, impact manifest hash, backup plan hash, and expiry.
  - CSRF tokens required on all POST endpoints (`HttpOnly`, `SameSite=Strict` cookies).
  - Agent hook client credential is distinct from dashboard authentication and is cryptographically prevented from invoking any approval endpoint.
  - CRITICAL tier requires dedicated full-page confirmation and typing exact "YES" (trimmed ASCII spaces only); cannot be satisfied via programmatic API flags.

### 3.4 Hook Failure & Fail-Open Exploitation

- **Threat:** Claude Code command hooks default to fail-open behavior if hook invocation crashes, exits non-zero, or times out, allowing risky commands to execute unvetted.
- **V2.3 Requirement & Mitigation:**
  - Mandate `onFailure: block` in Claude Code hook registration.
  - Register hooks and deny rules in Administrator-protected managed settings (`C:\Program Files\ClaudeCode\managed-settings.json`).
  - Validate exit codes: exit 0 with JSON decision for normal flow; exit 2 for hard block.
  - Measure timeout budgets: if hook timeout is less than 375 seconds (approval + backup budget + margin), use retry-after-approval mode rather than blocking wait to prevent premature timeout fail-open.
  - If service is unreachable or journal fails, fail closed (deny action).

### 3.5 Parser Ambiguity & Evasion

- **Threat:** An agent obscures malicious intent via complex shell syntax, aliases, subshell expansions (`$(rm -rf /)`), arithmetic expansion, here-docs, or character encoding that bypass naive regex scanners.
- **V2.3 Requirement & Mitigation:**
  - Formal AST parsing using `BashParserAdapter` wrapping `bashlex`.
  - Commands with subshell substitutions, unresolvable parameters, or unsupported syntax are marked `ParserCoverage.PARTIAL` or `ParserCoverage.UNSUPPORTED` and are strictly disqualified from instant run.
  - Central policy resolver escalates unknown or incomplete parser coverage to at least `MEDIUM` or `HIGH`.
  - Unbounded destructive scope (`rm -rf /`, `> /dev/sda`, `dd if=/dev/zero`) triggers hard-deny that cannot be overridden even with typed YES.

### 3.6 Storage Quota Exhaustion & DoS

- **Threat:** An agent repeatedly generates file modifications or attempts large deletes to fill the disk or consume the version history quota, causing denial of service or forced early eviction of backup history.
- **V2.3 Requirement & Mitigation:**
  - Enforce Option A retention policy: fixed 50 MB per-file cap and 2 GB shared quota across blobs, external Git backups, and logical trash bytes.
  - Quota pressure starts cleanup checks at 80% and warnings at 80% and 95%.
  - Quota reclamation NEVER purges unexpired data early (30-day retention window is sacred). Only expired trash and oldest expired unpinned snapshots are reclaimed.
  - If eligible cleanup cannot free sufficient headroom, the destructive action requiring backup is blocked. Edits whose snapshot cannot fit require a dashboard decision and are flagged with an anomaly signal.

---

## 4. Phase 0 Security Gates and Status

| Gate | Status | Reason |
|---|---|---|
| `CheckpointSvc` Account Isolation | BLOCKED (Needs User Admin Approval) | Awaiting explicit admin credential/approval from user |
| Journal Drop Folder ACLs | BLOCKED (Requires CheckpointSvc) | Depends on service account creation |
| DPAPI CurrentUser Protection | BLOCKED (Requires CheckpointSvc profile) | Depends on service account profile |
| Claude Code Managed Settings | BLOCKED (Claude Code Not Installed) | Awaiting installation of Claude Code on host |
| `onFailure: block` Enforcement | BLOCKED (Claude Code Not Installed) | Awaiting installation of Claude Code on host |
| Hook Schema Fixture Verification | SIMULATED | Fixtures created from official docs; pending live app verification |
| Parser Adapter & Grammar Matrix | VERIFIED (In-Memory / Private) | bashlex adapter implemented, tested, and GPL notice preserved |
