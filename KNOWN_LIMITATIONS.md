# Checkpoint Known Limitations
**Assessed against v2.3 specification · Updated 2026-11-21**

---

## 1. Claude Code Not Installed on Host

**Severity: HIGH — Integration Blocked (Awaiting Application)**

Per user clarification, Claude AI / Claude Code is not currently installed on the host computer.

**Consequence:**
- Cannot test live hook execution or timing behavior.
- Cannot measure the live maximum hook timeout budget on this Windows installation.
- Cannot verify `onFailure: block` fail-closed behavior against the running CLI.
- Managed settings (`C:\Program Files\ClaudeCode\managed-settings.json`) cannot be configured or evaluated.

**Current Mitigation / Status:**
- `core/claude_code_adapter.py` and official hook fixtures (`tests/fixtures/claude_code/*.json`) provide clean contract separation.
- Automated tests pass against fixture payloads and simulated stdin/stdout hook events.
- All live enforcement and compatibility claims remain strictly marked **BLOCKED / SIMULATED** until Claude Code is installed and verified.

---

## 2. No Windows Service Account (`CheckpointSvc`)

**Severity: CRITICAL — Host Security Isolation Blocked**

`CheckpointSvc` local account has not been created because it requires manual administrative approval and command execution (`net user CheckpointSvc ...`).

**Consequence:**
- Checkpoint currently runs in the same user space as any potential agent.
- Windows ACL isolation on the store (`%LOCALAPPDATA%\Checkpoint\store`) and journal drop folder cannot be established.
- DPAPI CurrentUser encryption cannot be bound to an isolated service account profile.
- CRITICAL tier human approval remains disabled.

---

## 3. Dependency Licenses & Distribution Gate

**Severity: LOW — Documentation Gate**

`bashlex` is installed in the local virtual environment for parsing ASTs in private research.
Per specification §4 and Decision Register 2:
- bashlex is under GPL-3.0-or-later.
- Checkpoint cannot be distributed or bundled with bashlex without a formal license review or replacement with a permissive alternative (such as tree-sitter-bash).
- Notice is strictly preserved in `core/parser_adapter.py`.

---

## 4. Feature 10 (Provenance Tracking) In-Memory & Test Gap

**Severity: MEDIUM — Application Completeness**

`core/provenance.py` implements session-level fetch tracking, dynamic command detection, and tier escalation, and is wired into `core/pipeline.py` and `core/policy_resolver.py`.
However:
- The persistent SQLite tables (`context_ingestions`, `action_provenance_evidence`) specified in §10 are not yet created in `storage/db.py`; records currently live in an in-memory session deque.
- There are no dedicated unit tests in `tests/` explicitly validating `core/provenance.py` detection rules.
- Live context ingestion hooks (`UserPromptSubmit`, `PostCompact`) are deferred awaiting Claude Code installation.

---

## 5. Dashboard Authentication Deferred

**Severity: MEDIUM — Access Control**

The web dashboard enforces CSRF protection and HTTPOnly/SameSite cookies on localhost, but does not yet require password authentication via Argon2id. It is currently intended solely for local developer operation until host security boundaries and multi-user service isolation are configured in Milestone 5.

---

## 6. Passive Approval Expiry

**Severity: LOW — Operational Timers**

Single-use decisions and replay prevention are strictly enforced in `storage/db.py`. However, the 300-second approval expiration window is evaluated passively upon query rather than by an active background cleanup daemon sweeping stale actions.
