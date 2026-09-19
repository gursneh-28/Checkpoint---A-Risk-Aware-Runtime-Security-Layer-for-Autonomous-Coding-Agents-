# Checkpoint
**A Risk-Aware Runtime Security Layer for Autonomous Coding Agents**

Checkpoint intercepts every file, shell, and git action an autonomous coding
agent (e.g. Claude Code, Cursor, Antigravity) attempts, classifies it by risk,
and lets safe actions run instantly while risky ones are simulated and shown
to the user as a plain outcome before anything touches the live system.

Team: Gursneh Kaur, Pakhi Sharma, Suhani Agarwal
Faculty Guide: Dr. Pranab Roy

---

## How the system works (high-level flow)

```
Agent requests an action
        ↓
Interception Core (captures it before execution)
        ↓
Provenance Tracker (where did this action's justification come from?)
        ↓
Risk Classifier (LOW / MEDIUM / HIGH, based on reversibility × blast-radius × cost)
        ↓
   ┌────────────┬─────────────────┬──────────────────┐
  LOW          MEDIUM             HIGH
   ↓             ↓                  ↓
Auto-execute   Sandbox/dry-run   Sandbox/dry-run + Anomaly check
   ↓             ↓                  ↓
Checkpoint    ────────→  Dashboard (shows outcome, not raw command)
   store                        ↓
                          User decision (approve/reject)
                                ↓
                    Execute + new checkpoint  /  Reject, logged
```

## Build phases

This project is built in dependency order — each step produces something
testable before moving to the next. Checked items are done.

### Phase 1 — Core interception loop
- [x] 1. Basic interceptor: logs a shell command, then runs it
- [x] 2. Risk classifier v1 — pattern-based LOW / MEDIUM / HIGH
- [x] 3. Extend interception to file operations (create, write, delete, move)
- [x] 4. Extend risk classification to git operations specifically
- [x] 5. SQLite logging layer — every action persisted, not just printed

### Phase 2 — Confirmation gate
- [ ] 6. Pause on MEDIUM/HIGH tier and ask for approve/reject
- [ ] 7. Rejection handling — log, block, confirm no change made

### Phase 3 — Sandbox / dry-run engine
- [ ] 8. Shadow-copy affected files before modifying/deleting
- [ ] 9. Diff generator — show real outcome, not the raw command
- [ ] 10. Wire diff output into the confirmation gate

### Phase 4 — Checkpointing and rollback
- [ ] 11. Save pre-state + post-state per executed action
- [ ] 12. Rollback function — restore a prior checkpoint

### Phase 5 — Provenance tracking (prompt-injection defense)
- [ ] 13. Tag each action's origin: user-typed / agent-internal / external-untrusted
- [ ] 14. Feed origin tag into the risk classifier
- [ ] 15. Build a test scenario simulating a prompt-injection attack

### Phase 6 — Anomaly detection
- [ ] 16. Log a behavioral baseline per session
- [ ] 17. Simple statistical anomaly scorer

### Phase 7 — Real agent integration
- [ ] 18. Hook the interceptor into an actual coding agent

### Phase 8 — Dashboard (product layer)
- [ ] 19. Minimal local web dashboard — live feed + pending approvals
- [ ] 20. Package as an installable desktop app (Electron/Tauri)

### Phase 9 — Formal policy layer
- [ ] 21. Define 2–3 critical safety invariants
- [ ] 22. Model as a finite-state system and verify bad states are unreachable

### Phase 10 — Polish and demo prep
- [ ] 23. Stress-test against real, messier agent sessions
- [ ] 24. Build 2–3 demo scenarios (safe cleanup, blocked action, caught injection)

---

## Project structure

```
checkpoint/
├── core/
│   ├── interceptor.py       # captures & routes actions through the pipeline
│   ├── risk_classifier.py   # assigns LOW / MEDIUM / HIGH
│   ├── file_ops.py          # intercepted file operations
│   └── git_ops.py           # git-specific risk rules
├── storage/
│   └── db.py                # SQLite logging layer
├── tests/
├── docs/
│   └── Checkpoint_Synopsis.docx
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```bash
python core/interceptor.py
```