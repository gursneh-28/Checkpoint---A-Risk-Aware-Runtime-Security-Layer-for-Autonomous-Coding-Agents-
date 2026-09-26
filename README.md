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

The roadmap is split into two halves — not by counting phases evenly, but
by what kind of work each half is. **PPT / midterm presentation: 4 Oct** —
target is to complete all of Half 1 by then.

**Half 1 — the core safety engine (Phases 1–5), target: 4 Oct**
Everything needed for Checkpoint to genuinely intercept, judge, simulate,
ask, execute, and roll back an action, end to end. A complete, honest,
demoable system on its own, even before any "smart" layer is added.

**Half 2 — intelligence, trust, and polish (Phases 6–11)**
The more open-ended, research-flavored work: recognizing manipulated
actions, learning behavior, hooking into a real agent, building the full
product, and formally proving safety guarantees. Deliberately scheduled
after the midterm, with more runway.

---

### HALF 1 — target: 4 Oct

### Phase 1 — Core interception loop ✅ DONE
- [x] 1. Basic interceptor: logs a shell command, then runs it
- [x] 2. Risk classifier v1 — pattern-based LOW / MEDIUM / HIGH
- [x] 3. Extend interception to file operations (create, write, delete, move)
- [x] 4. Extend risk classification to git operations specifically
- [x] 5. SQLite logging layer — every action persisted, not just printed

### Phase 2 — Confirmation gate ✅ DONE
- [x] 6. Pause on MEDIUM/HIGH tier and ask for approve/reject
- [x] 7. Rejection handling — log, block, confirm no change made

### Phase 3 — Frontend basics (dashboard MVP) ✅ DONE
A deliberately simple, plain-language dashboard — not the full product yet,
just enough to make Phases 1–2 visible and understandable to anyone,
technical or not. Simplicity here is a design choice we explain in the
presentation, not a shortcut: a safety tool with a confusing interface
would repeat the exact problem Checkpoint exists to fix.
- [x] 8. Minimal local dashboard (Flask, one page) reading live from
      `storage/checkpoint.db`
- [x] 9. Table view: action, risk tier (color-coded — green/yellow/red),
      status (executed / blocked / rejected) — plain language, no raw
      command syntax in the main view
- [x] 10. Manual or auto-refresh so newly logged actions show up without
      restarting the app
- [x] 11. Pending actions get a live approve/reject button in the browser —
      the confirmation gate now holds MEDIUM/HIGH actions in a "pending"
      state (polled every second) instead of blocking on a terminal prompt

### Phase 4 — Sandbox / dry-run engine
- [ ] 12. Shadow-copy affected files before modifying/deleting
- [ ] 13. Diff generator — show real outcome, not the raw command
- [ ] 14. Wire diff output into the confirmation gate (and the dashboard,
      once Phase 3 is live)

### Phase 5 — Checkpointing and rollback
- [ ] 15. Save pre-state + post-state per executed action
- [ ] 16. Rollback function — restore a prior checkpoint
- [ ] 17. Short talking-points script covering Phases 1–5 for a
      non-technical evaluator, rehearsed at least once beforehand

---

### HALF 2 — after the midterm

### Phase 6 — Provenance tracking (prompt-injection defense)
- [ ] 18. Tag each action's origin: user-typed / agent-internal / external-untrusted
- [ ] 19. Feed origin tag into the risk classifier
- [ ] 20. Build a test scenario simulating a prompt-injection attack

### Phase 7 — Anomaly detection
- [ ] 21. Log a behavioral baseline per session
- [ ] 22. Simple statistical anomaly scorer

### Phase 8 — Real agent integration
- [ ] 23. Hook the interceptor into an actual coding agent

### Phase 9 — Full product dashboard + packaging
- [ ] 24. Expand Phase 3's dashboard into the full live-feed + history +
      approvals product view
- [ ] 25. Package as an installable desktop app (Electron/Tauri)

### Phase 10 — Formal policy layer
- [ ] 26. Define 2–3 critical safety invariants
- [ ] 27. Model as a finite-state system and verify bad states are unreachable

### Phase 11 — Polish and final demo prep
- [ ] 28. Stress-test against real, messier agent sessions
- [ ] 29. Build 2–3 demo scenarios (safe cleanup, blocked action, caught injection)

---

## Midterm presentation plan

We present Half 1 in full — a complete, working core engine — plus Half 2
as the clearly-planned second half, not something we're improvising.

**What we demo live:**
- A safe action (e.g. `echo`, a normal `git commit`) — runs instantly, shows
  up in the dashboard as "executed," no interruption
- A risky action (e.g. `git push --force`) — gets paused, simulated in the
  sandbox so the real outcome is shown (not raw syntax), we approve/reject
  it, and it's checkpointed either way
- A rollback — undo a previously executed action using a saved checkpoint
- The dashboard itself: plain labels, color-coded risk, readable by someone
  with zero technical background

**What we say, not demo:** Half 2 — provenance tracking / prompt-injection
defense, anomaly detection, real agent hookup, the full product, and formal
verification — presented as the planned next phases with reasoning for why
each matters, not shown working yet.

---

## Project structure

```
checkpoint/
├── core/
│   ├── interceptor.py       # captures & routes shell/git actions through the pipeline
│   ├── risk_classifier.py   # assigns LOW / MEDIUM / HIGH (shell, file-op, and git-specific rules)
│   ├── file_ops.py          # intercepted file operations (create, write, delete, move)
│   └── confirmation.py      # shared gate: auto-executes LOW, pauses for approve/reject otherwise
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