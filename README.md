# Checkpoint
**A Risk-Aware Runtime Security Layer for Autonomous Coding Agents**

Checkpoint intercepts every file, shell, and git action an autonomous coding
agent (e.g. Claude Code, Cursor, Antigravity) attempts, classifies it by risk,
and lets safe actions run instantly while risky ones are simulated and shown
to the user as a plain outcome before anything touches the live system.

---

## How the system works (high-level flow)

```
Agent requests an action
        ↓
Interception Core (captures it before execution)
        ↓
Provenance Tracker (where did this action's justification come from?)
        ↓
Risk Classifier (LOW / MEDIUM / HIGH — hardcoded rules, ML fallback in progress)
        ↓
   ┌────────────┬─────────────────┬──────────────────┐
  LOW          MEDIUM             HIGH
   ↓             ↓                  ↓
Auto-execute   Sandbox/dry-run   Sandbox/dry-run + Anomaly check
   ↓             ↓                  ↓
Checkpoint    ────────→  Dashboard (shows outcome, not raw command)
   store                        ↓
                    Approve / Reject / "Do this instead"
                                ↓
              Execute + new checkpoint  /  Reject, logged  /  Safer alternative run
```

## How "Do this instead" actually works

When a risky action is intercepted, it isn't just labeled risky and left
there — the system checks whether a known, safer way to do the same thing
exists, and if so, offers it as a real third choice, not just a warning.

**How a suggestion is generated:** this is a plain, hardcoded lookup — not
AI, and not the same model used for risk scoring. A command's text is
checked against a small table of known risky patterns, each mapped to a
safer equivalent action:

| Risky pattern detected | Safer alternative offered |
|---|---|
| `git push --force` | `git push --force-with-lease` (fails safely instead of silently overwriting someone else's work) |
| `git reset --hard` | `git stash` (keeps the changes recoverable instead of discarding them) |
| Permanently deleting a file | Move the file into a local trash folder instead (fully recoverable) |

If a command doesn't match any pattern in this table, no suggestion is
generated, and only Approve/Reject are shown — "Do this instead" never
appears for an action with no known safer version.

**How the three-way decision actually gets resolved:**
1. The risky action is logged to the database with status `pending`,
   along with its plain-language suggestion text (if one exists).
2. The dashboard displays the action, its risk tier, and — if present — a
   highlighted suggestion box with a third button alongside Approve/Reject.
3. Whichever option the user picks sends a request that updates that
   action's status in the database (`approved`, `rejected`, or
   `alternative`).
4. The part of the system that originally intercepted the action is still
   waiting, checking the database once a second for a decision. The moment
   it sees the new status, it does exactly one of three things:
   - `approved` → runs the **original** risky action for real
   - `rejected` → runs nothing, logs that nothing happened
   - `alternative` → runs the **safer** action instead (e.g. actually moves
     the file to trash, or actually runs the `--force-with-lease` version)

**The important safety property to understand:** the suggested alternative
is never trusted automatically and never runs on its own — it only ever
executes after an explicit decision, through the exact same waiting/logging
mechanism as a normal approval. Suggesting a safer path doesn't bypass any
of the safety checks already built — it's just a second, safer button
instead of the usual single choice between "run the risky thing" or "do
nothing."

---

## Build phases

This project is built in dependency order — each step produces something
testable before moving to the next. Checked items are done.

The roadmap is split into two halves — not by counting phases evenly, but
by what kind of work each half is. **PPT / midterm presentation: 4 Oct** —
target is to complete all of Half 1 by then.

**Half 1 — the core safety engine, target: 4 Oct**
Everything needed for Checkpoint to genuinely intercept, judge, simulate,
ask, execute, and roll back an action, end to end — plus a safer-alternative
suggestion option, security hardening, automated tests, and an ML-based
fallback classifier.

**Half 2 — intelligence, trust, and polish**
The more open-ended, research-flavored work: recognizing manipulated
actions, learning behavior, hooking into a real agent, building the full
product, and formally proving safety guarantees. Scheduled after the
midterm, with more runway.

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
- [x] 8. "Do this instead" — a third option alongside Approve/Reject. When
      a safer equivalent exists (`git push --force` → `--force-with-lease`;
      permanent delete → move to a local trash folder, fully recoverable),
      it's offered in plain language and runs through the SAME risk
      pipeline — never auto-trusted
- [x] 9. Security hardening — approve/reject/alternative and rollback
      require a real POST request with a CSRF token, not a plain link;
      secure session cookie handling
- [x] 10. Idempotent decision handling — an already-decided action can't
      be flipped by a double-click or a second request

### Phase 3 — Frontend basics (dashboard MVP) ✅ DONE
- [x] 11. Minimal local dashboard (Flask, one page) reading live from
      `storage/checkpoint.db`
- [x] 12. Table view: action, risk tier (color-coded), status — plain
      language, no raw command syntax in the main view
- [x] 13. Auto-refresh so newly logged actions show up without restarting
- [x] 14. Live approve/reject/alternative buttons in the browser
      (pending-state based, instead of a terminal prompt)

### Phase 4 — Sandbox / dry-run engine ✅ DONE
- [x] 15. Shadow-copy affected files before modifying/deleting
- [x] 16. Diff generator — show real outcome, not the raw command
- [x] 17. Wire diff output into the confirmation gate and dashboard

### Phase 5 — Checkpointing and rollback ✅ DONE
- [x] 18. Save pre-state + post-state per executed action — full version
      history, not just "one step back"
- [x] 19. Rollback function — restore any saved checkpoint, forward or back
- [x] 20. Rollback made itself reversible — rolling back snapshots the
      current state first and is logged as a tracked action
- [x] 21. Checkpoints store absolute file paths, so they stay correct even
      if the working directory changes later

### Phase 2A — Automated test suite ✅ DONE, integration pending
- [x] 22. A pytest suite covering the database, dashboard, risk classifier,
      and sandbox
- [x] 23. A documented set of known gaps in the current hardcoded
      classifier (e.g. reordered command flags, chained commands,
      `curl | bash`, `git clean -fdx`, writes to system files, path
      traversal — none currently caught) — a concrete target list for the
      ML classifier
- [ ] 24. Extend the suite to also cover the suggestion feature and the ML
      classifier once built

### Phase 2B — ML-based risk classifier
Hardcoded rules stay authoritative for anything they match (and for every
future formally-verified invariant — only deterministic rules can be
formally proven). The model's job is specifically the known-gap cases above
and anything else unmatched, replacing a blind default with an actual
informed prediction.
- [x] 25. Dataset generator — auto-labels a large set of example commands
      using the existing hardcoded rules (no manual labeling needed);
      currently 115 labeled examples across all three risk tiers
- [ ] 26. Training script — TF-IDF + Logistic Regression (or similar), a
      real train/test split, reported accuracy and a confusion matrix
- [ ] 27. Prediction wrapper — load the trained model, classify a new,
      never-seen command
- [ ] 28. Integration — wire the model in as the fallback for any command
      that doesn't match a hardcoded rule, including the known-gap cases
      above as a real before/after test

### Phase 2C — Final prep
- [ ] 29. Combine the suggestion feature and the security hardening into
      one consistent, fully working set of files — both exist and work
      individually and need to run together
- [ ] 30. Talking-points script covering everything above for a
      non-technical evaluator, rehearsed at least once beforehand

---

### HALF 2 — after the midterm

### Phase 6 — Provenance tracking (prompt-injection defense)
- [ ] 31. Tag each action's origin: user-typed / agent-internal / external-untrusted
- [ ] 32. Feed origin tag into the risk classifier
- [ ] 33. Build a test scenario simulating a prompt-injection attack

### Phase 7 — Anomaly detection
- [ ] 34. Log a behavioral baseline per session
- [ ] 35. Simple statistical anomaly scorer

### Phase 8 — Real agent integration
- [ ] 36. Hook the interceptor into an actual coding agent, via its native
      hook system (confirmed available for Claude Code, Cursor, and
      Antigravity)

### Phase 9 — Full product dashboard + packaging
- [ ] 37. Expand Phase 3's dashboard into the full live-feed + history +
      approvals product view
- [ ] 38. Package as an installable desktop app (Electron/Tauri)

### Phase 10 — Formal policy layer
A small, deliberately named set of 2–3 catastrophic invariants only — not
applied to every HIGH-risk action. Everything else keeps the normal
single-click flow; only this tiny named set gets extra protection.
- [ ] 39. Define the 2–3 critical invariants to protect (candidates: a
      destructive git operation on a protected branch; a write/delete
      outside the project's granted scope)
- [ ] 40. For each one, require a stronger confirmation than a single click
      (e.g. typing the branch name, same pattern GitHub uses for deleting a
      repo) — provably hard to trigger by accident, still fully possible
      for a user who deliberately means it
- [ ] 41. Model the allowed action sequence as a finite-state system and
      verify the defined bad states are unreachable except through that
      stronger confirmation path

### Phase 11 — Polish and final demo prep
- [ ] 42. Stress-test against real, messier agent sessions
- [ ] 43. Build 2–3 demo scenarios (safe cleanup, blocked action, caught injection)

---

## Midterm presentation plan (4 Oct)

**What we demo live:**
- A safe action — runs instantly, shows up as "executed," no interruption
- A risky action — paused, simulated in the sandbox (real outcome shown,
  not raw syntax), resolved live from the dashboard
- "Do this instead" on a risky delete or force-push — the safer path runs
  instead of the dangerous one
- A rollback — undo a previous action using a saved checkpoint, itself
  logged and reversible
- The dashboard itself: plain labels, color-coded risk, readable by someone
  with zero technical background
- *(if Phase 2B finishes in time)* a genuinely novel command, never seen by
  the hardcoded rules, correctly classified by the trained model

**What we say, not demo:** Half 2 — provenance tracking / prompt-injection
defense, anomaly detection, real agent hookup, the full product, and formal
verification — presented as planned next phases with reasoning, not shown
working yet.

---

## Project structure

```
checkpoint/
├── core/
│   ├── interceptor.py       # captures & routes shell/git actions through the pipeline
│   ├── risk_classifier.py   # assigns LOW / MEDIUM / HIGH (hardcoded rules; ML fallback in progress)
│   ├── file_ops.py          # intercepted file operations (create, write, delete, move)
│   ├── confirmation.py      # shared gate: LOW auto-executes; MEDIUM/HIGH go pending for approve/reject/alternative
│   ├── sandbox.py           # shadow-copies files, generates diffs, rollback (self-reversible)
│   ├── suggestions.py       # safer-alternative mapping for "Do this instead"
│   ├── ml_dataset.py        # generates the auto-labeled training set
│   ├── ml_train.py          # [to build] trains the fallback classifier
│   └── ml_classifier.py     # [to build] loads the model, predicts risk for new commands
├── storage/
│   ├── db.py                # SQLite logging + checkpoints table
│   ├── shadow_copies/       # every saved version of every file risky actions have touched
│   ├── trash/                # soft-deleted files from "Do this instead"
│   └── training_data.csv    # auto-labeled ML training examples
├── dashboard/
│   ├── app.py                     # Flask app: live table, approve/reject/alternative, CSRF-protected
│   └── templates/
│       ├── index.html             # main activity dashboard
│       ├── checkpoints.html       # rollback history
│       └── rollback_result.html   # confirms a rollback succeeded/failed
├── tests/                   # pytest suite
│   ├── test_db.py
│   ├── test_dashboard.py
│   ├── test_risk_classifier.py
│   └── test_sandbox.py
├── docs/
│   └── Checkpoint_Synopsis.docx
├── requirements.txt          # flask, pytest, scikit-learn
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
python dashboard/app.py        # terminal 1 — leave running
python core/interceptor.py     # terminal 2 — or core/file_ops.py, or your own test script
```

## Testing

```bash
pytest tests/ -v
```