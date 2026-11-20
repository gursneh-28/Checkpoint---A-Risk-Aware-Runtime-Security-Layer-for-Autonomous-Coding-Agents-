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
Provenance Tracker (where did this action's justification come from?)   [Half 2]
        ↓
Risk Classifier (LOW / MEDIUM / HIGH — hardcoded rules first, trained ML model as fallback)
        ↓
   ┌────────────┬─────────────────┬──────────────────┐
  LOW          MEDIUM             HIGH
   ↓             ↓                  ↓
Auto-execute   Sandbox/dry-run   Sandbox/dry-run + Anomaly check [Half 2]
   ↓             ↓                  ↓
Checkpoint    ────────→  Dashboard (shows outcome, not raw command)
   store                        ↓
                    Approve / Reject / "Do this instead"
                                ↓
              Execute + new checkpoint  /  Reject, logged  /  Safer alternative run
```

## Build phases

**Half 1 — the core safety engine**
Everything needed for Checkpoint to genuinely intercept, judge, simulate,
ask, execute, and roll back an action, end to end — plus a safer-alternative
suggestion option, security hardening, automated tests, and an ML-based
fallback classifier.

**Half 2 — intelligence, trust, and polish**
The more open-ended, research-flavored work: recognizing manipulated
actions, learning behavior, hooking into a real agent, building the full
product, and formally proving safety guarantees.

---

### HALF 1

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
      `git reset --hard` → `git stash`; permanent delete → move to a local
      trash folder, fully recoverable), it's offered in plain language and
      only runs after an explicit decision — never auto-trusted
- [x] 9. Security hardening — approve/reject/alternative and rollback
      require a real POST request with a CSRF token, not a plain link;
      secure session cookie handling
- [x] 10. Idempotent decision handling — an already-decided action can't
      be flipped by a double-click or a second request (covers `alternative`
      too)

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

### Phase 2A — Automated test suite ✅ DONE
- [x] 22. A pytest suite covering the database, dashboard, risk classifier,
      and sandbox
- [x] 23. A documented set of known gaps in the hardcoded classifier
      (reordered command flags, chained commands, `curl | bash`,
      `git clean -fdx`, writes to system files, path traversal) — the target
      list for the ML classifier and new rules
- [x] 24. Extended the suite to cover the suggestion feature, the
      confirmation gate (approve / reject / alternative), the database's
      suggestion handling, and the ML classifier (rules-first ordering,
      model fallback, known-gap before/after cases)

### Phase 2B — ML-based risk classifier ✅ DONE
Hardcoded rules stay authoritative for anything they match (and for every
future formally-verified invariant — only deterministic rules can be
formally proven). The model's job is specifically the unmatched cases,
replacing a blind default with an informed prediction.
- [x] 25. Dataset generator — labels a large set of example commands using
      the hardcoded rules only (never the model), plus a small hand-labeled
      set for commands no rule covers; currently 230 labeled examples
      across all three risk tiers
- [x] 26. Training script — TF-IDF + Logistic Regression, a real
      train/test split, reported accuracy and confusion matrix
- [x] 27. Prediction wrapper — loads the trained model and classifies a
      new, never-seen command; fails safe to MEDIUM if the model or
      scikit-learn is missing
- [x] 28. Integration — the model is the fallback for any command that
      doesn't match a hardcoded rule. Before/after results on the known
      gaps: `rm -fr`, `rm -r -f`, `curl | bash` and writes into `/etc` are
      now caught by new deterministic rules; `git clean -fdx`,
      `chmod -R 777`, `find -delete` and `git -C ... push --force` are
      handled by the model (result can vary between retrains)

### Phase 2C — Final prep ✅ DONE
- [x] 29. Suggestion feature and security hardening combined into one
      consistent set of files: suggestions stored with the pending action,
      a CSRF-protected "Do this instead" button, and the confirmation gate
      executing the safer action only after an explicit decision

---

### HALF 2

### Phase 6 — Provenance tracking (prompt-injection defense)
- [ ] 30. Tag each action's origin: user-typed / agent-internal / external-untrusted
- [ ] 31. Feed origin tag into the risk classifier
- [ ] 32. Build a test scenario simulating a prompt-injection attack

### Phase 7 — Anomaly detection
- [ ] 33. Log a behavioral baseline per session
- [ ] 34. Simple statistical anomaly scorer

### Phase 8 — Real agent integration
- [ ] 35. Hook the interceptor into an actual coding agent, via its native
      hook system (confirmed available for Claude Code, Cursor, and
      Antigravity)

### Phase 9 — Full product dashboard + packaging
- [ ] 36. Expand Phase 3's dashboard into the full live-feed + history +
      approvals product view
- [ ] 37. Package as an installable desktop app (Electron/Tauri)

### Phase 10 — Formal policy layer
A small, deliberately named set of 2–3 catastrophic invariants only — not
applied to every HIGH-risk action. Everything else keeps the normal
single-click flow; only this tiny named set gets extra protection.
- [ ] 38. Define the 2–3 critical invariants to protect (candidates: a
      destructive git operation on a protected branch; a write/delete
      outside the project's granted scope)
- [ ] 39. For each one, require a stronger confirmation than a single click
      (e.g. typing the branch name, same pattern GitHub uses for deleting a
      repo) — provably hard to trigger by accident, still fully possible
      for a user who deliberately means it
- [ ] 40. Model the allowed action sequence as a finite-state system and
      verify the defined bad states are unreachable except through that
      stronger confirmation path

### Phase 11 — Polish and final demo prep
- [ ] 41. Stress-test against real, messier agent sessions
- [ ] 42. Build 2–3 demo scenarios (safe cleanup, blocked action, caught injection)

---

## Project structure

```
checkpoint/
├── core/
│   ├── interceptor.py       # captures & routes shell/git actions through the pipeline
│   ├── risk_classifier.py   # assigns LOW / MEDIUM / HIGH (hardcoded rules first, ML fallback)
│   ├── file_ops.py          # intercepted file operations (create, write, delete, move)
│   ├── confirmation.py      # shared gate: LOW auto-executes; MEDIUM/HIGH go pending for approve/reject/alternative
│   ├── sandbox.py           # shadow-copies files, generates diffs, rollback (self-reversible)
│   ├── suggestions.py       # safer-alternative mapping + soft-delete to trash for "Do this instead"
│   ├── ml_dataset.py        # generates the labeled training set (rule-labeled + hand-labeled)
│   ├── ml_train.py          # trains the fallback classifier, prints accuracy + confusion matrix
│   └── ml_classifier.py     # loads the model, predicts risk for new commands (fails safe to MEDIUM)
├── storage/
│   ├── db.py                # SQLite logging, suggestions, decisions, checkpoints table
│   ├── shadow_copies/       # every saved version of every file risky actions have touched
│   ├── trash/               # soft-deleted files from "Do this instead"
│   ├── training_data.csv    # labeled ML training examples
│   └── risk_model.pkl       # trained fallback model (regenerate with core/ml_train.py)
├── dashboard/
│   ├── app.py                     # Flask app: live table, approve/reject/alternative, CSRF-protected
│   └── templates/
│       ├── index.html             # main activity dashboard (with suggestion box + "Do this instead")
│       ├── checkpoints.html       # rollback history
│       └── rollback_result.html   # confirms a rollback succeeded/failed
├── tests/                   # pytest suite
│   ├── test_db.py
│   ├── test_db_suggestions.py     # suggestion storage, 'alternative' decision rules, DB upgrade
│   ├── test_confirmation.py       # approve / reject / alternative through the gate
│   ├── test_dashboard.py
│   ├── test_risk_classifier.py
│   ├── test_ml_classifier.py      # rules-first ordering, model fallback, known-gap cases
│   ├── test_suggestions.py        # safer-alternative mapping and trash behaviour
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

The trained model (`storage/risk_model.pkl`) is included. To regenerate the
dataset and retrain it:

```bash
python core/ml_dataset.py      # writes storage/training_data.csv
python core/ml_train.py        # trains, prints accuracy + confusion matrix, saves the model
```

## Running

```bash
python dashboard/app.py        # terminal 1 — leave running (restart it after code changes)
python core/interceptor.py     # terminal 2 — or core/file_ops.py, or your own test script
```

Run the interceptor from a scratch git repo, not a real project, since
approving the force-push demo runs a real `git push --force`.

## Testing

```bash
python -m pytest tests/ -v
```