# Checkpoint

### A runtime security layer for autonomous coding agents

## Overview

Autonomous coding agents can issue commands that modify files, repositories, or system state. Checkpoint intercepts supported agent actions and evaluates their risk before execution, allowing review of elevated-risk actions and recording decisions for audit.

## Key Features

- Runtime command interception through agent adapters and hooks.
- Rules-first risk classification with an ML fallback.
- Human approval and rejection workflow for elevated-risk actions.
- Plain-language explanations and impact previews for supported command families; unrecognized commands are shown as unknown rather than guessed.
- Safer alternative suggestions for selected risky commands.
- File snapshots, version history, conflict checks, and restore support, subject to configured storage and recovery paths.
- Provenance tracking and append-only audit logging.
- Rules-based anomaly signals and circuit-breaker checks.
- Git safety checks and backup mechanisms for selected destructive operations.

## Architecture

Agent command → Checkpoint interception → Risk analysis → Approval or safer alternative → Execution decision and audit logging.

## Technology Stack

Python, Flask, SQLite, bashlex, scikit-learn, argon2-cffi, and cryptography. Git and PowerShell support repository safety and Windows security setup.

## Setup and Running

From Windows PowerShell:

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:CHECKPOINT_DEV_MODE = "1"
python -m flask --app dashboard.app run --host=127.0.0.1 --port=5000
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Development mode uses workspace storage; production storage requires the Windows security setup.

## Testing

Run the suite with:

```powershell
$env:CHECKPOINT_DEV_MODE = "1"
.\venv\Scripts\python.exe -m pytest tests/ -v
```

The recorded passing baseline is **226 passed, 5 skipped**. Four skipped integration tests require elevated security setup; one covers non-Windows DPAPI behavior.
