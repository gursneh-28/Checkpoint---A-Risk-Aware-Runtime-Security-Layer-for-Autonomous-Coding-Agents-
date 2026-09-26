import sqlite3
import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "checkpoint.db")


def init_db():
    """Create the actions table if it doesn't exist yet. Safe to call every run."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action_type TEXT NOT NULL,      -- 'shell', 'file', 'git'
            command TEXT NOT NULL,
            risk_tier TEXT NOT NULL,        -- 'LOW', 'MEDIUM', 'HIGH'
            status TEXT NOT NULL,           -- 'executed', 'blocked', 'rejected', 'pending', 'approved'
            output TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_action(action_type: str, command: str, risk_tier: str, status: str, output: str = ""):
    """Insert one FINAL action record (used for LOW-tier auto-executed actions)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO actions (timestamp, action_type, command, risk_tier, status, output)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.datetime.now().isoformat(),
        action_type,
        command,
        risk_tier,
        status,
        output
    ))
    conn.commit()
    conn.close()


def log_pending_action(action_type: str, command: str, risk_tier: str) -> int:
    """
    Insert a MEDIUM/HIGH action as 'pending' — it does NOT execute yet.
    Returns the new row's id, so the caller can poll for a decision on it.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO actions (timestamp, action_type, command, risk_tier, status, output)
        VALUES (?, ?, ?, ?, 'pending', '')
    """, (
        datetime.datetime.now().isoformat(),
        action_type,
        command,
        risk_tier,
    ))
    conn.commit()
    action_id = cursor.lastrowid
    conn.close()
    return action_id


def get_action_status(action_id: int) -> str:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM actions WHERE id = ?", (action_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def set_action_status(action_id: int, status: str, output: str = ""):
    """Used both by the dashboard (approve/reject clicks) and by the interceptor
    (updating 'approved' -> 'executed' once the action actually runs)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if output:
        cursor.execute("UPDATE actions SET status = ?, output = ? WHERE id = ?", (status, output, action_id))
    else:
        cursor.execute("UPDATE actions SET status = ? WHERE id = ?", (status, action_id))
    conn.commit()
    conn.close()


def get_all_actions():
    """Return every logged action, most recent first."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM actions ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    init_db()
    log_action("shell", "echo test", "LOW", "executed", "test output")
    print("DB initialized and test row inserted. Current rows:")
    for row in get_all_actions():
        print(row)