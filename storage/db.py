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
            status TEXT NOT NULL,           -- 'executed', 'blocked', 'rejected'
            output TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_action(action_type: str, command: str, risk_tier: str, status: str, output: str = ""):
    """Insert one action record. Called for every intercepted action, no exceptions."""
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


def get_all_actions():
    """Return every logged action, most recent first. Used later by the dashboard."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM actions ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    # Quick manual test: run this file directly to verify the DB layer works.
    init_db()
    log_action("shell", "echo test", "LOW", "executed", "test output")
    print("DB initialized and test row inserted. Current rows:")
    for row in get_all_actions():
        print(row)