import sqlite3
import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "checkpoint.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action_type TEXT NOT NULL,
            command TEXT NOT NULL,
            risk_tier TEXT NOT NULL,
            status TEXT NOT NULL,
            output TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS checkpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            file_path TEXT NOT NULL,
            snapshot_path TEXT NOT NULL,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_action(action_type: str, command: str, risk_tier: str, status: str, output: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO actions (timestamp, action_type, command, risk_tier, status, output)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.datetime.now().isoformat(), action_type, command, risk_tier, status, output))
    conn.commit()
    conn.close()


def log_pending_action(action_type: str, command: str, risk_tier: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO actions (timestamp, action_type, command, risk_tier, status, output)
        VALUES (?, ?, ?, ?, 'pending', '')
    """, (datetime.datetime.now().isoformat(), action_type, command, risk_tier))
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if output:
        cursor.execute("UPDATE actions SET status = ?, output = ? WHERE id = ?", (status, output, action_id))
    else:
        cursor.execute("UPDATE actions SET status = ? WHERE id = ?", (status, action_id))
    conn.commit()
    conn.close()


def get_all_actions():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM actions ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


# ---------- Checkpoints (Phase 5) ----------

def record_checkpoint(file_path: str, snapshot_path: str, description: str = "") -> int:
    """Records that 'snapshot_path' holds a saved copy of 'file_path' as it
    looked right before a risky action touched it."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO checkpoints (timestamp, file_path, snapshot_path, description)
        VALUES (?, ?, ?, ?)
    """, (datetime.datetime.now().isoformat(), file_path, snapshot_path, description))
    conn.commit()
    checkpoint_id = cursor.lastrowid
    conn.close()
    return checkpoint_id


def get_all_checkpoints():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM checkpoints ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_checkpoint(checkpoint_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM checkpoints WHERE id = ?", (checkpoint_id,))
    row = cursor.fetchone()
    conn.close()
    return row

if __name__ == "__main__":
    init_db()
    log_action("shell", "echo test", "LOW", "executed", "test output")
    print("DB initialized and test row inserted. Current rows:")
    for row in get_all_actions():
        print(row)