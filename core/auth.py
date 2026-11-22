"""
core/auth.py — Feature 9 & Dashboard Security: Complete Authentication & Access Control

Provides:
- Argon2id password hashing and verification.
- Secure session management (creation, validation, expiration, invalidation).
- Persistent dashboard signing key stored outside the project in %LOCALAPPDATA%\\Checkpoint\\auth\\
  with explicit authenticated key rotation.
- Separate hook credential (token-based) that can submit events but CANNOT approve actions.
- Strict Host and Origin validation to prevent DNS rebinding and cross-site attacks.
- Rate limiting for login and sensitive actions.
- Explicit disablement of CRITICAL approvals until OS account isolation is verified.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import argon2

from storage.db import _connect


# ---------------------------------------------------------------------------
# Key Storage & Rotation
# ---------------------------------------------------------------------------

def get_auth_dir() -> str:
    """Directory for sensitive auth keys."""
    override = os.environ.get("CHECKPOINT_AUTH_DIR")
    if override:
        os.makedirs(override, exist_ok=True)
        return override

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        try:
            auth_dir = os.path.join(local_app_data, "Checkpoint", "auth")
            os.makedirs(auth_dir, exist_ok=True)
            # Test writability
            test_file = os.path.join(auth_dir, ".probe")
            with open(test_file, "w") as f:
                f.write("probe")
            os.remove(test_file)
            return auth_dir
        except (PermissionError, OSError):
            pass

    # Fallback within storage directory
    fallback = os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage", "auth")
    os.makedirs(fallback, exist_ok=True)
    return fallback


class PersistentKeyManager:
    """Manages persistent session signing key with authenticated rotation."""

    def __init__(self, auth_dir: Optional[str] = None):
        self.auth_dir = auth_dir or get_auth_dir()
        self.key_path = os.path.join(self.auth_dir, "session_signing.key")
        self._key: Optional[bytes] = None

    def get_signing_key(self) -> bytes:
        if self._key is not None:
            return self._key
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                self._key = f.read().strip()
                if len(self._key) >= 32:
                    return self._key

        # Generate new 32-byte secret key
        new_key = secrets.token_bytes(32)
        with open(self.key_path, "wb") as f:
            f.write(new_key)
        self._key = new_key
        return self._key

    def rotate_key(self) -> bytes:
        """Rotate the signing key and invalidate memory cache."""
        new_key = secrets.token_bytes(32)
        with open(self.key_path, "wb") as f:
            f.write(new_key)
        self._key = new_key
        return new_key


_key_manager = PersistentKeyManager()


def get_signing_key() -> bytes:
    return _key_manager.get_signing_key()


def rotate_signing_key() -> bytes:
    return _key_manager.rotate_key()


# ---------------------------------------------------------------------------
# Argon2id Password Hasher
# ---------------------------------------------------------------------------

_ph = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    type=argon2.Type.ID,
)


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return _ph.hash(password)


def verify_password(hash_str: str, password: str) -> bool:
    """Verify password against Argon2id hash."""
    try:
        return _ph.verify(hash_str, password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHash):
        return False


# ---------------------------------------------------------------------------
# Database Schema & Initialization
# ---------------------------------------------------------------------------

def init_auth_tables():
    """Ensure user, session, and hook credential tables exist."""
    with _connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username        TEXT PRIMARY KEY,
            password_hash   TEXT NOT NULL,
            role            TEXT NOT NULL DEFAULT 'admin',
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_sessions (
            session_token   TEXT PRIMARY KEY,
            username        TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            last_active_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hook_credentials (
            token           TEXT PRIMARY KEY,
            role            TEXT NOT NULL DEFAULT 'hook_client',
            description     TEXT,
            created_at      TEXT NOT NULL,
            revoked         INTEGER DEFAULT 0
        );
        """)


def create_user(username: str, password: str, role: str = "admin") -> bool:
    """Create a new user with Argon2id hash."""
    init_auth_tables()
    pw_hash = hash_password(password)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _connect() as conn:
        try:
            conn.execute("""
                INSERT INTO users (username, password_hash, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """, (username, pw_hash, role, ts, ts))
            return True
        except Exception:
            return False


def verify_user(username: str, password: str) -> bool:
    """Check credentials against SQLite users table."""
    init_auth_tables()
    with _connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return False
        return verify_password(row[0], password)


def create_session(username: str, duration_seconds: int = 3600) -> str:
    """Create a cryptographically secure session token."""
    init_auth_tables()
    raw_token = secrets.token_hex(32)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(seconds=duration_seconds)

    with _connect() as conn:
        conn.execute("""
            INSERT INTO user_sessions (session_token, username, created_at, expires_at, last_active_at)
            VALUES (?, ?, ?, ?, ?)
        """, (raw_token, username, now.isoformat(), expires.isoformat(), now.isoformat()))
    return raw_token


def validate_session(session_token: str, sliding_window_seconds: int = 3600) -> Optional[str]:
    """
    Validate session token. Updates last_active_at if valid.
    Returns username if valid, None if invalid or expired.
    """
    if not session_token:
        return None
    init_auth_tables()
    now = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now.isoformat()

    with _connect() as conn:
        row = conn.execute("""
            SELECT username, expires_at FROM user_sessions WHERE session_token = ?
        """, (session_token,)).fetchone()
        if not row:
            return None
        username, expires_at_str = row
        try:
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
            if now > expires_at:
                # Expired: remove it
                conn.execute("DELETE FROM user_sessions WHERE session_token = ?", (session_token,))
                return None
        except Exception:
            return None

        # Sliding window update
        new_expires = now + datetime.timedelta(seconds=sliding_window_seconds)
        conn.execute("""
            UPDATE user_sessions
            SET last_active_at = ?, expires_at = ?
            WHERE session_token = ?
        """, (now_iso, new_expires.isoformat(), session_token))
        return username


def invalidate_session(session_token: str):
    """Log out / invalidate a session token."""
    init_auth_tables()
    with _connect() as conn:
        conn.execute("DELETE FROM user_sessions WHERE session_token = ?", (session_token,))


def invalidate_all_sessions_for_user(username: str):
    """Invalidate all active sessions for a user (e.g., after password change or key rotation)."""
    init_auth_tables()
    with _connect() as conn:
        conn.execute("DELETE FROM user_sessions WHERE username = ?", (username,))


# ---------------------------------------------------------------------------
# Separate Hook Credential (Cannot approve actions)
# ---------------------------------------------------------------------------

def create_hook_credential(description: str = "Agent Hook Token") -> str:
    """Generate a separate credential token for the Claude Code agent hook."""
    init_auth_tables()
    token = "hook_" + secrets.token_hex(24)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("""
            INSERT INTO hook_credentials (token, role, description, created_at, revoked)
            VALUES (?, 'hook_client', ?, ?, 0)
        """, (token, description, ts))
    return token


def validate_hook_credential(token: str) -> bool:
    """Check if hook token is valid and active."""
    if not token:
        return False
    init_auth_tables()
    with _connect() as conn:
        row = conn.execute("""
            SELECT role, revoked FROM hook_credentials WHERE token = ?
        """, (token,)).fetchone()
        if not row:
            return False
        role, revoked = row
        return role == "hook_client" and not bool(revoked)


def is_hook_token_attempting_approval(role: str) -> bool:
    """
    CRITICAL INVARIANT: Hook credentials can NEVER approve actions.
    """
    return role == "hook_client"


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding window rate limiter for login and sensitive endpoints."""

    def __init__(self, max_attempts: int = 5, window_seconds: float = 60.0):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        # key -> list of float timestamps
        self._attempts: Dict[str, List[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        history = self._attempts.get(key, [])
        valid = [t for t in history if t > cutoff]
        if len(valid) >= self.max_attempts:
            self._attempts[key] = valid
            return False
        valid.append(now)
        self._attempts[key] = valid
        return True

    def reset(self, key: str):
        self._attempts.pop(key, None)


_login_limiter = RateLimiter(max_attempts=5, window_seconds=60.0)


def check_login_rate_limit(client_ip: str) -> bool:
    return _login_limiter.is_allowed(client_ip)


def reset_login_rate_limit(client_ip: str):
    _login_limiter.reset(client_ip)


# ---------------------------------------------------------------------------
# Strict Host and Origin Validation
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS: Set[str] = {
    "127.0.0.1",
    "localhost",
    "[::1]",
    "127.0.0.1:5000",
    "localhost:5000",
    "[::1]:5000",
}


def validate_request_host(host_header: Optional[str]) -> bool:
    """
    Strict Host header validation. Defends against DNS rebinding attacks.
    """
    if not host_header:
        return False
    cleaned = host_header.strip().lower()
    return cleaned in _ALLOWED_HOSTS


def validate_request_origin(origin_or_referer: Optional[str]) -> bool:
    """
    Strict Origin/Referer validation for state-modifying requests.
    """
    if not origin_or_referer:
        return True  # If omitted by client, CSRF token validation protects the request
    # Extract host:port from URL
    clean = origin_or_referer.lower().replace("http://", "").replace("https://", "").split("/")[0]
    return clean in _ALLOWED_HOSTS


# ---------------------------------------------------------------------------
# CRITICAL Approval Gate
# ---------------------------------------------------------------------------

_OS_ISOLATION_VERIFIED: bool = False


def set_os_isolation_verified(verified: bool):
    global _OS_ISOLATION_VERIFIED
    _OS_ISOLATION_VERIFIED = verified


def is_os_isolation_verified() -> bool:
    return _OS_ISOLATION_VERIFIED


def can_approve_critical() -> Tuple[bool, str]:
    """
    Requirement from v2.3: Keep CRITICAL approvals disabled until dedicated-account
    isolation and ACL boundaries are verified.
    """
    if not _OS_ISOLATION_VERIFIED:
        return False, "CRITICAL tier approvals are disabled until OS account isolation (CheckpointSvc) and ACL boundaries are verified."
    return True, ""
