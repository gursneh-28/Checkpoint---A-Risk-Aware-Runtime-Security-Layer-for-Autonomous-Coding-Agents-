"""
Windows path normalization for Checkpoint.

Handles: C:\\..., /c/... (Git Bash), UNC \\\\server\\share paths.
Explicitly does NOT handle: WSL /mnt/c (different namespace),
reparse points, symlink ancestors, hard links — those return UNKNOWN.

The design doc requires one tested module for all path forms.  Every
other module (classifier, preview, sandbox) imports from here.
"""
from __future__ import annotations

import os
import re
import sys
from enum import Enum
from typing import Optional, Tuple


class PathKind(str, Enum):
    WINDOWS_ABSOLUTE = "windows_absolute"   # C:\\foo
    GIT_BASH_DRIVE   = "git_bash_drive"     # /c/foo
    UNC              = "unc"                 # \\server\share
    WSL_MOUNT        = "wsl_mount"          # /mnt/c/foo  — different namespace, NOT git bash
    POSIX_ABSOLUTE   = "posix_absolute"     # /usr/bin/...
    RELATIVE         = "relative"
    UNKNOWN          = "unknown"


# Regexes
_WIN_ABS_RE   = re.compile(r'^([A-Za-z]):[/\\]')
_GIT_BASH_RE  = re.compile(r'^/([A-Za-z])(/|$)')
_UNC_RE       = re.compile(r'^\\\\[^\\]+\\[^\\]+')
_WSL_MOUNT_RE = re.compile(r'^/mnt/([A-Za-z])(/|$)')


# Sensitive files / directories that the classifier uses
_SENSITIVE_NAMES = frozenset([
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".ssh", "credentials", "aws_access_key", "aws_secret",
    ".netrc", ".pgpass", "private_key", "secret_key",
    "token", "api_key", "passwd", "shadow",
])

_SENSITIVE_EXTENSIONS = frozenset([
    ".pem", ".p12", ".pfx", ".key", ".ppk",
])

_REGEN_FOLDER_NAMES = frozenset([
    "node_modules", ".venv", "venv", "__pycache__",
    "build", "dist", ".next", ".nuxt", "target",
])


def detect_kind(path: str) -> PathKind:
    """Classify the syntactic form of a path."""
    if _WSL_MOUNT_RE.match(path):
        return PathKind.WSL_MOUNT
    if _WIN_ABS_RE.match(path):
        return PathKind.WINDOWS_ABSOLUTE
    if _GIT_BASH_RE.match(path):
        return PathKind.GIT_BASH_DRIVE
    if _UNC_RE.match(path):
        return PathKind.UNC
    if path.startswith("/"):
        return PathKind.POSIX_ABSOLUTE
    if re.match(r'^[A-Za-z]:', path):
        return PathKind.WINDOWS_ABSOLUTE
    return PathKind.RELATIVE


def to_windows_absolute(path: str, cwd: str = "") -> Optional[str]:
    """
    Convert any supported path form to a Windows absolute path string.
    Returns None when the path is WSL, an unsupported form, or cannot be resolved.
    """
    kind = detect_kind(path)

    if kind == PathKind.WSL_MOUNT:
        # WSL is a different namespace from Git Bash — do not silently convert
        return None

    if kind == PathKind.WINDOWS_ABSOLUTE:
        return os.path.normpath(path)

    if kind == PathKind.GIT_BASH_DRIVE:
        # /c/foo/bar → C:\foo\bar
        m = _GIT_BASH_RE.match(path)
        drive = m.group(1).upper()
        rest = path[len(m.group(0)) - 1:]  # keep the leading slash equivalent
        rest = rest.replace("/", "\\")
        return f"{drive}:{rest}"

    if kind == PathKind.UNC:
        return os.path.normpath(path)

    if kind == PathKind.RELATIVE:
        base = cwd if cwd else os.getcwd()
        return os.path.normpath(os.path.join(base, path))

    if kind == PathKind.POSIX_ABSOLUTE:
        # Bare /usr/bin on a Windows host — treat as unknown on Windows
        return None

    return None


def is_sensitive_path(path: str, cwd: str = "") -> bool:
    """
    Return True when the path name, extension, or any ancestor segment
    matches a known sensitive file / directory pattern.
    """
    win = to_windows_absolute(path, cwd) or path
    parts = re.split(r'[/\\]', win.lower())
    for part in parts:
        name, ext = os.path.splitext(part)
        if name in _SENSITIVE_NAMES or part in _SENSITIVE_NAMES:
            return True
        if ext in _SENSITIVE_EXTENSIONS:
            return True
    return False


def is_regenerable_folder(path: str) -> Tuple[bool, str]:
    """
    Return (True, reason) when the final path segment is a known regenerable
    folder name AND a qualifying lockfile/manifest exists alongside it.
    Otherwise return (False, "").

    The design doc says: exemption only when "a recognized lockfile or manifest
    exists and the preview says 'regenerable, not backed up'".
    """
    norm = to_windows_absolute(path) or path
    folder_name = os.path.basename(norm.rstrip("/\\")).lower()
    if folder_name not in _REGEN_FOLDER_NAMES:
        return False, ""

    # Check for a qualifying lockfile/manifest in the parent directory
    parent = os.path.dirname(norm)
    lockfiles = [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",  # node_modules
        "requirements.txt", "Pipfile.lock", "pyproject.toml",  # venv
        "Cargo.lock", "go.sum", "composer.lock",
    ]
    for lf in lockfiles:
        if os.path.isfile(os.path.join(parent, lf)):
            return True, f"lockfile '{lf}' found alongside '{folder_name}'"

    return False, ""


def is_inside_project(path: str, project_root: str, cwd: str = "") -> bool:
    """Return True when path is under project_root (after canonicalization)."""
    abs_path = to_windows_absolute(path, cwd)
    if abs_path is None:
        return False
    try:
        norm_path   = os.path.normcase(os.path.realpath(abs_path))
        norm_root   = os.path.normcase(os.path.realpath(project_root))
    except (OSError, ValueError):
        return False
    return norm_path.startswith(norm_root + os.sep) or norm_path == norm_root


def redact_path(path: str) -> str:
    """Replace the user home directory prefix with <home> for logging."""
    try:
        home = os.path.expanduser("~")
        abs_p = to_windows_absolute(path) or path
        if os.path.normcase(abs_p).startswith(os.path.normcase(home)):
            return "<home>" + abs_p[len(home):]
    except Exception:
        pass
    return path
