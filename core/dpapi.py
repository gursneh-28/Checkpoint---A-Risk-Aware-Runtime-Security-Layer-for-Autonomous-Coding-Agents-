
"""
core/dpapi.py - Windows DPAPI wrapper for Checkpoint.

Uses CryptProtectData / CryptUnprotectData with CurrentUser scope.
Production secrets must be encrypted and decrypted by the CheckpointSvc
Windows account. This module does not itself create that account or enforce
the process identity.

Decryption failures must fail closed. Never fall back to plaintext.
"""

from __future__ import annotations
import time
import ctypes
import ctypes.wintypes
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

_WINDOWS = sys.platform == "win32"

# Do not change after deployment. Changing this invalidates existing blobs.
_CHECKPOINT_ENTROPY = b"Checkpoint-v2.3-ACL-DPAPI-scope-2026"

_CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DpapiUnavailableError(RuntimeError):
    """Raised when DPAPI is called on a non-Windows platform."""


class DpapiDecryptionError(ValueError):
    """Raised when DPAPI decryption fails."""


class DpapiEncryptionError(ValueError):
    """Raised when DPAPI encryption fails."""


if _WINDOWS:
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    _crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.wintypes.LPCWSTR,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = ctypes.wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.POINTER(ctypes.wintypes.LPWSTR),
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = ctypes.wintypes.BOOL

    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p


def is_available() -> bool:
    """Return True when Windows DPAPI is available."""
    return _WINDOWS


def _make_blob(data: bytes):
    """Create a DATA_BLOB and retain its backing buffer."""
    if not isinstance(data, bytes):
        raise TypeError("DPAPI input must be bytes")

    # Windows DPAPI requires a valid pointer even when cbData is zero.
    # Allocate one backing byte for empty input, but keep the actual length 0.
    buffer_size = max(1, len(data))
    buffer = (ctypes.c_ubyte * buffer_size)()

    if data:
        ctypes.memmove(buffer, data, len(data))

    pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    blob = _DATA_BLOB(len(data), pointer)

    return blob, buffer


def _free_local(pointer) -> None:
    """Free a pointer allocated by a Windows LocalAlloc-based API."""
    address = ctypes.cast(pointer, ctypes.c_void_p).value
    if address:
        _kernel32.LocalFree(ctypes.c_void_p(address))


def encrypt(plaintext: bytes, description: str = "Checkpoint") -> bytes:
    """
    Encrypt bytes using DPAPI CurrentUser scope.

    The calling Windows user profile determines who can decrypt the result.
    """
    if not _WINDOWS:
        raise DpapiUnavailableError("DPAPI is only available on Windows")

    if not isinstance(description, str):
        raise TypeError("description must be a string")

    input_blob, input_buffer = _make_blob(plaintext)
    entropy_blob, entropy_buffer = _make_blob(_CHECKPOINT_ENTROPY)
    output_blob = _DATA_BLOB()

    try:
        success = _crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            description,
            ctypes.byref(entropy_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )

        if not success:
            error = ctypes.get_last_error()
            raise DpapiEncryptionError(
                f"CryptProtectData failed: Windows error {error:#010x}"
            )

        return ctypes.string_at(output_blob.pbData, output_blob.cbData)

    finally:
        if output_blob.pbData:
            _free_local(output_blob.pbData)


def decrypt(ciphertext: bytes) -> bytes:
    """
    Decrypt a DPAPI blob under the same Windows user profile.

    Wrong-user, corrupt, and tampered ciphertext must raise an error.
    """
    if not _WINDOWS:
        raise DpapiUnavailableError("DPAPI is only available on Windows")

    input_blob, input_buffer = _make_blob(ciphertext)
    entropy_blob, entropy_buffer = _make_blob(_CHECKPOINT_ENTROPY)
    output_blob = _DATA_BLOB()
    description_ptr = ctypes.wintypes.LPWSTR()

    try:
        success = _crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            ctypes.byref(description_ptr),
            ctypes.byref(entropy_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )

        if not success:
            error = ctypes.get_last_error()

            if error == 0x8009000B:
                message = "DPAPI decryption failed: NTE_BAD_KEY_STATE"
            elif error == 0x80090005:
                message = "DPAPI decryption failed: NTE_BAD_DATA"
            else:
                message = (
                    f"CryptUnprotectData failed: Windows error {error:#010x}"
                )

            raise DpapiDecryptionError(message)

        return ctypes.string_at(output_blob.pbData, output_blob.cbData)

    finally:
        if output_blob.pbData:
            _free_local(output_blob.pbData)

        if description_ptr:
            _free_local(description_ptr)


def protect_file(plaintext: bytes, path: os.PathLike[str] | str) -> None:
    """
    Encrypt bytes and atomically replace the destination file.

    Each writer gets a unique temporary file. Transient Windows sharing
    conflicts during replacement are retried a limited number of times.
    """
    destination = Path(path)
    ciphertext = encrypt(plaintext)

    temporary_path: Optional[str] = None

    try:
        fd, temporary_path = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".dpapi.tmp",
            dir=str(destination.parent),
        )

        with os.fdopen(fd, "wb") as temporary_file:
            temporary_file.write(ciphertext)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        for attempt in range(8):
            try:
                os.replace(temporary_path, destination)
                temporary_path = None
                break

            except PermissionError as exc:
                # Windows: access denied, sharing violation, or lock violation.
                # Retry only these known transient errors.
                transient_errors = {5, 32, 33}

                if (
                    not _WINDOWS
                    or getattr(exc, "winerror", None) not in transient_errors
                    or attempt == 7
                ):
                    raise

                time.sleep(0.01 * (2 ** attempt))

    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def unprotect_file(path: os.PathLike[str] | str) -> bytes:
    """Read and decrypt a DPAPI-protected file."""
    ciphertext = Path(path).read_bytes()
    return decrypt(ciphertext)


class _DevModeStub:
    """
    Base64 development stub.

    This is NOT encryption and MUST NOT be used for production secrets.
    """

    def encrypt(self, plaintext: bytes, description: str = "") -> bytes:
        import base64

        if not isinstance(plaintext, bytes):
            raise TypeError("DPAPI input must be bytes")

        return b"DEVMODE:" + base64.b64encode(plaintext)

    def decrypt(self, data: bytes) -> bytes:
        import base64

        if not data.startswith(b"DEVMODE:"):
            raise DpapiDecryptionError("Not a dev-mode plaintext blob")

        try:
            return base64.b64decode(data[8:], validate=True)
        except Exception as exc:
            raise DpapiDecryptionError(
                "Invalid dev-mode ciphertext"
            ) from exc


_dev_stub = _DevModeStub()


def get_dev_stub() -> _DevModeStub:
    """Return the non-production development stub."""
    return _dev_stub
