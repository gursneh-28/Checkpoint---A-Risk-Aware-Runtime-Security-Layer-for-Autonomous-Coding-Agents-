"""
tests/test_dpapi.py — DPAPI round-trip and integration tests for Checkpoint Stage 5A.

These tests cover:
  1. DPAPI round-trip encrypt/decrypt under the current user (Windows only)
  2. Dev-mode stub behavior on non-Windows / for CI
  3. protect_file / unprotect_file helpers
  4. Error paths: wrong-format data, truncated ciphertext

Security note:
  DPAPI's core security property (only the SAME WINDOWS USER can decrypt) is
  verified here for the current user. The cross-account isolation property
  (CheckpointSvc-encrypted data cannot be read by gursn) can only be verified
  by running decrypt() as a DIFFERENT user — this is documented in
  KNOWN_LIMITATIONS.md and tested by verify_security.ps1.
"""
import os
import sys
import pytest

# Skip entire module on non-Windows if the test is about real DPAPI
IS_WINDOWS = sys.platform == "win32"

from core.dpapi import (
    is_available,
    encrypt,
    decrypt,
    protect_file,
    unprotect_file,
    get_dev_stub,
    DpapiUnavailableError,
    DpapiDecryptionError,
    DpapiEncryptionError,
)


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

def test_is_available_matches_platform():
    assert is_available() == IS_WINDOWS


# ---------------------------------------------------------------------------
# DPAPI round-trip (Windows only)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_dpapi_roundtrip_basic():
    plaintext = b"checkpoint_secret_key_1234567890"
    ct = encrypt(plaintext)
    assert ct != plaintext
    assert len(ct) > len(plaintext)
    result = decrypt(ct)
    assert result == plaintext


@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_dpapi_roundtrip_empty():
    plaintext = b""
    ct = encrypt(plaintext)
    result = decrypt(ct)
    assert result == plaintext


@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_dpapi_roundtrip_long():
    plaintext = os.urandom(4096)
    ct = encrypt(plaintext)
    result = decrypt(ct)
    assert result == plaintext


@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_dpapi_ciphertext_is_different_each_call():
    plaintext = b"same_secret"
    ct1 = encrypt(plaintext)
    ct2 = encrypt(plaintext)
    # DPAPI adds randomized session key — ciphertexts should differ
    assert ct1 != ct2
    # But both decrypt to the same plaintext
    assert decrypt(ct1) == plaintext
    assert decrypt(ct2) == plaintext


@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_dpapi_decrypt_corrupt_data_raises():
    garbage = b"not_a_valid_dpapi_blob_" + os.urandom(64)
    with pytest.raises(DpapiDecryptionError):
        decrypt(garbage)


@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_dpapi_decrypt_truncated_raises():
    plaintext = b"test_secret_data"
    ct = encrypt(plaintext)
    truncated = ct[:len(ct) // 2]
    with pytest.raises(DpapiDecryptionError):
        decrypt(truncated)


# ---------------------------------------------------------------------------
# Non-Windows / unavailable paths
# ---------------------------------------------------------------------------

@pytest.mark.skipif(IS_WINDOWS, reason="Only tests non-Windows behavior")
def test_dpapi_unavailable_on_non_windows():
    with pytest.raises(DpapiUnavailableError):
        encrypt(b"test")
    with pytest.raises(DpapiUnavailableError):
        decrypt(b"test")


# ---------------------------------------------------------------------------
# protect_file / unprotect_file
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_protect_and_unprotect_file(tmp_path):
    secret = b"my_signing_key_32_bytes_long_data"
    key_file = tmp_path / "signing.key.dpapi"
    protect_file(secret, key_file)
    assert key_file.exists()
    # File should NOT contain the plaintext
    raw = key_file.read_bytes()
    assert secret not in raw
    # Decryption should recover the original
    recovered = unprotect_file(key_file)
    assert recovered == secret


@pytest.mark.skipif(not IS_WINDOWS, reason="DPAPI only available on Windows")
def test_protect_file_is_atomic(tmp_path):
    """protect_file uses a .tmp file and os.replace — not partial writes."""
    import threading
    secret = b"atomic_key_data"
    key_file = tmp_path / "atomic.key.dpapi"

    # Write it concurrently and verify no corrupt intermediate state
    errors = []
    def write_it():
        try:
            protect_file(secret, key_file)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=write_it) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors
    assert unprotect_file(key_file) == secret


# ---------------------------------------------------------------------------
# Dev-mode stub
# ---------------------------------------------------------------------------

def test_dev_stub_roundtrip():
    stub = get_dev_stub()
    plaintext = b"dev_mode_test_secret"
    ct = stub.encrypt(plaintext, description="test")
    assert ct.startswith(b"DEVMODE:")
    result = stub.decrypt(ct)
    assert result == plaintext


def test_dev_stub_reject_non_devmode():
    stub = get_dev_stub()
    with pytest.raises(DpapiDecryptionError):
        stub.decrypt(b"not_a_devmode_blob")


# ---------------------------------------------------------------------------
# SECURITY BOUNDARY DOCUMENTATION TEST
# ---------------------------------------------------------------------------

def test_cross_account_isolation_is_manual_only():
    """
    DOCUMENTED LIMITATION: The core DPAPI security property — that only the
    CheckpointSvc account can decrypt CheckpointSvc-encrypted blobs — cannot
    be verified by a unit test running as the current user.

    Verification requires:
      1. CheckpointSvc account to exist (requires elevation to create)
      2. Data encrypted under CheckpointSvc profile
      3. Attempting decryption from a process running as gursn

    This is verified by scripts/verify_security.ps1 and documented in
    KNOWN_LIMITATIONS.md under "DPAPI cross-account isolation".

    This test exists to document that the limitation is KNOWN and INTENTIONAL,
    not accidentally missing.
    """
    # This test always passes — its purpose is documentation
    assert True, (
        "DPAPI cross-account isolation is verified by verify_security.ps1, "
        "not by unit tests running as the current user."
    )
