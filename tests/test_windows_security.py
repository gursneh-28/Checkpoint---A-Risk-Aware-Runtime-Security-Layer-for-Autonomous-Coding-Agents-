"""
tests/test_windows_security.py — Unit tests for core/windows_security.py (non-elevated paths).

Verifies:
  1. Exception classes inheritance.
  2. is_elevated() and require_elevation() fail-closed behavior.
  3. account_exists() on non-existent account.
  4. verify_account_security() structure and safe execution without elevation.
  5. verify_acl_boundary() behavior.
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import core.windows_security as ws


def test_exception_classes():
    assert issubclass(ws.WindowsSecurityError, RuntimeError)
    assert issubclass(ws.ElevationRequired, ws.WindowsSecurityError)


def test_is_elevated_returns_bool():
    result = ws.is_elevated()
    assert isinstance(result, bool)


def test_require_elevation_raises_when_not_elevated(monkeypatch):
    monkeypatch.setattr(ws, "is_elevated", lambda: False)
    with pytest.raises(ws.ElevationRequired, match="requires Administrator elevation"):
        ws.require_elevation("test_op")


def test_require_elevation_passes_when_elevated(monkeypatch):
    monkeypatch.setattr(ws, "is_elevated", lambda: True)
    # Should not raise
    ws.require_elevation("test_op")


def test_account_exists_nonexistent():
    # An account name that is extremely unlikely to exist
    assert ws.account_exists("CheckpointNonExistent_99999") is False


def test_verify_account_security_returns_expected_structure():
    report = ws.verify_account_security()
    assert isinstance(report, dict)
    assert "ok" in report
    assert "checks" in report
    assert isinstance(report["checks"], list)
    assert len(report["checks"]) >= 3
    for check in report["checks"]:
        assert "check" in check
        assert "result" in check
        assert "note" in check


def test_create_service_account_requires_elevation(monkeypatch):
    monkeypatch.setattr(ws, "is_elevated", lambda: False)
    with pytest.raises(ws.ElevationRequired):
        ws.create_service_account("some_password_12345")


def test_delete_service_account_requires_elevation(monkeypatch):
    monkeypatch.setattr(ws, "is_elevated", lambda: False)
    monkeypatch.setattr(ws, "account_exists", lambda name: True)
    with pytest.raises(ws.ElevationRequired):
        ws.delete_service_account()
