import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import core.risk_classifier as rc
from core.ml_classifier import predict_risk

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "risk_model.pkl")
VALID_TIERS = {"LOW", "MEDIUM", "HIGH"}


# ---------- model basics ----------

def test_trained_model_file_exists():
    assert os.path.exists(MODEL_PATH), "run core/ml_train.py first"


def test_predict_risk_on_never_seen_command():
    tier, confidence, source = predict_risk("terraform destroy -auto-approve")
    assert tier in VALID_TIERS
    assert 0.0 <= confidence <= 1.0


# ---------- rules first, model second ----------

def _explode(*args, **kwargs):
    raise AssertionError("ML model was called, but a hardcoded rule should have matched")


@pytest.mark.parametrize("cmd,expected", [
    ("rm -rf build/", "HIGH"),
    ("chmod 777 server.js", "HIGH"),
    ("mv a.txt b.txt", "MEDIUM"),
    ("ls -la", "LOW"),
    ("cat notes.txt", "LOW"),
])
def test_rules_are_authoritative_and_skip_model(monkeypatch, cmd, expected):
    monkeypatch.setattr(rc, "predict_risk", _explode)
    assert rc.classify_risk(cmd) == expected


@pytest.mark.parametrize("git_cmd,expected", [
    ("git push --force origin main", "HIGH"),
    ("git reset --hard HEAD~1", "HIGH"),
    ("git status", "LOW"),
])
def test_git_rules_skip_model(monkeypatch, git_cmd, expected):
    monkeypatch.setattr(rc, "predict_risk", _explode)
    assert rc.classify_git_op(git_cmd) == expected


def test_model_is_used_when_no_rule_matches(monkeypatch):
    monkeypatch.setattr(rc, "predict_risk", lambda cmd: ("HIGH", 0.99, "ml"))
    assert rc.classify_risk("somecustomtool --wipe-everything") == "HIGH"


def test_chained_command_takes_highest_tier(monkeypatch):
    monkeypatch.setattr(rc, "predict_risk", _explode)
    assert rc.classify_risk("ls && rm -rf build/") == "HIGH"


# ---------- rules-only function (added in Task 2) ----------

def test_classify_by_rules_returns_none_when_no_rule_matches():
    assert rc.classify_by_rules("python app.py") is None
    assert rc.classify_by_rules("lsblk") is None


def test_classify_by_rules_returns_tier_when_rule_matches():
    assert rc.classify_by_rules("rm -rf build/") == "HIGH"
    assert rc.classify_by_rules("ls -la") == "LOW"


# ---------- allowlist hole (fixed in Task 3) ----------

def test_redirect_to_device_is_not_treated_as_safe(monkeypatch):
    monkeypatch.setattr(rc, "predict_risk", lambda cmd: ("LOW", 0.5, "ml"))
    assert rc.classify_risk("echo data > /dev/sda") == "HIGH"


def test_env_prefix_does_not_make_command_safe(monkeypatch):
    monkeypatch.setattr(rc, "predict_risk", lambda cmd: ("LOW", 0.5, "ml"))
    assert rc.classify_risk("env rm important.txt") != "LOW"


# ---------- known gaps (item 28 before/after) ----------
# These use the REAL model. They are xfail now and should flip to passing
# as the classifier improves; remove the xfail mark once each one passes.

KNOWN_GAPS = [
    ("git clean -fdx", "HIGH"),
    ("chmod -R 777 /", "HIGH"),
]


@pytest.mark.xfail(reason="known gap from item 23, target for item 28", strict=False)
@pytest.mark.parametrize("cmd,expected", KNOWN_GAPS)
def test_known_gap_cases(cmd, expected):
    assert rc.classify_risk(cmd) == expected