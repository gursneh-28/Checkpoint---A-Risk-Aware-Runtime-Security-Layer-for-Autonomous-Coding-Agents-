import json
import os
import pytest
from core.claude_code_adapter import ClaudeCodeHookAdapter, handle_hook_call
from core.event_types import DecisionKind

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "claude_code")


def test_simulated_pre_tool_use_safe_command():
    fixture_path = os.path.join(FIXTURES_DIR, "pre_tool_use_bash_safe_ls.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        payload_str = f.read()

    exit_code, out_str = handle_hook_call(payload_str)
    out = json.loads(out_str)
    
    assert "hookSpecificOutput" in out
    decision = out["hookSpecificOutput"]
    # Instant run for ls -la should allow
    assert decision["permissionDecision"] == "allow"
    assert exit_code == 0


def test_simulated_pre_tool_use_malformed_json_fails_closed():
    exit_code, out_str = handle_hook_call("INVALID NOT A JSON {{{")
    assert exit_code == 2
    out = json.loads(out_str)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_simulated_unsupported_tool_denied():
    payload = {
        "tool_name": "PowerShell",
        "tool_input": {"command": "Get-Process"},
        "session_id": "test-sim-002"
    }
    exit_code, out_str = handle_hook_call(json.dumps(payload))
    out = json.loads(out_str)
    # Unsupported tool must be denied fail-closed
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert exit_code == 2
