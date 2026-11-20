"""
Claude Code hook adapter & simulated client — Phase 0 / Feature 1.

STATUS: SIMULATED / PREPARED INTERFACE
======================================
Claude Code is not installed on the development host.
This module implements the official hook contract according to the official Claude Code Hooks reference:
- PreToolUse is the enforcement point.
- Exit code 0 + JSON: { permissionDecision: "allow" | "deny" | "ask" | "defer", ... }
- Exit code 2: block action.
- onFailure: block requires non-zero exit codes to fail closed.

DO NOT claim live Claude Code enforcement or hook compatibility has been verified.
This module is tested against fixtures and mock hook JSON invocations.
"""
from __future__ import annotations

import json
import sys
import os
from typing import Any, Dict, Optional, Tuple

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.event_types import Event, Decision, DecisionKind, ToolKind
from core.pipeline import evaluate


class ClaudeCodeHookAdapter:
    """
    Transforms Claude Code hook JSON payloads into Checkpoint Event objects,
    and formats Decisions into the hookSpecificOutput JSON Claude Code expects.
    """

    @staticmethod
    def payload_to_event(payload: Dict[str, Any]) -> Event:
        tool_name = payload.get("tool_name", "Other")
        tool_input = payload.get("tool_input", {})
        
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        file_path = tool_input.get("file_path") or tool_input.get("path") if isinstance(tool_input, dict) else None

        return Event(
            session_id=payload.get("session_id", "default-session"),
            tool_use_id=payload.get("tool_use_id", ""),
            tool_name=tool_name,
            tool_kind=ToolKind.BASH if tool_name == "Bash" else ToolKind.OTHER,
            command=command,
            file_path=file_path,
            cwd=payload.get("cwd", ""),
            prompt_id=payload.get("prompt_id", ""),
            agent_id=payload.get("agent_id", "main_agent"),
        )

    @staticmethod
    def decision_to_hook_output(decision: Decision) -> Tuple[int, Dict[str, Any]]:
        """
        Returns (exit_code, output_dict).
        Exit 0 for successful hook evaluation with permission decision.
        Exit 2 for hard block.
        """
        reply = decision.to_hook_reply()
        if decision.kind == DecisionKind.DENY:
            return 2, {"error": decision.reason, "hookSpecificOutput": reply}
        return 0, {"hookSpecificOutput": reply}


def handle_hook_call(input_json_str: str) -> Tuple[int, str]:
    """
    Main entry point for command hook invocations.
    Reads JSON from stdin, runs evaluate(), returns exit code and stdout JSON.
    """
    try:
        data = json.loads(input_json_str)
    except Exception as e:
        # Malformed input: fail closed
        err_reply = {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "reason": f"Malformed hook payload JSON: {e}"
            }
        }
        return 2, json.dumps(err_reply)

    event = ClaudeCodeHookAdapter.payload_to_event(data)
    decision = evaluate(event)
    exit_code, output_dict = ClaudeCodeHookAdapter.decision_to_hook_output(decision)
    return exit_code, json.dumps(output_dict)


if __name__ == "__main__":
    raw_in = sys.stdin.read()
    code, out = handle_hook_call(raw_in)
    sys.stdout.write(out)
    sys.exit(code)
