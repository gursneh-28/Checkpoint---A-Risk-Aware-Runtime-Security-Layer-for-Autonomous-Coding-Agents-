
"""
Antigravity lifecycle hook adapter.

Receives Antigravity PreToolUse JSON and routes supported terminal
commands through Checkpoint's existing evaluation pipeline.

This first version intentionally supports run_command only.
Unsupported tools must not be treated as safe.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable, Dict

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from core.event_types import (
    Decision,
    DecisionKind,
    Event,
    ToolKind,
)
from core.pipeline import evaluate


def payload_to_event(payload: Dict[str, Any]) -> Event:
    """Convert an Antigravity PreToolUse payload into a Checkpoint Event."""

    tool_call = payload.get("toolCall")

    if not isinstance(tool_call, dict):
        raise ValueError("Missing or invalid toolCall object.")

    tool_name = tool_call.get("name")
    args = tool_call.get("args", {})

    if not isinstance(args, dict):
        raise ValueError("Invalid tool arguments.")

    if tool_name != "run_command":
        raise ValueError(
            f"Unsupported Antigravity tool: {tool_name}"
        )

    command = args.get("CommandLine")

    if not isinstance(command, str) or not command.strip():
        raise ValueError("Missing or empty CommandLine.")

    conversation_id = payload.get(
        "conversationId",
        "antigravity-default-session"
    )

    step_index = payload.get("stepIdx", 0)

    workspace_paths = payload.get("workspacePaths", [])
    workspace = (
        workspace_paths[0]
        if isinstance(workspace_paths, list) and workspace_paths
        else ""
    )

    cwd = args.get("Cwd") or payload.get("cwd") or workspace or os.getcwd()

    return Event(
        session_id=str(conversation_id),
        tool_use_id=f"antigravity:{conversation_id}:{step_index}",
        tool_name="Bash",
        tool_kind=ToolKind.BASH,
        command=command,
        cwd=str(cwd),
        prompt_id=str(payload.get("lastUserInput", "")),
        agent_id="antigravity",
    )


def decision_to_hook_output(decision: Decision) -> Dict[str, Any]:
    """Convert a Checkpoint decision into Antigravity's hook response."""

    if decision.kind == DecisionKind.ALLOW:
        return {
            "decision": "allow",
            "reason": decision.reason,
        }

    if decision.kind == DecisionKind.REWRITE:
        alternative = decision.alternative or {}
        updated_input = alternative.get("updated_input", {})

        safer_command = (
            updated_input.get("command")
            or updated_input.get("CommandLine")
        )

        if not isinstance(safer_command, str) or not safer_command.strip():
            return {
                "decision": "deny",
                "reason": "Invalid safer alternative. Original action blocked.",
            }

        return {
            "decision": "allow",
            "overwrite": {
                "CommandLine": safer_command,
            },
            "reason": decision.reason,
        }

    return {
        "decision": "deny",
        "reason": decision.reason,
    }


def handle_pre_tool_use(
    input_json: str,
    evaluator: Callable[[Event], Decision] | None = None,
) -> str:
    """
    Process one Antigravity PreToolUse invocation.

    Always returns valid JSON. Hook errors must not result in a
    non-zero exit code because Antigravity may ignore failed hooks.
    """

    try:
        payload = json.loads(input_json)

        if not isinstance(payload, dict):
            raise ValueError("Hook payload must be a JSON object.")

        event = payload_to_event(payload)

        evaluate_event = evaluator or evaluate
        decision = evaluate_event(event)

        response = decision_to_hook_output(decision)

    except Exception as exc:
        response = {
            "decision": "deny",
            "reason": f"Checkpoint could not safely evaluate this action: {exc}",
        }

    return json.dumps(response)


def main() -> int:
    """Command-line entry point used by Antigravity hooks."""

    raw_input = sys.stdin.read()
    output = handle_pre_tool_use(raw_input)

    sys.stdout.write(output + "\n")
    sys.stdout.flush()

    # Return zero even on evaluation errors.
    # Antigravity may ignore a hook that exits non-zero.
    return 0


if __name__ == "__main__":
    sys.exit(main())
