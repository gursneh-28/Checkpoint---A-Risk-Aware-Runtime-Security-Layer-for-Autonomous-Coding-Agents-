
import json

from core.antigravity_adapter import (
    payload_to_event,
    decision_to_hook_output,
    handle_pre_tool_use,
)

from core.event_types import (
    Decision,
    DecisionKind,
    RiskTier,
)


def sample_payload():
    return {
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "echo Checkpoint test",
                "Cwd": "D:\\Checkpoint-Demo",
            },
        },
        "stepIdx": 3,
        "conversationId": "test-conversation-123",
        "workspacePaths": ["D:\\Checkpoint-Demo"],
        "lastUserInput": "Run a test command",
    }


def test_payload_to_event():
    event = payload_to_event(sample_payload())

    assert event.command == "echo Checkpoint test"
    assert event.cwd == "D:\\Checkpoint-Demo"
    assert event.tool_name == "Bash"
    assert event.session_id == "test-conversation-123"
    assert event.agent_id == "antigravity"
    assert event.tool_use_id == "antigravity:test-conversation-123:3"


def test_allow_decision():
    decision = Decision(
        kind=DecisionKind.ALLOW,
        reason="LOW risk; instant-run approved",
        base_tier=RiskTier.LOW,
        effective_tier=RiskTier.LOW,
    )

    result = decision_to_hook_output(decision)

    assert result["decision"] == "allow"


def test_deny_decision():
    decision = Decision(
        kind=DecisionKind.DENY,
        reason="Rejected by user",
        base_tier=RiskTier.HIGH,
        effective_tier=RiskTier.HIGH,
    )

    result = decision_to_hook_output(decision)

    assert result["decision"] == "deny"
    assert result["reason"] == "Rejected by user"


def test_rewrite_decision():
    decision = Decision(
        kind=DecisionKind.REWRITE,
        reason="Safer alternative selected",
        alternative={
            "updated_input": {
                "command": "git push --force-with-lease"
            }
        },
    )

    result = decision_to_hook_output(decision)

    assert result["decision"] == "allow"
    assert result["overwrite"]["CommandLine"] == (
        "git push --force-with-lease"
    )


def test_unsupported_tool_is_denied():
    payload = sample_payload()
    payload["toolCall"]["name"] = "write_to_file"

    output = json.loads(
        handle_pre_tool_use(json.dumps(payload))
    )

    assert output["decision"] == "deny"


def test_malformed_payload_is_denied():
    output = json.loads(handle_pre_tool_use("{invalid json"))

    assert output["decision"] == "deny"
    assert "safely evaluate" in output["reason"]


def test_low_risk_event_reaches_evaluator():
    captured = []

    def fake_evaluator(event):
        captured.append(event)

        return Decision(
            kind=DecisionKind.ALLOW,
            reason="Test approval",
            base_tier=RiskTier.LOW,
            effective_tier=RiskTier.LOW,
        )

    output = json.loads(
        handle_pre_tool_use(
            json.dumps(sample_payload()),
            evaluator=fake_evaluator,
        )
    )

    assert output["decision"] == "allow"
    assert len(captured) == 1
    assert captured[0].agent_id == "antigravity"
