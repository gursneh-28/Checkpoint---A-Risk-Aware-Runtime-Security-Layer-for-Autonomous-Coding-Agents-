"""
Checkpoint evaluation pipeline — Feature 1.

evaluate(event) → Decision is the single decision point.
It NEVER executes any command.

Steps:
1. Record a durable journal entry immediately (before anything else).
2. Run the classifier → ClassifierResult.
3. Run provenance tracker.
4. Run policy resolver → effective tier.
5. Run anomaly detector.
6. If destructive git op → check/create git backup.
7. Generate preview.
8. For HIGH/CRITICAL: generate impact report + backup plan.
9. Generate suggestion (if applicable).
10. If LOW + fast-path eligible → allow (journal first).
11. If MEDIUM/HIGH → pending, wait for dashboard decision.
12. If CRITICAL → pending, require typed YES.
13. Hard-deny → deny immediately.

Design doc: "Record first, then answer."
"""
from __future__ import annotations

import os
import sys
import time
from typing import Optional

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from core.event_types import (
    Event, Decision, DecisionKind, RiskTier, HardDenyReason, ToolKind
)
from core.risk_classifier import classify_risk_full
from core.policy_resolver import resolve, PolicyResolution
from core import provenance, anomaly
from core.preview import generate_preview, generate_analysis
from core.impact_report import build_impact_manifest, build_backup_plan
from core.suggestions import suggest_alternative
from storage.db import (
    log_pending_action, log_action, set_action_status,
    get_action_status, append_action_event, create_alert, init_db
)

# ---------------------------------------------------------------------------
# Decision timeout (5 minutes per v2.2 spec)
# ---------------------------------------------------------------------------
APPROVAL_TIMEOUT_SECONDS = 300
POLL_INTERVAL_SECONDS    = 1


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def evaluate(event: Event) -> Decision:
    """
    The single evaluation pipeline.  Never executes anything.
    Returns a Decision to be returned to the hook client.
    """
    # Ensure DB exists
    try:
        init_db()
    except Exception as e:
        return Decision(
            kind=DecisionKind.DENY,
            reason=f"Journal initialization failed: {e}. Action blocked (record-first policy).",
        )

    # Determine tool kind
    tool_kind = ToolKind(event.tool_name) if event.tool_name in {t.value for t in ToolKind} \
                else ToolKind.OTHER

    # Only Bash is covered in v1
    if tool_kind != ToolKind.BASH:
        # Read/Edit/Write not yet fully covered — pending
        # Still log it
        action_id = log_pending_action(
            action_type=event.tool_name,
            command=event.file_path or event.tool_name,
            risk_tier="UNKNOWN",
            session_id=event.session_id,
            tool_use_id=event.tool_use_id,
            cwd=event.cwd,
        )
        return Decision(
            kind=DecisionKind.DENY,
            reason=f"Tool '{event.tool_name}' is not yet covered by Checkpoint v1. "
                   "Action blocked (coverage gap).",
            action_id=action_id,
            base_tier=RiskTier.UNKNOWN,
            effective_tier=RiskTier.UNKNOWN,
        )

    command = event.command or ""

    # 1. Classify
    classifier_result = classify_risk_full(command)

    # 2. Provenance
    provenance.record_event(event)
    prov_signal = provenance.get_signal(event)

    # 3. Policy resolve (first pass, without anomaly)
    resolution = resolve(
        classifier_result=classifier_result,
        command=command,
        file_path=event.file_path,
        provenance=prov_signal,
        backup_failed=False,
        journal_failed=False,
        unsupported_environment=False,
    )

    # 4. Anomaly (uses effective tier from first pass)
    anomaly_signal = anomaly.get_signal(event, resolution.effective_tier)

    # 5. Policy resolve (final, with anomaly)
    resolution = resolve(
        classifier_result=classifier_result,
        command=command,
        file_path=event.file_path,
        provenance=prov_signal,
        anomaly=anomaly_signal,
        backup_failed=False,
        journal_failed=False,
        unsupported_environment=False,
    )

    effective_tier = resolution.effective_tier

    # 6. Git safety net for destructive git ops
    git_backup_missing = False
    if command.strip().lower().startswith("git "):
        from core.git_safety import is_destructive_git_op, has_verified_backup
        if is_destructive_git_op(command):
            if not has_verified_backup(event.cwd or os.getcwd(), max_age_seconds=600):
                git_backup_missing = True
                # Re-resolve with backup_failed=True → hard deny
                resolution = resolve(
                    classifier_result=classifier_result,
                    command=command,
                    provenance=prov_signal,
                    anomaly=anomaly_signal,
                    backup_failed=True,
                )
                effective_tier = resolution.effective_tier

    # --- Hard deny ---
    if resolution.is_hard_deny:
        action_id = _journal_deny(event, resolution)
        anomaly.post_decision(event, effective_tier, rejected=True)
        return Decision(
            kind=DecisionKind.DENY,
            reason="HARD DENY: " + "; ".join(resolution.escalation_reasons),
            action_id=action_id,
            base_tier=resolution.base_tier,
            effective_tier=effective_tier,
        )

    # 7. Preview
    preview = generate_preview(command, event.cwd)

    # 8. Impact report + backup plan (HIGH/CRITICAL)
    impact    = None
    bk_plan   = None
    if effective_tier in (RiskTier.HIGH, RiskTier.CRITICAL):
        impact  = build_impact_manifest(command, event.cwd)
        bk_plan = build_backup_plan(impact)

    # 9. Suggestion
    suggestion = suggest_alternative(command, risk_tier=effective_tier.value)

    # --- LOW: fast path ---
    if effective_tier == RiskTier.LOW:
        action_id = log_action(
            action_type="shell",
            command=command,
            risk_tier="LOW",
            status="execution_authorized",
            session_id=event.session_id,
            cwd=event.cwd,
        )
        anomaly.post_decision(event, effective_tier, rejected=False)
        return Decision(
            kind=DecisionKind.ALLOW,
            reason="LOW risk; instant-run approved",
            action_id=action_id,
            base_tier=resolution.base_tier,
            effective_tier=effective_tier,
        )

    # --- MEDIUM / HIGH / CRITICAL: pend and wait ---
    action_id = log_pending_action(
        action_type="shell",
        command=command,
        risk_tier=resolution.base_tier.value,
        effective_tier=effective_tier.value,
        suggestion=suggestion,
        preview_hash=preview.preview_hash,
        manifest_hash=impact.manifest_hash if impact else "",
        backup_hash=bk_plan.plan_hash if bk_plan else "",
        session_id=event.session_id,
        tool_use_id=event.tool_use_id,
        cwd=event.cwd,
    )

    # Create pending alert (Feature 15)
    create_alert(action_id, kind="pending_approval")

    # Wait for dashboard decision
    deadline = time.time() + APPROVAL_TIMEOUT_SECONDS
    while time.time() < deadline:
        status = get_action_status(action_id)

        if status == "approved":
            append_action_event(action_id, "execution_authorized")
            anomaly.post_decision(event, effective_tier, rejected=False)
            return Decision(
                kind=DecisionKind.ALLOW,
                reason=f"Approved by dashboard (tier={effective_tier.value})",
                action_id=action_id,
                base_tier=resolution.base_tier,
                effective_tier=effective_tier,
            )

        if status == "rejected":
            anomaly.post_decision(event, effective_tier, rejected=True)
            return Decision(
                kind=DecisionKind.DENY,
                reason="Rejected by user in dashboard",
                action_id=action_id,
                base_tier=resolution.base_tier,
                effective_tier=effective_tier,
            )

        if status == "alternative" and suggestion:
            append_action_event(action_id, "alternative_selected",
                                {"alternative": suggestion.get("command")})
            anomaly.post_decision(event, effective_tier, rejected=False)
            # Return the alternative as a rewrite (or deny original + inform)
            if suggestion.get("kind") == "command" and suggestion.get("command"):
                return Decision(
                    kind=DecisionKind.REWRITE,
                    reason=f"Safer alternative selected: {suggestion['text']}",
                    action_id=action_id,
                    base_tier=resolution.base_tier,
                    effective_tier=effective_tier,
                    alternative={
                        "updated_input": {"command": suggestion["command"]},
                        "text":          suggestion["text"],
                        "diff":          suggestion.get("diff", ""),
                    },
                )
            else:
                # Trash / protect-then-run: deny original; Checkpoint handles it
                return Decision(
                    kind=DecisionKind.DENY,
                    reason=f"Alternative action selected (Checkpoint will handle): {suggestion['text']}",
                    action_id=action_id,
                    base_tier=resolution.base_tier,
                    effective_tier=effective_tier,
                    alternative=suggestion,
                )

        time.sleep(POLL_INTERVAL_SECONDS)

    # Timeout → deny
    set_action_status(action_id, "stale")
    create_alert(action_id, kind="timeout")
    anomaly.post_decision(event, effective_tier, rejected=True)
    return Decision(
        kind=DecisionKind.DENY,
        reason=f"Approval timeout after {APPROVAL_TIMEOUT_SECONDS}s. Action denied.",
        action_id=action_id,
        base_tier=resolution.base_tier,
        effective_tier=effective_tier,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _journal_deny(event: Event, resolution: PolicyResolution) -> int:
    """Write an immediate hard-deny journal entry and return the action_id."""
    return log_action(
        action_type="shell",
        command=event.command or "",
        risk_tier=resolution.base_tier.value,
        status="rejected",
        session_id=event.session_id,
        cwd=event.cwd,
    )
