from storage.db import log_action


def resolve_action(action_type: str, description: str, risk_tier: str, execute_fn):
    """
    The single decision point every intercepted action passes through.

    - LOW tier: executes immediately, no interruption.
    - MEDIUM/HIGH tier: pauses and asks the user to approve or reject.

    execute_fn: a zero-argument function that actually performs the action
    when called. Passing it in (instead of running it directly) means the
    action genuinely does NOT happen until this gate decides it should.

    Returns True if the action was executed, False if it was rejected.
    """
    print(f"[Checkpoint] {description}")
    print(f"[Checkpoint] Risk tier: {risk_tier}")

    if risk_tier == "LOW":
        output = execute_fn()
        log_action(action_type, description, risk_tier, "executed", output or "")
        print("[Checkpoint] Executed (auto — low risk).\n")
        return True

    # MEDIUM or HIGH — pause and ask
    print(f"[Checkpoint] This action is tier {risk_tier} and needs your approval.")
    decision = input("Approve this action? (y/n): ").strip().lower()

    if decision == "y":
        output = execute_fn()
        log_action(action_type, description, risk_tier, "executed", output or "")
        print("[Checkpoint] Approved — executed.\n")
        return True
    else:
        log_action(action_type, description, risk_tier, "rejected")
        print("[Checkpoint] Rejected — no changes were made.\n")
        return False