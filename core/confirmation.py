import time
from storage.db import log_action, log_pending_action, get_action_status, set_action_status

POLL_INTERVAL_SECONDS = 1


def resolve_action(action_type: str, description: str, risk_tier: str, execute_fn):
    """
    The single decision point every intercepted action passes through.

    - LOW tier: executes immediately, no interruption.
    - MEDIUM/HIGH tier: logged as 'pending' and this function WAITS, checking
      the database every second, until someone approves/rejects it from the
      Checkpoint dashboard in the browser.

    execute_fn: a zero-argument function that actually performs the action
    when called — it only ever gets called after a real decision is made.
    """
    print(f"[Checkpoint] {description}")
    print(f"[Checkpoint] Risk tier: {risk_tier}")

    if risk_tier == "LOW":
        output = execute_fn()
        log_action(action_type, description, risk_tier, "executed", output or "")
        print("[Checkpoint] Executed (auto — low risk).\n")
        return True

    # MEDIUM or HIGH — log as pending, then wait for the dashboard
    action_id = log_pending_action(action_type, description, risk_tier)
    print(f"[Checkpoint] This action needs approval (tier {risk_tier}).")
    print(f"[Checkpoint] Waiting for a decision in the dashboard — http://127.0.0.1:5000  (action #{action_id})")

    while True:
        status = get_action_status(action_id)

        if status == "approved":
            output = execute_fn()
            set_action_status(action_id, "executed", output or "")
            print(f"[Checkpoint] Action #{action_id} approved via dashboard — executed.\n")
            return True

        if status == "rejected":
            print(f"[Checkpoint] Action #{action_id} rejected via dashboard — no changes made.\n")
            return False

        time.sleep(POLL_INTERVAL_SECONDS)