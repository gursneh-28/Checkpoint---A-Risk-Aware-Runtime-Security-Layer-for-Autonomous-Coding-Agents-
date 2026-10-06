import time
from storage.db import log_action, log_pending_action, get_action_status, set_action_status

POLL_INTERVAL_SECONDS = 1


def resolve_action(action_type: str, description: str, risk_tier: str, execute_fn,
                   suggestion: dict = None, alternative_fn=None):
    """
    The single decision point every intercepted action passes through.

    - LOW tier: executes immediately, no interruption.
    - MEDIUM/HIGH tier: logged as 'pending'; this function WAITS, checking the
      database every second, for a decision from the dashboard:
        approved    -> runs the ORIGINAL action (execute_fn)
        rejected    -> runs nothing
        alternative -> runs the SAFER action (alternative_fn) instead

    execute_fn / alternative_fn: zero-argument functions that perform the
    action. They are only ever called after a real decision. A suggestion is
    only offered if there is an alternative_fn that can actually run it.
    """
    print(f"[Checkpoint] {description}")
    print(f"[Checkpoint] Risk tier: {risk_tier}")

    if risk_tier == "LOW":
        output = execute_fn()
        log_action(action_type, description, risk_tier, "executed", output or "")
        print("[Checkpoint] Executed (auto, low risk).\n")
        return True

    if alternative_fn is None:
        suggestion = None

    action_id = log_pending_action(action_type, description, risk_tier, suggestion)
    print(f"[Checkpoint] This action needs approval (tier {risk_tier}).")
    if suggestion:
        print(f"[Checkpoint] Safer option available: {suggestion['text']}")
    print(f"[Checkpoint] Waiting for a decision in the dashboard: http://127.0.0.1:5000  (action #{action_id})")

    while True:
        status = get_action_status(action_id)

        if status == "approved":
            output = execute_fn()
            set_action_status(action_id, "executed", output or "")
            print(f"[Checkpoint] Action #{action_id} approved via dashboard, executed.\n")
            return True

        if status == "rejected":
            print(f"[Checkpoint] Action #{action_id} rejected via dashboard, no changes made.\n")
            return False

        if status == "alternative":
            output = alternative_fn()
            set_action_status(action_id, "executed-alternative", output or "")
            print(f"[Checkpoint] Action #{action_id}: safer alternative executed instead.\n")
            return True

        time.sleep(POLL_INTERVAL_SECONDS)