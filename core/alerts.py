"""
core/alerts.py — Feature 15: Alerts & Notifications Pipeline

Provides:
- Webhook payload formatting for pending human approval events.
- Rate-limited desktop notification dispatcher (prevents notification storms).
- Alert delivery tracking in the Checkpoint database.
"""

from __future__ import annotations

import json
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from storage.db import (
    create_alert,
    get_action,
    update_alert_status,
)


class AlertChannel(str, Enum):
    WEBHOOK = "webhook"
    DESKTOP = "desktop"


class DesktopNotifier:
    """
    Rate-limited desktop notification delivery.
    Prevents alert storms by enforcing a minimum interval between notifications.
    """

    def __init__(
        self,
        rate_limit_seconds: float = 3.0,
        sink: Optional[Callable[[str, str], bool]] = None,
    ):
        self.rate_limit_seconds = rate_limit_seconds
        self.sink = sink
        self.last_notified_at: float = 0.0
        self.notification_log: List[Dict[str, Any]] = []

    def notify(self, title: str, message: str) -> bool:
        """
        Attempt to send a desktop notification.
        Returns True if delivered, False if throttled / rate-limited.
        """
        now = time.monotonic()
        if now - self.last_notified_at < self.rate_limit_seconds:
            # Throttled
            self.notification_log.append({
                "timestamp": now,
                "title": title,
                "message": message,
                "status": "throttled",
            })
            return False

        self.last_notified_at = now
        delivered = True
        if self.sink:
            try:
                delivered = bool(self.sink(title, message))
            except Exception:
                delivered = False

        self.notification_log.append({
            "timestamp": now,
            "title": title,
            "message": message,
            "status": "delivered" if delivered else "failed",
        })
        return delivered


_default_notifier = DesktopNotifier()


def get_default_notifier() -> DesktopNotifier:
    return _default_notifier


def format_webhook_payload(
    action: Dict[str, Any],
    base_url: str = "http://localhost:5000",
) -> Dict[str, Any]:
    """
    Format a standardized JSON webhook payload for pending approval.
    """
    action_id = action.get("id")
    risk_tier = action.get("effective_tier") or action.get("risk_tier", "UNKNOWN")
    command = action.get("command", "")
    tool_name = action.get("action_type") or action.get("tool_name", "bash")
    preview_hash = action.get("preview_hash", "")

    return {
        "event": "action.pending_approval",
        "action_id": action_id,
        "timestamp": action.get("timestamp", ""),
        "tool_name": tool_name,
        "command": command,
        "risk_tier": risk_tier,
        "preview_hash": preview_hash,
        "approval_url": f"{base_url}/action/{action_id}",
        "resolve_url": f"{base_url}/resolve/{action_id}/approve",
    }


def dispatch_alerts(
    action_id: int,
    channels: Optional[List[str]] = None,
    notifier: Optional[DesktopNotifier] = None,
    base_url: str = "http://localhost:5000",
) -> Dict[str, Any]:
    """
    Feature 15: Dispatch alerts across specified channels and record them in DB.
    Default channels: ['webhook', 'desktop'].
    """
    if channels is None:
        channels = [AlertChannel.WEBHOOK.value, AlertChannel.DESKTOP.value]

    action = get_action(action_id)
    if not action:
        return {"error": f"Action {action_id} not found", "delivered": []}

    results: Dict[str, Any] = {"action_id": action_id, "channels": {}}
    desktop_agent = notifier or _default_notifier

    for ch in channels:
        if ch == AlertChannel.WEBHOOK.value:
            payload = format_webhook_payload(action, base_url=base_url)
            payload_str = json.dumps(payload)
            alert_id = create_alert(
                action_id=action_id,
                kind="pending_approval",
                channel="webhook",
                payload=payload_str,
            )
            # In local/simulated environment, webhook payload is formatted and recorded
            update_alert_status(alert_id, "delivered")
            results["channels"]["webhook"] = {
                "alert_id": alert_id,
                "status": "delivered",
                "payload": payload,
            }

        elif ch == AlertChannel.DESKTOP.value:
            tier = action.get("effective_tier") or action.get("risk_tier", "UNKNOWN")
            cmd = action.get("command", "")[:60]
            title = f"Checkpoint Approval Required [{tier}]"
            msg = f"Action #{action_id} needs approval: {cmd}"

            alert_id = create_alert(
                action_id=action_id,
                kind="pending_approval",
                channel="desktop",
                payload=json.dumps({"title": title, "message": msg}),
            )

            delivered = desktop_agent.notify(title, msg)
            status = "delivered" if delivered else "throttled"
            update_alert_status(alert_id, status)
            results["channels"]["desktop"] = {
                "alert_id": alert_id,
                "status": status,
            }

    return results
