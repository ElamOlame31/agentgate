"""
Alert dispatcher for AgentGate.

Fires real-time notifications when AgentGate makes an ESCALATE or DENY decision.
Supports ntfy.sh (push notifications, zero setup) and any generic webhook URL.

Configure in .env:
    AGENTGATE_ALERT_TOPIC=agentgate-yourname   # ntfy.sh topic
    AGENTGATE_WEBHOOK_URL=https://...          # optional custom webhook
    AGENTGATE_ALERT_ON_ESCALATE=true
    AGENTGATE_ALERT_ON_DENY=true
"""

import os
import threading
import httpx


NTFY_BASE = "https://ntfy.sh"
TOPIC = os.getenv("AGENTGATE_ALERT_TOPIC", "")
WEBHOOK_URL = os.getenv("AGENTGATE_WEBHOOK_URL", "")
ALERT_ON_ESCALATE = os.getenv("AGENTGATE_ALERT_ON_ESCALATE", "true").lower() == "true"
ALERT_ON_DENY = os.getenv("AGENTGATE_ALERT_ON_DENY", "true").lower() == "true"


def _send(decision: str, agent_id: str, action: str, resource: str,
          explanation: str, flags: list[str], score: float):
    """Send alert in a background thread — never blocks the main request."""

    flag_str = ", ".join(flags) if flags else "none"
    is_deny = decision == "DENY"

    title = f"AgentGate {decision}: {agent_id}"
    body = (
        f"Action: {action} {resource}\n"
        f"Score: {score}/100\n"
        f"Flags: {flag_str}\n"
        f"Reason: {explanation}"
    )
    priority = "urgent" if is_deny else "high"
    tags = "rotating_light,shield" if is_deny else "warning,shield"

    # ── ntfy.sh push notification ─────────────────────────────────────────
    if TOPIC:
        try:
            httpx.post(
                f"{NTFY_BASE}/{TOPIC}",
                content=body.encode("utf-8"),
                headers={
                    "Title": title,
                    "Priority": priority,
                    "Tags": tags,
                },
                timeout=5.0,
            )
        except Exception:
            pass

    # ── Generic webhook (Slack, Teams, custom) ────────────────────────────
    if WEBHOOK_URL:
        try:
            httpx.post(
                WEBHOOK_URL,
                json={
                    "decision": decision,
                    "agent_id": agent_id,
                    "action": action,
                    "resource": resource,
                    "score": score,
                    "flags": flags,
                    "explanation": explanation,
                },
                timeout=5.0,
            )
        except Exception:
            pass


def fire_alert(decision: str, agent_id: str, action: str, resource: str,
               explanation: str, flags: list[str], score: float):
    """
    Call this after every ESCALATE or DENY decision.
    Runs in a background thread — zero latency impact on the main response.
    """
    if decision == "DENY" and not ALERT_ON_DENY:
        return
    if decision == "ESCALATE" and not ALERT_ON_ESCALATE:
        return
    if decision == "PERMIT":
        return
    if not TOPIC and not WEBHOOK_URL:
        return

    thread = threading.Thread(
        target=_send,
        args=(decision, agent_id, action, resource, explanation, flags, score),
        daemon=True,
    )
    thread.start()


def alerts_configured() -> bool:
    return bool(TOPIC or WEBHOOK_URL)


def alert_status() -> str:
    if TOPIC:
        return f"ntfy.sh/{TOPIC}"
    if WEBHOOK_URL:
        return WEBHOOK_URL
    return "not configured"
