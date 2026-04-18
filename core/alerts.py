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
from dotenv import load_dotenv

load_dotenv()

NTFY_BASE = "https://ntfy.sh"

def _get_config():
    return {
        "topic": os.getenv("AGENTGATE_ALERT_TOPIC", ""),
        "webhook": os.getenv("AGENTGATE_WEBHOOK_URL", ""),
        "on_escalate": os.getenv("AGENTGATE_ALERT_ON_ESCALATE", "true").lower() == "true",
        "on_deny": os.getenv("AGENTGATE_ALERT_ON_DENY", "true").lower() == "true",
    }


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

    cfg = _get_config()
    topic = cfg["topic"]
    webhook = cfg["webhook"]

    # ── ntfy.sh push notification ─────────────────────────────────────────
    if topic:
        try:
            r = httpx.post(
                f"{NTFY_BASE}/{topic}",
                content=body.encode("utf-8"),
                headers={
                    "Title": title,
                    "Priority": priority,
                    "Tags": tags,
                },
                timeout=10.0,
            )
            print(f"[AgentGate] ntfy.sh response: {r.status_code}", flush=True)
        except Exception as e:
            print(f"[AgentGate] Alert error: {e}", flush=True)

    # ── Generic webhook ───────────────────────────────────────────────────
    if webhook:
        try:
            httpx.post(webhook, json={
                "decision": decision, "agent_id": agent_id,
                "action": action, "resource": resource,
                "score": score, "flags": flags, "explanation": explanation,
            }, timeout=5.0)
        except Exception as e:
            print(f"[AgentGate] Webhook error: {e}", flush=True)


def fire_alert(decision: str, agent_id: str, action: str, resource: str,
               explanation: str, flags: list[str], score: float):
    cfg = _get_config()
    if decision == "PERMIT":
        return
    if decision == "DENY" and not cfg["on_deny"]:
        return
    if decision == "ESCALATE" and not cfg["on_escalate"]:
        return
    if not cfg["topic"] and not cfg["webhook"]:
        print(f"[AgentGate] Alert skipped — no topic/webhook configured", flush=True)
        return

    print(f"[AgentGate] Firing alert: {decision} {agent_id} {action} {resource}", flush=True)
    thread = threading.Thread(
        target=_send,
        args=(decision, agent_id, action, resource, explanation, flags, score),
        daemon=False,
    )
    thread.start()


def alerts_configured() -> bool:
    return bool(_get_config()["topic"] or _get_config()["webhook"])


def alert_status() -> str:
    cfg = _get_config()
    if cfg["topic"]:
        return f"ntfy.sh/{cfg['topic']}"
    if cfg["webhook"]:
        return cfg["webhook"]
    return "not configured"
