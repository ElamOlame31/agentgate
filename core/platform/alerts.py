"""
Alert dispatcher for AgentGate.

Fires real-time notifications when AgentGate makes an ESCALATE or DENY decision.
Supports ntfy.sh (push notifications), Slack (Block Kit), Teams (Adaptive Cards),
generic webhooks, Splunk HEC, and Microsoft Sentinel.

Configure in .env:
    AGENTGATE_ALERT_TOPIC=agentgate-yourname        # ntfy.sh topic
    AGENTGATE_WEBHOOK_URL=https://hooks.slack.com/… # Slack incoming webhook
    AGENTGATE_WEBHOOK_URL=https://…webhook.office…  # Teams incoming webhook
    AGENTGATE_ALERT_ON_ESCALATE=true
    AGENTGATE_ALERT_ON_DENY=true

    # Splunk HEC (fires on every decision)
    AGENTGATE_SPLUNK_HEC_URL=https://splunk.example.com:8088
    AGENTGATE_SPLUNK_TOKEN=your-hec-token
    AGENTGATE_SPLUNK_INDEX=main               # optional, default: main

    # Microsoft Sentinel / Log Analytics (fires on every decision)
    AGENTGATE_SENTINEL_WORKSPACE_ID=your-workspace-id
    AGENTGATE_SENTINEL_KEY=your-primary-key   # base64-encoded shared key
    AGENTGATE_SENTINEL_LOG_TYPE=AgentGateDecision  # optional, default shown
"""

import base64
import datetime
import hashlib
import hmac as _hmac_mod
import json
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


def _slack_payload(decision: str, agent_id: str, action: str, resource: str,
                   explanation: str, flags: list[str], score: float) -> dict:
    """Build a Slack Block Kit message."""
    is_deny = decision == "DENY"
    color  = "#FF3B5C" if is_deny else "#FF9500"
    emoji  = ":rotating_light:" if is_deny else ":warning:"
    flag_str = ", ".join(flags) if flags else "none"

    return {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} AgentGate {decision}: {agent_id}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Action*\n`{action} {resource}`"},
                        {"type": "mrkdwn", "text": f"*Trust Score*\n`{score:.0f}/100`"},
                        {"type": "mrkdwn", "text": f"*Agent ID*\n`{agent_id}`"},
                        {"type": "mrkdwn", "text": f"*Flags*\n`{flag_str}`"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Reason*\n{explanation}"},
                },
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": ":shield: Sent by *AgentGate PDP*"}],
                },
            ],
        }]
    }


def _teams_payload(decision: str, agent_id: str, action: str, resource: str,
                   explanation: str, flags: list[str], score: float) -> dict:
    """Build a Microsoft Teams Adaptive Card payload."""
    is_deny = decision == "DENY"
    color   = "attention" if is_deny else "warning"
    flag_str = ", ".join(flags) if flags else "none"

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "size": "Large",
                        "weight": "Bolder",
                        "color": color,
                        "text": f"AgentGate {decision}: {agent_id}",
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Action",      "value": f"`{action} {resource}`"},
                            {"title": "Trust Score", "value": f"{score:.0f}/100"},
                            {"title": "Flags",       "value": flag_str},
                            {"title": "Reason",      "value": explanation},
                        ],
                    },
                ],
            },
        }],
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

    # ── Slack / Teams / Generic webhook ──────────────────────────────────
    if webhook:
        try:
            if "hooks.slack.com" in webhook:
                payload = _slack_payload(decision, agent_id, action, resource,
                                         explanation, flags, score)
            elif "webhook.office.com" in webhook or "webhook.microsoft.com" in webhook:
                payload = _teams_payload(decision, agent_id, action, resource,
                                          explanation, flags, score)
            else:
                payload = {
                    "decision": decision, "agent_id": agent_id,
                    "action": action, "resource": resource,
                    "score": score, "flags": flags, "explanation": explanation,
                }
            httpx.post(webhook, json=payload, timeout=5.0)
        except Exception as e:
            print(f"[AgentGate] Webhook error: {e}", flush=True)


# ── SIEM Connectors ────────────────────────────────────────────────────────────

def _build_siem_event(decision: str, agent_id: str, action: str, resource: str,
                      explanation: str, flags: list[str], score: float,
                      breakdown: dict | None = None,
                      request_id: str | None = None) -> dict:
    import time as _time
    event = {
        "timestamp": _time.time(),
        "request_id": request_id or "",
        "decision": decision,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "trust_score": round(score, 2),
        "attack_flags": flags,
        "explanation": explanation,
        "source": "agentgate-pdp",
    }
    if breakdown:
        event.update({
            "identity_score":    round(breakdown.get("identity_score", 0), 2),
            "delegation_score":  round(breakdown.get("delegation_score", 0), 2),
            "purpose_score":     round(breakdown.get("purpose_alignment_score", 0), 2),
            "behavioral_score":  round(breakdown.get("behavioral_score", 0), 2),
            "resource_sensitivity": breakdown.get("resource_sensitivity", ""),
        })
    return event


def _splunk_send(event: dict):
    url   = os.getenv("AGENTGATE_SPLUNK_HEC_URL", "").rstrip("/")
    token = os.getenv("AGENTGATE_SPLUNK_TOKEN", "")
    index = os.getenv("AGENTGATE_SPLUNK_INDEX", "main")
    if not url or not token:
        return
    payload = {
        "time":       event.get("timestamp"),
        "host":       "agentgate",
        "source":     "agentgate-pdp",
        "sourcetype": "agentgate:decision",
        "index":      index,
        "event":      event,
    }
    try:
        r = httpx.post(
            f"{url}/services/collector/event",
            json=payload,
            headers={"Authorization": f"Splunk {token}"},
            timeout=5.0,
            verify=False,  # common in on-prem Splunk with self-signed certs
        )
        if r.status_code not in (200, 204):
            print(f"[AgentGate] Splunk HEC {r.status_code}: {r.text[:120]}", flush=True)
    except Exception as e:
        print(f"[AgentGate] Splunk HEC error: {e}", flush=True)


def _sentinel_sign(workspace_id: str, shared_key: str, rfc822_date: str,
                   content_length: int) -> str:
    """Compute SharedKey HMAC-SHA256 signature for Azure Monitor Data Collector API."""
    string_to_sign = (
        f"POST\n{content_length}\napplication/json\n"
        f"x-ms-date:{rfc822_date}\n/api/logs"
    )
    key_bytes = base64.b64decode(shared_key)
    sig_bytes = _hmac_mod.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(sig_bytes).decode()


def _sentinel_send(event: dict):
    workspace_id = os.getenv("AGENTGATE_SENTINEL_WORKSPACE_ID", "")
    shared_key   = os.getenv("AGENTGATE_SENTINEL_KEY", "")
    log_type     = os.getenv("AGENTGATE_SENTINEL_LOG_TYPE", "AgentGateDecision")
    if not workspace_id or not shared_key:
        return

    body_bytes = json.dumps([event]).encode("utf-8")
    rfc822_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    try:
        signature = _sentinel_sign(workspace_id, shared_key, rfc822_date, len(body_bytes))
    except Exception as e:
        print(f"[AgentGate] Sentinel signature error: {e}", flush=True)
        return

    url = (
        f"https://{workspace_id}.ods.opinsights.azure.com"
        "/api/logs?api-version=2016-04-01"
    )
    try:
        r = httpx.post(
            url,
            content=body_bytes,
            headers={
                "Authorization":      f"SharedKey {workspace_id}:{signature}",
                "Log-Type":           log_type,
                "x-ms-date":          rfc822_date,
                "Content-Type":       "application/json",
                "time-generated-field": "timestamp",
            },
            timeout=10.0,
        )
        if r.status_code not in (200, 202, 204):
            print(f"[AgentGate] Sentinel {r.status_code}: {r.text[:120]}", flush=True)
    except Exception as e:
        print(f"[AgentGate] Sentinel error: {e}", flush=True)


def _send_siem(event: dict):
    _splunk_send(event)
    _sentinel_send(event)


def fire_siem_event(decision: str, agent_id: str, action: str, resource: str,
                    explanation: str, flags: list[str], score: float,
                    breakdown: dict | None = None, request_id: str | None = None):
    """Forward every authorization decision to configured SIEM connectors.

    Unlike fire_alert(), this fires on PERMIT as well — SIEMs need the full
    audit stream, not just incidents. Runs in a daemon background thread so it
    never adds latency to the /authorize response.
    """
    splunk_url   = os.getenv("AGENTGATE_SPLUNK_HEC_URL", "")
    sentinel_id  = os.getenv("AGENTGATE_SENTINEL_WORKSPACE_ID", "")
    if not splunk_url and not sentinel_id:
        return
    event = _build_siem_event(decision, agent_id, action, resource,
                               explanation, flags, score, breakdown, request_id)
    threading.Thread(target=_send_siem, args=(event,), daemon=True).start()


def siem_configured() -> bool:
    return bool(
        os.getenv("AGENTGATE_SPLUNK_HEC_URL") or
        os.getenv("AGENTGATE_SENTINEL_WORKSPACE_ID")
    )


def siem_status() -> list[str]:
    destinations = []
    if os.getenv("AGENTGATE_SPLUNK_HEC_URL"):
        url = os.getenv("AGENTGATE_SPLUNK_HEC_URL", "")
        destinations.append(f"splunk:{url}")
    if os.getenv("AGENTGATE_SENTINEL_WORKSPACE_ID"):
        wid = os.getenv("AGENTGATE_SENTINEL_WORKSPACE_ID", "")
        log_type = os.getenv("AGENTGATE_SENTINEL_LOG_TYPE", "AgentGateDecision")
        destinations.append(f"sentinel:{wid}/{log_type}")
    return destinations


# ── Incident Alerts (DENY / ESCALATE only) ────────────────────────────────────

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


def fire_approval_request(request_id: str, agent_id: str, action: str,
                          resource: str, explanation: str, score: float):
    """Send an ntfy.sh notification with Approve/Deny action buttons."""
    cfg = _get_config()
    topic = cfg["topic"]
    if not topic:
        return

    public_url = os.getenv("AGENTGATE_PUBLIC_URL", "").rstrip("/")
    title = f"APPROVAL NEEDED: {agent_id}"
    body = (
        f"Action: {action} on {resource}\n"
        f"Trust Score: {score}/100\n"
        f"Reason: {explanation}\n"
        f"Auto-denies in 90 seconds."
    )
    headers = {
        "Title": title,
        "Priority": "urgent",
        "Tags": "question,shield",
    }
    if public_url:
        # Use the dedicated admin key for approval URLs — never expose the agent API key.
        # If no admin key is set, fall back to API key with a warning logged at startup.
        admin_key = os.getenv("AGENTGATE_ADMIN_KEY", "").strip()
        api_key = os.getenv("AGENTGATE_API_KEY", "").strip()
        auth_key = admin_key or api_key
        if admin_key:
            key_suffix = f"?admin_key={auth_key}"
        elif auth_key:
            key_suffix = f"?key={auth_key}"
        else:
            key_suffix = ""
        headers["Actions"] = (
            f"http, Approve, {public_url}/decisions/{request_id}/approve{key_suffix}, method=POST, headers.ngrok-skip-browser-warning=true, clear=true; "
            f"http, Deny, {public_url}/decisions/{request_id}/deny{key_suffix}, method=POST, headers.ngrok-skip-browser-warning=true, clear=true"
        )

    try:
        r = httpx.post(
            f"{NTFY_BASE}/{topic}",
            content=body.encode("utf-8"),
            headers=headers,
            timeout=10.0,
        )
        print(f"[AgentGate] Approval alert sent: {r.status_code}", flush=True)
    except Exception as e:
        print(f"[AgentGate] Approval alert error: {e}", flush=True)


def alerts_configured() -> bool:
    return bool(_get_config()["topic"] or _get_config()["webhook"])


def alert_status() -> str:
    cfg = _get_config()
    if cfg["topic"]:
        return f"ntfy.sh/{cfg['topic']}"
    if cfg["webhook"]:
        return cfg["webhook"]
    return "not configured"
