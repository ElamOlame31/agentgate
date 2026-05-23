"""
Human-in-the-loop approval store for AgentGate.

When an ESCALATE fires on an agent with requires_human_approval=True,
the decision pauses (PENDING). A human must approve or deny within 90s.
After 90 seconds, the system auto-denies.
"""

import threading
import time
from typing import Dict, Optional

TIMEOUT_SECONDS = 90

# Lazy import to avoid circular import at module load time
def _persist_create(request_id, agent_id, action, resource, explanation, trust_score, expires_at):
    try:
        from core import audit as _audit
        _audit.save_pending_approval(request_id, agent_id, action, resource,
                                     explanation, trust_score, expires_at)
    except Exception:
        pass

def _persist_resolve(request_id, status):
    try:
        from core import audit as _audit
        _audit.resolve_pending_approval(request_id, status)
    except Exception:
        pass


class PendingApproval:
    def __init__(self, request_id: str, agent_id: str, action: str,
                 resource: str, explanation: str, trust_score: float):
        self.id = request_id
        self.agent_id = agent_id
        self.action = action
        self.resource = resource
        self.explanation = explanation
        self.trust_score = trust_score
        self.status = "PENDING"
        self.created_at = time.time()
        self.resolved_at: Optional[float] = None
        self._event = threading.Event()

    def resolve(self, status: str):
        self.status = status
        self.resolved_at = time.time()
        self._event.set()

    def wait_for_resolution(self, timeout: float) -> bool:
        return self._event.wait(timeout=timeout)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "explanation": self.explanation,
            "trust_score": self.trust_score,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "expires_at": self.created_at + TIMEOUT_SECONDS,
        }


_store: Dict[str, PendingApproval] = {}
_lock = threading.Lock()
# Callback to broadcast WebSocket messages (injected by server)
_broadcast_callback = None


def set_broadcast_callback(fn):
    global _broadcast_callback
    _broadcast_callback = fn


def _auto_deny(request_id: str):
    broadcast_data = None
    with _lock:
        approval = _store.get(request_id)
        if approval and approval.status == "PENDING":
            approval.resolve("DENIED")
            broadcast_data = approval.to_dict()
    if broadcast_data:
        print(f"[AgentGate] Auto-denied pending approval {request_id} (90s timeout)", flush=True)
        if _broadcast_callback:
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        _broadcast_callback({"type": "approval_resolved", "data": broadcast_data}),
                        loop
                    )
            except Exception:
                pass


def create_pending(request_id: str, agent_id: str, action: str,
                   resource: str, explanation: str, trust_score: float) -> PendingApproval:
    approval = PendingApproval(request_id, agent_id, action, resource, explanation, trust_score)
    with _lock:
        _store[request_id] = approval
    _persist_create(request_id, agent_id, action, resource, explanation,
                    trust_score, approval.created_at + TIMEOUT_SECONDS)
    t = threading.Timer(TIMEOUT_SECONDS, _auto_deny, args=(request_id,))
    t.daemon = True
    t.start()
    return approval


def get_pending(request_id: str) -> Optional[PendingApproval]:
    with _lock:
        return _store.get(request_id)


def get_all_pending() -> list:
    with _lock:
        return [a.to_dict() for a in _store.values() if a.status == "PENDING"]


def approve(request_id: str) -> bool:
    broadcast_data = None
    with _lock:
        approval = _store.get(request_id)
        if not approval or approval.status != "PENDING":
            return False
        approval.resolve("APPROVED")
        broadcast_data = approval.to_dict()
    _persist_resolve(request_id, "APPROVED")
    if _broadcast_callback and broadcast_data:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    _broadcast_callback({"type": "approval_resolved", "data": broadcast_data}),
                    loop
                )
        except Exception:
            pass
    return True


def deny(request_id: str) -> bool:
    broadcast_data = None
    with _lock:
        approval = _store.get(request_id)
        if not approval or approval.status != "PENDING":
            return False
        approval.resolve("DENIED")
        broadcast_data = approval.to_dict()
    _persist_resolve(request_id, "DENIED")
    if _broadcast_callback and broadcast_data:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    _broadcast_callback({"type": "approval_resolved", "data": broadcast_data}),
                    loop
                )
        except Exception:
            pass
    return True
