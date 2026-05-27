"""
Trust contagion: when one agent in a delegation chain is quarantined,
adjacent agents (parent and children) receive a behavioral score penalty.

  Child quarantined  → parent penalty:  -15 points (child's bad behaviour
                        reflects on the parent that spawned it)
  Parent quarantined → each child:      -30 points (children may have been
                        spawned as part of the attack, or are now operating
                        without a trustworthy principal)

Penalties are additive (multiple compromised neighbours stack, capped at 60),
have a 1-hour TTL, and are cleared when the source agent is released.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

_CHILD_PENALTY = 15.0   # deducted from child agent's behavioural score when it is quarantined
_PARENT_PENALTY = 30.0  # deducted from children's scores when their parent is quarantined
_TTL = 3_600.0          # 1 hour
_MAX_PENALTY = 60.0     # cap so a single event cannot wipe all behavioural score alone


@dataclass
class ContagionRecord:
    source_agent_id: str
    direction: str          # "from_child" | "from_parent"
    penalty: float
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = _TTL

    def is_expired(self) -> bool:
        return time.time() > self.created_at + self.ttl_seconds

    def flag(self) -> str:
        direction_tag = "FROM_PARENT" if self.direction == "from_parent" else "FROM_CHILD"
        return f"CONTAGION:{direction_tag}:{self.source_agent_id}"


# agent_id → list[ContagionRecord]
_store: dict[str, list[ContagionRecord]] = {}


def _apply(target_id: str, source_id: str, direction: str, penalty: float) -> None:
    records = _store.setdefault(target_id, [])
    # Prune expired entries first
    records[:] = [r for r in records if not r.is_expired()]
    # Avoid duplicate entry from the same source (refresh instead)
    records[:] = [r for r in records if r.source_agent_id != source_id]
    records.append(ContagionRecord(
        source_agent_id=source_id,
        direction=direction,
        penalty=penalty,
    ))


def propagate_quarantine(quarantined_id: str, agents: dict) -> list[str]:
    """
    Called immediately after an agent is quarantined.
    Marks adjacent agents (parent and children) with a contagion penalty.
    Returns the list of affected agent IDs.
    """
    affected: list[str] = []
    agent = agents.get(quarantined_id)
    if agent is None:
        return affected

    # Penalise parent — child was quarantined
    parent_id = getattr(agent, "delegated_by", None)
    if parent_id and parent_id in agents:
        _apply(parent_id, quarantined_id, "from_child", _CHILD_PENALTY)
        affected.append(parent_id)

    # Penalise all children — their principal was quarantined
    for aid, a in agents.items():
        if getattr(a, "delegated_by", None) == quarantined_id:
            _apply(aid, quarantined_id, "from_parent", _PARENT_PENALTY)
            affected.append(aid)

    return affected


def get_contagion_penalty(agent_id: str) -> tuple[float, list[str]]:
    """
    Returns (total_penalty, flag_strings) for the given agent.
    Expired records are pruned in-place.
    """
    records = _store.get(agent_id, [])
    records[:] = [r for r in records if not r.is_expired()]
    if not records:
        return 0.0, []
    total = min(_MAX_PENALTY, sum(r.penalty for r in records))
    flags = [r.flag() for r in records]
    return total, flags


def clear_contagion(agent_id: str) -> None:
    """Remove all contagion records pointing FROM this agent (called on quarantine release)."""
    for records in _store.values():
        records[:] = [r for r in records if r.source_agent_id != agent_id]
    _store.pop(agent_id, None)


def get_all() -> dict[str, list[dict]]:
    """Return a snapshot of the full contagion store (for debugging / dashboard)."""
    out = {}
    for agent_id, records in _store.items():
        active = [r for r in records if not r.is_expired()]
        if active:
            out[agent_id] = [
                {
                    "source": r.source_agent_id,
                    "direction": r.direction,
                    "penalty": r.penalty,
                    "expires_in": round(r.created_at + r.ttl_seconds - time.time()),
                }
                for r in active
            ]
    return out
