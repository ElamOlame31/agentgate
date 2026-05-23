"""
Delegation chain enforcement for AgentGate.

Core invariant: a delegated agent can NEVER exceed the scope of its parent.
This is enforced at two points:
  1. Registration time — POST /agents/delegate rejects invalid scope
  2. Authorization time — chain walk blocks requests that exceed any ancestor's scope
"""

import fnmatch

MAX_DELEGATION_DEPTH = 3
CHAIN_TRUST_DECAY = 0.10  # 10% trust penalty per delegation level


class ChainBrokenError(Exception):
    """Raised when an ancestor in the delegation chain is missing from the registry."""


# ── Scope validation ──────────────────────────────────────────────────────────

def _pattern_covered_by(child: str, parent: str) -> bool:
    """Return True if child resource pattern is a strict subset of parent pattern."""
    if child == parent:
        return True
    if fnmatch.fnmatch(child, parent):
        return True
    # /documents/public/* is covered by /documents/*
    if parent.endswith("/*") and child.endswith("/*"):
        parent_base = parent[:-2]
        return child[:-2] == parent_base or child[:-2].startswith(parent_base + "/")
    # /documents/foo.pdf is covered by /documents/*
    if parent.endswith("/*"):
        base = parent[:-2]
        return child.startswith(base + "/") or child == base
    return False


def validate_delegation(
    parent_resources: list[str], parent_actions: list[str],
    child_resources: list[str], child_actions: list[str],
) -> tuple[bool, str]:
    """
    Validate child scope is a subset of parent scope.
    Returns (valid, error_message).
    """
    for cr in child_resources:
        if not any(_pattern_covered_by(cr, pr) for pr in parent_resources):
            return False, f"Child resource '{cr}' is not within parent scope {parent_resources}"

    parent_action_set = {a.lower() for a in parent_actions}
    for ca in child_actions:
        if ca.lower() not in parent_action_set:
            return False, f"Child action '{ca}' not in parent actions {parent_actions}"

    return True, ""


# ── Chain walking ─────────────────────────────────────────────────────────────

def get_chain(agent_id: str, agents: dict) -> list:
    """
    Walk up the delegation chain. Returns list from root → agent.
    Raises ChainBrokenError if any ancestor is missing — fail closed,
    never silently skip a gap in the chain.
    """
    chain = []
    current_id = agent_id
    visited = set()
    while current_id and current_id not in visited:
        agent = agents.get(current_id)
        if not agent:
            raise ChainBrokenError(f"ancestor '{current_id}' is missing from the registry")
        chain.append(agent)
        visited.add(current_id)
        current_id = agent.delegated_by
    chain.reverse()
    return chain


def check_chain_scope(agent_id: str, action: str, resource: str, agents: dict) -> tuple[bool, str]:
    """
    Walk every ancestor in the chain and verify the requested action+resource
    is within each ancestor's authorized scope.

    This is the core enforcement: a child CANNOT do what its parent couldn't do.
    """
    try:
        chain = get_chain(agent_id, agents)
    except ChainBrokenError as e:
        return False, str(e)
    if len(chain) <= 1:
        return True, ""

    for ancestor in chain[:-1]:  # every ancestor except the requesting agent itself
        action_ok = action.lower() in {a.lower() for a in ancestor.authorized_actions}
        if not action_ok:
            return False, (
                f"Action '{action}' was not delegated by '{ancestor.agent_id}' "
                f"(ancestor allowed: {ancestor.authorized_actions})"
            )

        resource_ok = any(
            fnmatch.fnmatch(resource, pattern) or
            (pattern.endswith("/*") and resource.startswith(pattern[:-2]))
            for pattern in ancestor.authorized_resources
        )
        if not resource_ok:
            return False, (
                f"Resource '{resource}' is outside scope delegated by '{ancestor.agent_id}' "
                f"(ancestor scope: {ancestor.authorized_resources})"
            )

    return True, ""


def compute_chain_trust_multiplier(delegation_depth: int) -> float:
    """Each delegation hop reduces effective trust — a long chain is inherently riskier."""
    return max(0.5, 1.0 - delegation_depth * CHAIN_TRUST_DECAY)


def chain_summary(agent_id: str, agents: dict) -> str:
    """Return a human-readable chain string like 'root → analyst → summarizer'."""
    try:
        chain = get_chain(agent_id, agents)
        return " -> ".join(a.agent_id for a in chain)
    except ChainBrokenError as e:
        return f"{agent_id} [BROKEN CHAIN: {e}]"
