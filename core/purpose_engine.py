from sentence_transformers import SentenceTransformer
import numpy as np
from functools import lru_cache

_model: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


@lru_cache(maxsize=512)
def _embed(text: str) -> tuple:
    vec = _get_model().encode(text, convert_to_numpy=True)
    return tuple(vec.tolist())


def _cosine(a: tuple, b: tuple) -> float:
    va, vb = np.array(a), np.array(b)
    denom = np.linalg.norm(va) * np.linalg.norm(vb)
    if denom == 0:
        return 0.0
    return float(np.dot(va, vb) / denom)


def score_purpose_alignment(declared_purpose: str, action: str, resource: str, justification: str = "") -> float:
    """
    Returns 0-100. How well does (action + resource + justification) align
    with the agent's declared purpose?
    """
    request_text = f"{action} {resource} {justification}".strip()
    purpose_vec = _embed(declared_purpose)
    request_vec = _embed(request_text)
    similarity = _cosine(purpose_vec, request_vec)
    # Similarity is -1 to 1; map to 0-100
    score = (similarity + 1) / 2 * 100
    return round(score, 2)


# Actions that are destructive by nature
_DESTRUCTIVE_ACTIONS = {"delete", "remove", "drop", "truncate", "wipe", "purge", "destroy", "overwrite"}

# Actions that move data outside the system — exfiltration signals
_EXFILTRATION_ACTIONS = {"write", "send", "upload", "export", "forward", "post", "publish"}

# Paths that are sensitive and should penalize out-of-scope agents
_SENSITIVE_PATHS = {"confidential", "salary", "payroll", "password", "secret", "private", "admin", "root", "cred"}

# Paths that indicate data is leaving the system
_EXTERNAL_PATHS = {"external", "email", "webhook", "smtp", "ftp", "s3", "upload", "export", "outbound"}

# Words indicating a read-only declared purpose
_READ_PURPOSE_WORDS = {"read", "summarize", "analyze", "view", "list", "search", "query", "report"}


def get_action_penalty(declared_purpose: str, action: str, resource: str) -> float:
    """
    Returns a penalty multiplier (0.0 to 1.0) based on action/resource danger signals.
    1.0 = no penalty, 0.0 = maximum penalty.
    """
    purpose_lower = declared_purpose.lower()
    action_lower = action.lower()
    resource_lower = resource.lower()

    penalty = 1.0
    is_read_purpose = any(w in purpose_lower for w in _READ_PURPOSE_WORDS)

    # Destructive action by a read-purpose agent
    if action_lower in _DESTRUCTIVE_ACTIONS and is_read_purpose:
        penalty *= 0.2

    # Exfiltration: write/send/upload by a read-purpose agent to an external destination
    if action_lower in _EXFILTRATION_ACTIONS and is_read_purpose:
        penalty *= 0.25

    # Writing to an external path (data leaving the system)
    if any(kw in resource_lower for kw in _EXTERNAL_PATHS):
        if is_read_purpose:
            penalty *= 0.2

    # Accessing sensitive paths outside declared scope
    if any(kw in resource_lower for kw in _SENSITIVE_PATHS):
        if not any(kw in purpose_lower for kw in _SENSITIVE_PATHS):
            penalty *= 0.3

    return penalty


def compute_purpose_score(declared_purpose: str, action: str, resource: str, justification: str = "") -> float:
    base = score_purpose_alignment(declared_purpose, action, resource, justification)
    penalty = get_action_penalty(declared_purpose, action, resource)
    return round(base * penalty, 2)
