"""
Purpose drift detector — identifies when an agent's actions are systematically
drifting away from its declared purpose over time.

Each /authorize call computes a purpose alignment score for the current action.
This module examines the *trend* of those scores across the agent's recent history.
An agent that gradually shifts from its declared purpose is an early-stage
compromise signal that no single-request check can catch — it is invisible to
stateless evaluators that score requests independently.

Flags raised:
  PURPOSE_DRIFT:GRADUAL:Npts_below_baseline  — recent avg dropped >= DRIFT_THRESHOLD_GRADUAL
                                               pts below established baseline → ESCALATE
  PURPOSE_DRIFT:SUSTAINED_LOW:recent_avg=N   — recent avg below absolute floor regardless
                                               of baseline → ESCALATE

Both detectors run independently and can fire simultaneously.
"""
import sqlite3
import time
from pathlib import Path

def _default_db_path() -> str:
    """Whatever the audit module is using, read at call time.

    A module-level Path(__file__)-relative constant was wrong twice over: it
    broke the moment this file moved into a package, and it ignored
    AGENTGATE_DB_PATH, so a deployment pointing the database at a volume would
    have had this detector reading a different one. The import is deferred so
    the module still loads without the server's dependencies.
    """
    from core.platform import audit

    return str(audit.DB_PATH)

# ── Tunable constants — kept at module level so tests can inspect them ─────────

# Number of most-recent entries that define the "recent" comparison window.
RECENT_WINDOW: int = 10
# Number of oldest entries within the query window that define the baseline.
BASELINE_WINDOW: int = 30
# Minimum total entries before drift detection activates.
# Guards against cold-start false positives when an agent has little history.
MIN_ENTRIES_FOR_DRIFT: int = 15
# Minimum average drop (points, 0-100 scale) to raise a GRADUAL drift flag.
DRIFT_THRESHOLD_GRADUAL: float = 15.0
# Absolute floor: recent average below this always raises SUSTAINED_LOW,
# regardless of what the baseline was.
DRIFT_THRESHOLD_ABSOLUTE: float = 40.0
# Maximum age of audit entries considered (seconds) — matches kill chain window.
DRIFT_MAX_AGE_SECONDS: float = 86_400.0


def get_purpose_score_history(
    agent_id: str,
    db_path: "str | Path | None" = None,
) -> list:
    """
    Return purpose alignment scores for agent_id from the last 24 h,
    ordered oldest-first.  Returns [] on missing table or empty history.
    """
    path = str(db_path) if db_path else _default_db_path()
    try:
        conn = sqlite3.connect(path)
        cutoff = time.time() - DRIFT_MAX_AGE_SECONDS
        rows = conn.execute(
            """
            SELECT purpose_score FROM audit_log
            WHERE agent_id = ? AND timestamp >= ? AND purpose_score IS NOT NULL
            ORDER BY timestamp ASC
            """,
            (agent_id, cutoff),
        ).fetchall()
        conn.close()
        return [float(r[0]) for r in rows]
    except sqlite3.OperationalError:
        return []


def detect_purpose_drift(
    agent_id: str,
    db_path: "str | Path | None" = None,
) -> list:
    """
    Examine historical purpose alignment scores and return drift flags.

    Returns a list of PURPOSE_DRIFT:* flag strings; empty if no drift detected.
    The list is empty when the agent has fewer than MIN_ENTRIES_FOR_DRIFT entries
    in its 24-hour history — preventing cold-start false positives.
    """
    scores = get_purpose_score_history(agent_id, db_path=db_path)
    if len(scores) < MIN_ENTRIES_FOR_DRIFT:
        return []

    flags = []

    # Baseline: oldest BASELINE_WINDOW scores (fewer if total history is shorter)
    baseline_scores = scores[:BASELINE_WINDOW]
    baseline_avg = sum(baseline_scores) / len(baseline_scores)

    # Recent: newest RECENT_WINDOW scores
    recent_scores = scores[-RECENT_WINDOW:]
    recent_avg = sum(recent_scores) / len(recent_scores)

    # Detector 1: Gradual drift — significant drop from established baseline
    delta = baseline_avg - recent_avg
    if delta >= DRIFT_THRESHOLD_GRADUAL:
        flags.append(
            f"PURPOSE_DRIFT:GRADUAL:{round(delta)}pts"
            f"(baseline={round(baseline_avg)},recent={round(recent_avg)})"
        )

    # Detector 2: Sustained low — absolute floor regardless of baseline
    if recent_avg < DRIFT_THRESHOLD_ABSOLUTE:
        flags.append(
            f"PURPOSE_DRIFT:SUSTAINED_LOW:recent_avg={round(recent_avg)}"
        )

    return flags
