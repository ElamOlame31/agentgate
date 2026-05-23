import hashlib
import os
import re
import sqlite3
import json
import time
import uuid
from pathlib import Path
from core.models import AuthorizationResponse, AgentRegistration

# Regex that matches a UUID v4 — tokens stored before H2 are plaintext UUIDs.
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE
)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token. Used for storage and comparison."""
    return hashlib.sha256(token.encode()).hexdigest()

DB_PATH = Path(__file__).parent.parent / "agentgate_audit.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            agent_id TEXT,
            action TEXT,
            resource TEXT,
            decision TEXT,
            trust_score REAL,
            identity_score REAL,
            delegation_score REAL,
            purpose_score REAL,
            behavioral_score REAL,
            resource_sensitivity TEXT,
            explanation TEXT,
            attack_flags TEXT,
            full_json TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT,
            declared_purpose TEXT,
            authorized_resources TEXT,
            authorized_actions TEXT,
            delegated_by TEXT,
            delegation_depth INTEGER,
            token TEXT,
            registered_at REAL,
            token_expires_at REAL DEFAULT NULL,
            processes_external_content INTEGER DEFAULT 0,
            requires_human_approval INTEGER DEFAULT 0,
            scope_at_delegation TEXT DEFAULT NULL
        )
    """)
    # Migrate existing tables that predate these columns
    _allowed_migrations = {
        "processes_external_content": "0",
        "requires_human_approval": "0",
        "scope_at_delegation": "NULL",
        "token_expires_at": "NULL",
    }
    for col, default in _allowed_migrations.items():
        try:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} TEXT DEFAULT {default}")
        except Exception:
            pass  # column already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_history (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            action TEXT,
            resource TEXT,
            timestamp REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_baselines (
            agent_id TEXT PRIMARY KEY,
            total_requests INTEGER DEFAULT 0,
            avg_rpm REAL DEFAULT 0.0,
            peak_rpm REAL DEFAULT 0.0,
            last_updated REAL DEFAULT 0.0,
            window_start REAL DEFAULT 0.0,
            window_count INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def log_decision(response: AuthorizationResponse, record_history: bool = True):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        response.request_id,
        response.timestamp,
        response.agent_id,
        response.action,
        response.resource,
        response.decision.value,
        response.trust_breakdown.final_score,
        response.trust_breakdown.identity_score,
        response.trust_breakdown.delegation_score,
        response.trust_breakdown.purpose_alignment_score,
        response.trust_breakdown.behavioral_score,
        response.trust_breakdown.resource_sensitivity.value,
        response.explanation,
        json.dumps(response.attack_flags),
        response.model_dump_json()
    ))
    # Don't record unregistered-agent probes in request_history — they would
    # poison the velocity baseline for any agent later registered with that ID.
    if record_history:
        conn.execute("""
            INSERT INTO request_history VALUES (?,?,?,?,?)
        """, (str(uuid.uuid4()), response.agent_id, response.action, response.resource, response.timestamp))
    conn.commit()
    conn.close()


def get_recent_decisions(limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_decisions_in_range(from_ts: float, to_ts: float) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp DESC",
        (from_ts, to_ts)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_agent_decisions(agent_id: str, limit: int = 100) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?",
        (agent_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_request_history(agent_id: str, action: str, resource: str):
    """Record a single request in the history window (used by trust engine + tests)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO request_history VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), agent_id, action, resource, time.time())
    )
    conn.commit()
    conn.close()


def get_agent_request_history(agent_id: str, window_seconds: float = 60.0) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cutoff = time.time() - window_seconds
    rows = conn.execute(
        "SELECT * FROM request_history WHERE agent_id=? AND timestamp>? ORDER BY timestamp DESC",
        (agent_id, cutoff)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


TOKEN_TTL = max(60.0, float(os.getenv("AGENTGATE_TOKEN_TTL", str(24 * 3600))))


def save_agent(agent: AgentRegistration):
    # Store the hash of the token, never the plaintext.
    # agent.token at this point is already a SHA-256 hex digest (set by the server
    # endpoints before calling save_agent), so we write it directly.
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO agents
        (agent_id, name, declared_purpose, authorized_resources, authorized_actions,
         delegated_by, delegation_depth, token, registered_at, token_expires_at,
         processes_external_content, requires_human_approval, scope_at_delegation)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        agent.agent_id, agent.name, agent.declared_purpose,
        json.dumps(agent.authorized_resources),
        json.dumps(agent.authorized_actions),
        agent.delegated_by, agent.delegation_depth,
        agent.token, time.time(),
        time.time() + TOKEN_TTL,
        int(agent.processes_external_content),
        int(agent.requires_human_approval),
        json.dumps(agent.scope_at_delegation) if agent.scope_at_delegation else None,
    ))
    conn.commit()
    conn.close()


def load_all_agents() -> dict[str, AgentRegistration]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM agents").fetchall()
    result = {}
    for r in rows:
        d = dict(r)
        d["authorized_resources"] = json.loads(d["authorized_resources"])
        d["authorized_actions"] = json.loads(d["authorized_actions"])
        d["processes_external_content"] = bool(d.get("processes_external_content", 0))
        d["requires_human_approval"] = bool(d.get("requires_human_approval", 0))
        raw_scope = d.get("scope_at_delegation")
        d["scope_at_delegation"] = json.loads(raw_scope) if raw_scope else None
        d.pop("registered_at", None)
        # Migrate: tokens stored before H2 are plaintext UUIDs. Hash them now and
        # persist so future restarts don't need to re-migrate.
        if d.get("token") and _UUID_RE.match(d["token"]):
            hashed = hash_token(d["token"])
            conn.execute(
                "UPDATE agents SET token=? WHERE agent_id=?",
                (hashed, d["agent_id"])
            )
            d["token"] = hashed
        result[d["agent_id"]] = AgentRegistration(**d)
    conn.commit()
    conn.close()
    return result


def delete_agent(agent_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
    conn.execute("DELETE FROM agent_baselines WHERE agent_id=?", (agent_id,))
    conn.execute("DELETE FROM request_history WHERE agent_id=?", (agent_id,))
    conn.commit()
    conn.close()


def _ensure_baseline_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_baselines (
            agent_id TEXT PRIMARY KEY,
            total_requests INTEGER DEFAULT 0,
            avg_rpm REAL DEFAULT 0.0,
            peak_rpm REAL DEFAULT 0.0,
            last_updated REAL DEFAULT 0.0,
            window_start REAL DEFAULT 0.0,
            window_count INTEGER DEFAULT 0
        )
    """)


def update_agent_baseline(agent_id: str, current_rpm: float):
    """
    Exponential moving average of RPM per agent.
    alpha=0.1 means the baseline updates slowly — 10 requests in before it shifts significantly.
    This intentionally makes sudden spikes stand out against a stable baseline.
    """
    conn = sqlite3.connect(DB_PATH)
    _ensure_baseline_table(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM agent_baselines WHERE agent_id=?", (agent_id,)
    ).fetchone()

    now = time.time()
    if row is None:
        conn.execute(
            "INSERT INTO agent_baselines VALUES (?,?,?,?,?,?,?)",
            (agent_id, 1, current_rpm, current_rpm, now, now, 1)
        )
    else:
        alpha = 0.15
        new_avg = alpha * current_rpm + (1 - alpha) * row["avg_rpm"]
        new_peak = max(row["peak_rpm"], current_rpm)
        new_total = row["total_requests"] + 1
        conn.execute(
            """UPDATE agent_baselines SET
               total_requests=?, avg_rpm=?, peak_rpm=?, last_updated=?
               WHERE agent_id=?""",
            (new_total, round(new_avg, 3), round(new_peak, 3), now, agent_id)
        )
    conn.commit()
    conn.close()


def get_agent_baseline(agent_id: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    _ensure_baseline_table(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM agent_baselines WHERE agent_id=?", (agent_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_baselines() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    _ensure_baseline_table(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM agent_baselines").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cleanup_old_history(max_age_seconds: float = 3600.0):
    """Prune request_history older than max_age_seconds to prevent unbounded growth."""
    conn = sqlite3.connect(DB_PATH)
    cutoff = time.time() - max_age_seconds
    conn.execute("DELETE FROM request_history WHERE timestamp<?", (cutoff,))
    conn.commit()
    conn.close()


def cleanup_old_audit_log(max_age_days: int = 90):
    """Prune audit_log entries older than max_age_days to cap database size."""
    days = max(1, int(os.getenv("AGENTGATE_AUDIT_RETENTION_DAYS", str(max_age_days))))
    conn = sqlite3.connect(DB_PATH)
    cutoff = time.time() - days * 86400
    conn.execute("DELETE FROM audit_log WHERE timestamp<?", (cutoff,))
    conn.commit()
    conn.close()


def get_stats() -> dict:
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    permits = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='PERMIT'").fetchone()[0]
    denials = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='DENY'").fetchone()[0]
    escalations = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='ESCALATE'").fetchone()[0]
    avg_score = conn.execute("SELECT AVG(trust_score) FROM audit_log").fetchone()[0] or 0
    attacks = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE attack_flags != '[]'"
    ).fetchone()[0]
    conn.close()
    return {
        "total_requests": total,
        "permits": permits,
        "denials": denials,
        "escalations": escalations,
        "avg_trust_score": round(avg_score, 1),
        "attack_flags_raised": attacks,
    }
