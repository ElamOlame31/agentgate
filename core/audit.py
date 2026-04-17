import sqlite3
import json
import time
import uuid
from pathlib import Path
from core.models import AuthorizationResponse

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
            registered_at REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_history (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            action TEXT,
            resource TEXT,
            timestamp REAL
        )
    """)
    conn.commit()
    conn.close()


def log_decision(response: AuthorizationResponse):
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
