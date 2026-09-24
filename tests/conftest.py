"""
Test isolation for the AgentGate suite.

Two separate problems are handled here.

First, modules under core/ resolve the audit database path and the HMAC log key
at import time, so both must be set before the first `core.*` import happens.
conftest.py is imported before any test module, which makes the module-level
block below the only place that can run early enough. Without it the suite
writes into the developer's real agentgate_audit.db: chain-integrity assertions
then depend on whatever history that file already holds — a log key rotated at
any point in the past leaves every later run failing verify_chain() — and alert
delivery fires real HTTP requests at ntfy.sh.

Second, the process keeps a good deal of state outside the database: the agent
registry and recent scans live in module-level dicts in server/main.py, and
approvals, quarantines and contagion records do the same in core/. Every test
file passes on its own, but running them together leaks agents and counters
across files. Each module therefore gets a fresh database and clean stores.
"""

import os
import tempfile
import uuid
from pathlib import Path

_SESSION_DB = Path(tempfile.gettempdir()) / f"agentgate_test_{uuid.uuid4().hex}.db"

# load_dotenv() does not overwrite variables already present in the
# environment, so what we set here wins over .env for the whole session.
os.environ["AGENTGATE_DB_PATH"] = str(_SESSION_DB)
os.environ["AGENTGATE_LOG_KEY"] = "agentgate-test-log-key"
os.environ["AGENTGATE_ALERT_TOPIC"] = ""   # no ntfy push notifications
os.environ["AGENTGATE_WEBHOOK_URL"] = ""   # no Slack / Teams webhook

import pytest  # noqa: E402  — must come after the environment is fixed


def _unlink_db(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def _clear_process_state() -> None:
    """Drop every in-process store the server and core modules keep."""
    from core import approvals, contagion, quarantine

    # Timers fire _auto_deny() on a background thread; cancel before dropping
    # the store or a stale timer can resolve an approval in the next module.
    for timer in approvals._timers.values():
        timer.cancel()
    approvals._timers.clear()
    approvals._store.clear()
    contagion._store.clear()
    quarantine._store.clear()
    quarantine._deny_windows.clear()

    try:
        from server import main as server_main
    except Exception:  # server not importable in a pure-core test run
        return
    server_main._agents.clear()
    server_main._recent_scans.clear()


@pytest.fixture(scope="session", autouse=True)
def _session_db():
    """Back-stop for anything touching the DB outside a module fixture."""
    from core.audit import init_db

    init_db()
    yield
    _unlink_db(_SESSION_DB)


@pytest.fixture(scope="module", autouse=True)
def _isolated_module_state():
    """Fresh database and clean in-process stores for each test module."""
    import core.audit as audit
    import core.policy_engine as policy_engine

    db = Path(tempfile.gettempdir()) / f"agentgate_test_{uuid.uuid4().hex}.db"
    audit.DB_PATH = db
    policy_engine.DB_PATH = db
    audit.init_db()
    _clear_process_state()

    yield

    _clear_process_state()
    _unlink_db(db)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear the in-memory rate-limit counters before every test.

    /authorize is capped at 200/minute and slowapi keys counters by client IP,
    which TestClient holds constant. Run enough test files together and later
    ones get 429s instead of decisions — the engine is never reached, so the
    assertion failures point anywhere but the real cause. Two test modules
    already carried a local copy of this fixture; it belongs to every module.
    """
    from server.main import limiter

    limiter.reset()
    yield
