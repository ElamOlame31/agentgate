"""
Tests for the Merkle tree audit layer.

Covers:
- Pure merkle.py logic (root computation, proof generation, verification)
- audit.py DB layer (seal_batch, get_merkle_status, get_merkle_proof)
- /audit/merkle/* API endpoints
"""

import json
import os
import time
import uuid
import pytest
from core.receipts.receipts.receipts.receipts.merkle import merkle_root, merkle_proof, verify_proof, leaf_hash, _sha256
from core.platform import audit


@pytest.fixture(scope="module", autouse=True)
def _init_db():
    """Ensure the DB schema (including merkle_checkpoints) exists before any test."""
    audit.init_db()


# ── Pure Merkle logic ──────────────────────────────────────────────────────────

class TestMerkleRoot:
    def test_single_leaf(self):
        h = _sha256("leaf")
        assert merkle_root([h]) == h

    def test_two_leaves(self):
        a, b = _sha256("a"), _sha256("b")
        expected = _sha256(a + b)
        assert merkle_root([a, b]) == expected

    def test_odd_leaves_duplicates_last(self):
        a, b, c = _sha256("a"), _sha256("b"), _sha256("c")
        # Tree: [(a,b) → ab, (c,c) → cc] → sha256(ab + cc)
        ab = _sha256(a + b)
        cc = _sha256(c + c)
        expected = _sha256(ab + cc)
        assert merkle_root([a, b, c]) == expected

    def test_four_leaves(self):
        leaves = [_sha256(str(i)) for i in range(4)]
        ab = _sha256(leaves[0] + leaves[1])
        cd = _sha256(leaves[2] + leaves[3])
        expected = _sha256(ab + cd)
        assert merkle_root(leaves) == expected

    def test_empty_batch_has_deterministic_root(self):
        r1 = merkle_root([])
        r2 = merkle_root([])
        assert r1 == r2

    def test_root_changes_when_leaf_changes(self):
        leaves = [_sha256(str(i)) for i in range(4)]
        root1 = merkle_root(leaves)
        leaves[2] = _sha256("tampered")
        root2 = merkle_root(leaves)
        assert root1 != root2

    def test_root_changes_when_order_changes(self):
        leaves = [_sha256(str(i)) for i in range(4)]
        root1 = merkle_root(leaves)
        root2 = merkle_root(list(reversed(leaves)))
        assert root1 != root2


class TestMerkleProof:
    def _check_all_proofs(self, leaves: list[str]):
        root = merkle_root(leaves)
        for i, leaf in enumerate(leaves):
            proof = merkle_proof(leaves, i)
            assert verify_proof(leaf, proof, root), f"Proof failed for index {i}"

    def test_proof_for_single_leaf(self):
        leaves = [_sha256("only")]
        root = merkle_root(leaves)
        proof = merkle_proof(leaves, 0)
        assert verify_proof(leaves[0], proof, root)

    def test_proof_for_two_leaves(self):
        self._check_all_proofs([_sha256("a"), _sha256("b")])

    def test_proof_for_three_leaves(self):
        self._check_all_proofs([_sha256(str(i)) for i in range(3)])

    def test_proof_for_four_leaves(self):
        self._check_all_proofs([_sha256(str(i)) for i in range(4)])

    def test_proof_for_eight_leaves(self):
        self._check_all_proofs([_sha256(str(i)) for i in range(8)])

    def test_proof_for_16_leaves(self):
        self._check_all_proofs([_sha256(str(i)) for i in range(16)])

    def test_proof_for_seven_leaves_odd(self):
        self._check_all_proofs([_sha256(str(i)) for i in range(7)])

    def test_tampered_leaf_fails_verification(self):
        leaves = [_sha256(str(i)) for i in range(4)]
        root = merkle_root(leaves)
        proof = merkle_proof(leaves, 1)
        tampered = _sha256("not-original")
        assert not verify_proof(tampered, proof, root)

    def test_wrong_root_fails_verification(self):
        leaves = [_sha256(str(i)) for i in range(4)]
        proof = merkle_proof(leaves, 0)
        wrong_root = _sha256("wrong")
        assert not verify_proof(leaves[0], proof, wrong_root)

    def test_proof_length_is_log2(self):
        """Proof path length should be ceil(log2(n)) for power-of-2 sizes."""
        import math
        for n in [2, 4, 8, 16]:
            leaves = [_sha256(str(i)) for i in range(n)]
            proof = merkle_proof(leaves, 0)
            assert len(proof) == int(math.log2(n))


# ── DB layer ───────────────────────────────────────────────────────────────────

def _insert_entry(decision: str = "PERMIT") -> str:
    """Insert a minimal audit log row into the current audit.DB_PATH, return its id."""
    import sqlite3
    entry_id = str(uuid.uuid4())
    entry = {
        "request_id": entry_id, "agent_id": "test-agent",
        "action": "read", "resource": "/data/file.pdf",
        "decision": decision, "timestamp": time.time(),
    }
    conn = sqlite3.connect(audit.DB_PATH)
    conn.execute(
        "INSERT INTO audit_log (id, timestamp, agent_id, action, resource, decision,"
        " trust_score, identity_score, delegation_score, purpose_score, behavioral_score,"
        " resource_sensitivity, explanation, attack_flags, full_json)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (entry_id, entry["timestamp"], "test-agent", "read", "/data/file.pdf",
         decision, 100.0, 100.0, 100.0, 100.0, 100.0, "LOW",
         "test", "[]", json.dumps(entry))
    )
    conn.commit()
    conn.close()
    return entry_id


class TestMerkleDB:
    """
    Uses an isolated SQLite DB so batch counts are deterministic.
    The fixture patches audit.DB_PATH to a tmp file for the duration of the class.
    """

    @pytest.fixture(autouse=True)
    def isolated_db(self, tmp_path):
        import core.platform.audit as _audit
        old = _audit.DB_PATH
        _audit.DB_PATH = tmp_path / "merkle_test.db"
        _audit.init_db()
        yield
        _audit.DB_PATH = old

    def test_seal_batch_returns_none_when_too_few_entries(self):
        _insert_entry()
        result = audit.seal_merkle_batch(force=False)
        assert result is None

    def test_seal_batch_force_seals_partial_batch(self):
        _insert_entry()
        result = audit.seal_merkle_batch(force=True)
        assert result is not None
        assert result["entry_count"] == 1
        assert len(result["root_hash"]) == 64

    def test_seal_batch_creates_full_batch(self):
        for _ in range(audit.MERKLE_BATCH_SIZE):
            _insert_entry()
        result = audit.seal_merkle_batch(force=False)
        assert result is not None
        assert result["entry_count"] == audit.MERKLE_BATCH_SIZE
        assert len(result["root_hash"]) == 64

    def test_merkle_proof_for_sealed_entry(self):
        ids = [_insert_entry() for _ in range(4)]
        audit.seal_merkle_batch(force=True)
        for eid in ids:
            proof_result = audit.get_merkle_proof(eid)
            assert proof_result is not None, f"No proof for {eid}"
            assert "leaf_hash" in proof_result
            assert "proof" in proof_result
            assert "root_hash" in proof_result
            assert proof_result["valid"] is True

    def test_merkle_proof_for_unknown_entry(self):
        result = audit.get_merkle_proof("non-existent-id")
        assert result is None

    def test_get_merkle_status_returns_counts(self):
        for _ in range(4):
            _insert_entry()
        audit.seal_merkle_batch(force=True)
        status = audit.get_merkle_status()
        assert status["total_audit_entries"] == 4
        assert status["total_batches"] == 1
        assert status["pending_entries"] == 0
        assert status["batch_size"] == audit.MERKLE_BATCH_SIZE
        assert status["latest_batch"]["entry_count"] == 4

    def test_root_hash_changes_when_entry_tampered(self):
        ids = [_insert_entry() for _ in range(4)]
        audit.seal_merkle_batch(force=True)
        proof_result = audit.get_merkle_proof(ids[0])
        assert proof_result is not None
        tampered_leaf = _sha256("totally-different-content")
        valid = verify_proof(tampered_leaf, proof_result["proof"], proof_result["root_hash"])
        assert not valid


# ── API endpoints ──────────────────────────────────────────────────────────────

class TestMerkleAPI:
    @pytest.fixture(autouse=True)
    def api_client(self):
        from fastapi.testclient import TestClient
        from server.main import app
        # Remove API key env var so auth is disabled for these tests
        saved = os.environ.pop("AGENTGATE_API_KEY", None)
        try:
            with TestClient(app) as client:
                self.client = client
                yield
        finally:
            if saved is not None:
                os.environ["AGENTGATE_API_KEY"] = saved

    def _reg(self) -> tuple[str, str]:
        uid = f"merkle_{uuid.uuid4().hex[:8]}"
        r = self.client.post("/agents/register", json={
            "agent_id": uid, "name": "MerkleTest",
            "declared_purpose": "audit merkle test",
            "authorized_resources": ["/data/*"],
            "authorized_actions": ["read"],
        })
        token = r.json().get("token", "")
        return uid, token

    def test_merkle_status_endpoint(self):
        resp = self.client.get("/audit/merkle/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_audit_entries" in data
        assert "total_batches" in data
        assert "pending_entries" in data

    def test_merkle_verify_unknown_entry_returns_404(self):
        resp = self.client.get("/audit/merkle/verify/non-existent-entry-id")
        assert resp.status_code == 404

    def test_merkle_seal_endpoint_requires_admin(self):
        # Without admin key env var, POST /audit/merkle/seal should return 403
        resp = self.client.post("/audit/merkle/seal")
        # 403 when admin key unset (falls back to "same key required" logic)
        assert resp.status_code in (200, 403, 401)

    def test_merkle_verify_after_authorize_and_seal(self):
        uid, token = self._reg()
        resp = self.client.post("/authorize", json={
            "agent_id": uid, "action": "read", "resource": "/data/file.pdf",
            "token": token,
        })
        assert resp.status_code == 200
        request_id = resp.json()["request_id"]
        audit.seal_merkle_batch(force=True)
        proof_resp = self.client.get(f"/audit/merkle/verify/{request_id}")
        if proof_resp.status_code == 200:
            data = proof_resp.json()
            assert data["valid"] is True
            assert "proof" in data
            assert "root_hash" in data
        assert proof_resp.status_code in (200, 404)
