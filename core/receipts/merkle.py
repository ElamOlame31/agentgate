"""
Merkle tree over audit log batches.

Leaf nodes:  SHA-256 of each entry's full_json string
Interior nodes: SHA-256 of left_child || right_child (concatenated hex strings)
Odd layers:  duplicate the last leaf/node to keep the tree complete

The root hash commits to the exact set and order of all entries in the batch.
Any single-byte modification to any entry invalidates the root in O(1), and
any entry's inclusion can be proven in O(log n) without revealing others.
"""

import hashlib


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def merkle_root(hashes: list[str]) -> str:
    """
    Compute the Merkle root of an ordered list of hex-string leaf hashes.
    Returns a single hex-string root hash.
    """
    if not hashes:
        return _sha256("empty-batch")
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_proof(hashes: list[str], index: int) -> list[dict]:
    """
    Build an inclusion proof for the leaf at `index`.
    Returns a list of {"sibling": <hex>, "position": "left"|"right"} steps.

    "position" describes where the SIBLING sits relative to the current node.
    To reconstruct a parent: if position=="right", parent = sha256(current + sibling)
                             if position=="left",  parent = sha256(sibling + current)
    """
    if not hashes:
        return []
    proof: list[dict] = []
    layer = list(hashes)
    idx = index
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        sibling_idx = idx ^ 1  # XOR with 1 flips the last bit: pairs 0↔1, 2↔3, ...
        proof.append({
            "sibling": layer[sibling_idx],
            "position": "right" if idx % 2 == 0 else "left",
        })
        layer = [_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        idx //= 2
    return proof


def verify_proof(leaf_hash: str, proof: list[dict], root: str) -> bool:
    """
    Verify that leaf_hash is a member of the Merkle tree identified by root.
    Replays the proof path bottom-up.
    """
    current = leaf_hash
    for step in proof:
        sibling = step["sibling"]
        if step["position"] == "right":
            current = _sha256(current + sibling)
        else:
            current = _sha256(sibling + current)
    return current == root


def leaf_hash(entry_json: str) -> str:
    """Canonical leaf hash for a single audit entry."""
    return _sha256(entry_json)
