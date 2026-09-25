"""
Receipts: what was authorized, provable to someone who was not there.

The layer that distinguishes this system from a policy engine. A decision that
only the issuer can confirm is a log entry; a decision anyone can check against
the operation that actually ran is evidence.

    action_ref         content address of an operation — every material
                       argument, recomputable by the caller at dispatch
    response_signing   HMAC over the decision, for the issuer's own checks
    receipt_signing    Ed25519 over the same bytes, for everyone else's
    receipts           one-time redemption, so an authorization is spent once
    merkle             batch commitment over the audit log
"""
