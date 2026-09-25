"""
Platform: the machinery the other packages stand on.

    audit       the record, its HMAC chain, and request history
    models      request and response shapes
    token       agent identity, Ed25519 JWT
    approvals   human-in-the-loop queue
    alerts      outbound notification and SIEM
    report      PDF and CSV export
    explainer   readable reasons, local by default
"""
