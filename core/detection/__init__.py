"""
Detection: signals that something looks wrong.

Heuristics, and labelled as such. They find patterns the lattice cannot see —
a sequence of individually legitimate reads, an instruction hidden in a
document — at the cost of being arguable and occasionally wrong.

    kill_chain          multi-step patterns across a session
    injection_detector  instructions embedded in content
    output_sanitizer    what an agent emits, before it travels
    quarantine          the state between active and revoked
    contagion           penalty across a delegation chain
    purpose_engine      semantic distance between an action and a declared purpose
"""
