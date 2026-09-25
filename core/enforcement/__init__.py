"""
Enforcement: whether an action may run, and whether data may reach a destination.

Two kinds of answer live here, and the difference matters.

    labels          information-flow lattice. A violation is a fact: what
                    leaves must not outrank where it goes, and content the
                    agent did not author does not choose the destination.
    trust_engine    weighted score across identity, delegation, purpose and
                    behaviour. A judgement, and arguable — which is why flow
                    violations are checked outside it rather than folded in.
    policy_engine   operator rules, evaluated before scoring
    delegation      chain walking and scope attenuation
"""
