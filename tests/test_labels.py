"""
Information-flow labels: may this data reach this destination?

The properties under test are lattice properties, not judgements. A read raises
what the session has been exposed to; a sink is refused when it would carry that
exposure somewhere with less clearance, or when material the agent did not
author gets to choose where data goes.
"""

import pytest

from core.enforcement import labels
from core.platform import audit
from core.enforcement.labels import (
    Confidentiality, Integrity, FlowState,
    check_flow, compute_flow_state, confidentiality_of, extract_destinations,
)


def _trusted(level: Confidentiality, sources=None) -> FlowState:
    return FlowState(level, Integrity.TRUSTED, sources or [])


def _untrusted(level: Confidentiality = Confidentiality.PUBLIC) -> FlowState:
    return FlowState(level, Integrity.UNTRUSTED, [], "test")


# ── Grading ───────────────────────────────────────────────────────────────────

class TestGrading:
    @pytest.mark.parametrize("resource,expected", [
        ("/public/newsletter.txt", Confidentiality.PUBLIC),
        ("/reports/q3.pdf", Confidentiality.PUBLIC),
        ("/internal/roadmap.md", Confidentiality.INTERNAL),
        ("/hr/employee_list.csv", Confidentiality.CONFIDENTIAL),
        ("/hr/salary_2026.xlsx", Confidentiality.SECRET),
        ("/config/.env", Confidentiality.SECRET),
    ])
    def test_resources_land_on_the_right_level(self, resource, expected):
        assert confidentiality_of(resource) == expected

    def test_the_lattice_is_ordered(self):
        assert (Confidentiality.PUBLIC < Confidentiality.INTERNAL
                < Confidentiality.CONFIDENTIAL < Confidentiality.SECRET)

    def test_untrusted_is_the_lower_integrity_element(self):
        assert Integrity.UNTRUSTED < Integrity.TRUSTED


# ── Confidentiality: what leaves must not outrank where it goes ───────────────

class TestConfidentialityFlow:
    def test_secret_to_public_is_refused(self):
        flags = check_flow(_trusted(Confidentiality.SECRET), "export", "/public/out.pdf")
        assert any("CONFIDENTIALITY:SECRET_TO_PUBLIC" in f for f in flags)

    def test_secret_to_secret_is_allowed(self):
        assert check_flow(_trusted(Confidentiality.SECRET), "export", "/hr/vault.xlsx") == []

    def test_public_session_can_send_anywhere(self):
        assert check_flow(_trusted(Confidentiality.PUBLIC), "export", "/public/out.pdf") == []

    def test_reads_never_violate(self):
        """A read raises the watermark; it does not spend it."""
        for action in ("read", "search", "list", "query"):
            assert check_flow(_trusted(Confidentiality.SECRET), action, "/public/x") == []

    def test_the_least_cleared_destination_decides(self):
        """Data sent several places is only as contained as the loosest of them."""
        flags = check_flow(
            _trusted(Confidentiality.CONFIDENTIAL), "send", "/hr/copy.csv",
            arguments={"to": ["/hr/archive.csv", "/public/leak.csv"]},
        )
        assert any("CONFIDENTIALITY" in f for f in flags)

    def test_the_refusal_names_what_caused_it(self):
        state = _trusted(Confidentiality.SECRET, ["/hr/salary_2026.xlsx"])
        flags = check_flow(state, "export", "/public/out.pdf")
        reason = labels.explain_violation(flags, state)
        assert "/hr/salary_2026.xlsx" in reason


# ── Integrity: untrusted content must not pick the destination ────────────────

class TestIntegrityFlow:
    DECLARED = ["/outbox/*", "*@ourcompany.com"]

    def test_a_declared_destination_is_allowed(self):
        """Reading a ticket and replying to it is what a support agent is for."""
        flags = check_flow(
            _untrusted(), "send", "/outbox/reply.txt",
            arguments={"to": "customer@ourcompany.com"},
            allowed_destinations=self.DECLARED,
        )
        assert flags == []

    def test_a_redirected_destination_is_refused(self):
        """The poisoned ticket must not be able to re-address the reply."""
        flags = check_flow(
            _untrusted(), "send", "/outbox/reply.txt",
            arguments={"to": "attacker@evil.com"},
            allowed_destinations=self.DECLARED,
        )
        assert any("INTEGRITY:UNDECLARED_DESTINATION" in f for f in flags)

    def test_declaring_nothing_blocks_every_sink_once_untrusted(self):
        """An agent that never said where it sends cannot improvise one."""
        flags = check_flow(
            _untrusted(), "send", "/outbox/reply.txt",
            arguments={"to": "anyone@anywhere.com"},
            allowed_destinations=None,
        )
        assert any("INTEGRITY" in f for f in flags)

    def test_a_trusted_session_is_not_restricted_to_declared_destinations(self):
        """The restriction exists because untrusted material is present."""
        flags = check_flow(
            _trusted(Confidentiality.PUBLIC), "send", "/outbox/reply.txt",
            arguments={"to": "anyone@anywhere.com"},
            allowed_destinations=self.DECLARED,
        )
        assert flags == []

    def test_both_rules_can_fire_at_once(self):
        state = FlowState(Confidentiality.SECRET, Integrity.UNTRUSTED, ["/hr/pay.xlsx"], "test")
        flags = check_flow(state, "export", "/public/out.pdf",
                           arguments={"to": "attacker@evil.com"},
                           allowed_destinations=["/outbox/*"])
        assert any("CONFIDENTIALITY" in f for f in flags)
        assert any("INTEGRITY" in f for f in flags)


# ── Destinations live in arguments, not only in the path ──────────────────────

class TestDestinationExtraction:
    def test_the_resource_is_always_a_destination(self):
        assert "/outbox/x.txt" in extract_destinations("/outbox/x.txt", None)

    @pytest.mark.parametrize("arg", ["to", "recipient", "url", "webhook", "email", "channel"])
    def test_destination_bearing_arguments_are_picked_up(self, arg):
        found = extract_destinations("/outbox/x.txt", {arg: "somewhere@else.com"})
        assert "somewhere@else.com" in found

    def test_lists_of_recipients_are_expanded(self):
        found = extract_destinations("/o/x", {"recipients": ["a@b.com", "c@d.com"]})
        assert "a@b.com" in found and "c@d.com" in found

    def test_unrelated_arguments_are_not_destinations(self):
        found = extract_destinations("/o/x", {"amount_minor": 25000, "subject": "hi"})
        assert found == ["/o/x"]


# ── The state is derived from the trail, not held beside it ───────────────────

class TestFlowStateFromTheAuditTrail:
    def test_the_watermark_rises_with_what_was_read(self):
        aid = "flowagent_watermark"
        audit.log_request_history(aid, "read", "/reports/q3.pdf")
        assert compute_flow_state(aid).confidentiality == Confidentiality.PUBLIC
        audit.log_request_history(aid, "read", "/hr/salary_2026.xlsx")
        assert compute_flow_state(aid).confidentiality == Confidentiality.SECRET

    def test_the_watermark_does_not_fall_on_later_public_reads(self):
        """Exposure is not undone by reading something harmless afterwards."""
        aid = "flowagent_monotone"
        audit.log_request_history(aid, "read", "/hr/salary_2026.xlsx")
        audit.log_request_history(aid, "read", "/public/news.txt")
        assert compute_flow_state(aid).confidentiality == Confidentiality.SECRET

    def test_the_sources_that_raised_it_are_recorded(self):
        aid = "flowagent_sources"
        audit.log_request_history(aid, "read", "/hr/salary_2026.xlsx")
        assert "/hr/salary_2026.xlsx" in compute_flow_state(aid).sources

    def test_a_fresh_agent_starts_public_and_trusted(self):
        state = compute_flow_state("flowagent_brand_new")
        assert state.confidentiality == Confidentiality.PUBLIC
        assert state.integrity == Integrity.TRUSTED

    def test_declaring_external_content_makes_the_session_untrusted(self):
        state = compute_flow_state("flowagent_ext", processes_external_content=True)
        assert state.integrity == Integrity.UNTRUSTED
        assert state.untrusted_reason

    def test_a_detected_injection_makes_the_session_untrusted(self):
        state = compute_flow_state("flowagent_inj", injection_detected=True)
        assert state.integrity == Integrity.UNTRUSTED

    def test_the_same_trail_yields_the_same_state(self):
        """
        The claim in a receipt must be reproducible by whoever holds the trail,
        otherwise it is the server's word rather than evidence.
        """
        aid = "flowagent_reproducible"
        audit.log_request_history(aid, "read", "/hr/salary_2026.xlsx")
        a, b = compute_flow_state(aid), compute_flow_state(aid)
        assert a.canonical() == b.canonical()
        assert a.to_dict()["sources"] == b.to_dict()["sources"]


# ── The receipt carries the claim ─────────────────────────────────────────────

class TestFlowIsSigned:
    def test_the_signature_covers_the_flow_state(self):
        import time
        from core.receipts import response_signing as rs

        ts = time.time()
        nonce, mac = rs.sign_response("req-1", "a", "PERMIT", ts, "ref", "SECRET|TRUSTED")
        ok, _ = rs.verify_response(nonce, mac, "req-1", "a", "PERMIT", ts, "ref", "SECRET|TRUSTED")
        assert ok

    def test_altering_the_flow_state_invalidates_the_signature(self):
        """A receipt cannot be re-presented as if the session had been cleaner."""
        import time
        from core.receipts import response_signing as rs

        ts = time.time()
        nonce, mac = rs.sign_response("req-1", "a", "PERMIT", ts, "ref", "SECRET|TRUSTED")
        ok, why = rs.verify_response(
            nonce, mac, "req-1", "a", "PERMIT", ts, "ref", "PUBLIC|TRUSTED")
        assert not ok
        assert why == "SIGNATURE_MISMATCH"

    def test_signing_info_advertises_the_field(self):
        from core.receipts import response_signing as rs
        assert "flow" in rs.get_signing_info()["canonical_fields"]
