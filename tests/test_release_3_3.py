from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_examples import rebind_action, refresh_audit  # noqa: E402
from validate_contracts import collection_errors, digest, load, record_errors, validate_envelope  # noqa: E402


class DelegatedRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/delegated-envelope.json")
        self.request = self.envelope["request"]
        self.root = self.envelope["proposal"]["delegation_chain"][0]

    def test_review_relayed_through_the_parent_call(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])

    def test_relay_must_be_an_ancestor_of_the_proposing_call(self) -> None:
        call_id = self.envelope["proposal"]["call_id"]
        self.request["relay"][0]["call_id"] = call_id
        self.assertIn(f"relay hop {call_id} is not an ancestor of the proposing call", validate_envelope(self.envelope))

    def test_relay_names_the_agent_of_its_hop(self) -> None:
        self.request["relay"][0]["agent_identity"] = "agent.other-orchestrator.prod"
        self.assertIn(f"relay hop {self.root['call_id']} names another agent than its delegation hop", validate_envelope(self.envelope))

    def test_relay_climbs_the_chain_once_per_hop(self) -> None:
        self.request["relay"].append(dict(self.request["relay"][0]))
        self.assertIn("relay hops do not climb the delegation chain nearest first", validate_envelope(self.envelope))

    def test_relay_happens_while_the_request_is_open(self) -> None:
        self.request["relay"][0]["relayed_at"] = self.request["expires_at"]
        self.assertIn(f"relay hop {self.root['call_id']} was relayed outside the request window", validate_envelope(self.envelope))

    def test_relaying_agent_cannot_decide(self) -> None:
        approval = self.envelope["approvals"][0]
        approval["decided_by"]["identifier"] = self.root["agent"]["identity"]
        self.assertIn(f"approval {approval['approval_id']} was decided by a relaying agent", validate_envelope(self.envelope))

    def test_every_relay_hop_has_its_audit_witness(self) -> None:
        self.envelope["audit_events"] = [e for e in self.envelope["audit_events"] if e["event_type"] != "approval.relayed"]
        refresh_audit(self.envelope)
        self.assertIn("audit approval.relayed witnesses disagree with the request relay", validate_envelope(self.envelope))

    def test_relay_witness_without_a_relay(self) -> None:
        self.request.pop("relay")
        self.assertIn("audit approval.relayed witnesses disagree with the request relay", validate_envelope(self.envelope))


class PendingNoticeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/delegated-envelope.json")
        self.child, self.parent = self.envelope["pending_notices"]

    def test_standalone_notice(self) -> None:
        self.assertEqual(record_errors("approval-pending-notice", load("examples/approval-pending-notice.json")), [])

    def test_poll_needs_a_next_check(self) -> None:
        self.parent.pop("next_check_at")
        self.assertTrue(record_errors("approval-pending-notice", self.parent))

    def test_next_check_inside_the_pending_window(self) -> None:
        self.parent["next_check_at"] = "2026-04-28T18:00:00Z"
        self.assertIn("pending notice notice_2026-04-28_parent01 next_check_at is outside its pending window",
                      record_errors("approval-pending-notice", self.parent))

    def test_notice_names_this_request(self) -> None:
        for field in ("request_id", "call_id", "action_hash"):
            with self.subTest(field=field):
                envelope = load("examples/delegated-envelope.json")
                notice = envelope["pending_notices"][0]
                notice[field] = "sha256:" + "0" * 64 if field == "action_hash" else "other_2026-04-28_0001"
                self.assertIn(f"pending notice {notice['notice_id']} {field} does not match the request", validate_envelope(envelope))

    def test_notice_goes_to_a_call_in_the_chain(self) -> None:
        self.parent["recipient_call_id"] = "call_2026-04-28_unrelated"
        self.assertIn("pending notice notice_2026-04-28_parent01 is addressed outside the delegation chain", validate_envelope(self.envelope))

    def test_notice_keeps_the_request_deadline(self) -> None:
        self.child["expires_at"] = "2026-04-28T18:14:23Z"
        self.assertIn("pending notice notice_2026-04-28_child01 misstates the request deadline", validate_envelope(self.envelope))

    def test_notice_only_while_pending(self) -> None:
        self.child["issued_at"] = "2026-04-28T09:14:31Z"
        self.assertIn("pending notice notice_2026-04-28_child01 was issued while the request was not pending", validate_envelope(self.envelope))

    def test_notice_cites_a_pending_revision(self) -> None:
        self.child["request_revision"] = self.envelope["request"]["revision"]
        self.assertIn("pending notice notice_2026-04-28_child01 cites a revision after the request left pending", validate_envelope(self.envelope))

    def test_notice_channels_were_used(self) -> None:
        self.child["channels"] = ["slack"]
        self.assertIn("pending notice notice_2026-04-28_child01 names a channel the request did not use", validate_envelope(self.envelope))

    def test_notice_ids_are_unique(self) -> None:
        self.parent["notice_id"] = self.child["notice_id"]
        self.assertIn("pending notices reuse notice_id", validate_envelope(self.envelope))


class EscalationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/escalated-envelope.json")
        self.request = self.envelope["request"]
        self.escalation = self.request["escalations"][0]

    def test_escalated_lifecycle(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])

    def test_escalation_needs_a_policy(self) -> None:
        self.request["policy"]["requirements"].pop("escalation")
        self.assertIn("request escalated without a policy escalation", validate_envelope(self.envelope))

    def test_escalation_waits_for_the_policy_delay(self) -> None:
        self.request["policy"]["requirements"]["escalation"]["after_seconds"] = 600
        self.assertIn("escalation at 2026-04-28T09:14:28Z came before the policy's escalation delay", validate_envelope(self.envelope))

    def test_escalation_only_while_pending(self) -> None:
        self.request["policy"]["requirements"]["escalation"]["after_seconds"] = 1
        self.escalation["escalated_at"] = "2026-04-28T09:14:31Z"
        self.assertIn("escalation at 2026-04-28T09:14:31Z happened after the request left pending", validate_envelope(self.envelope))

    def test_escalation_notifies_only_named_actors(self) -> None:
        self.escalation["notified_actor_ids"] = ["someone-else@acme-corp.example"]
        self.assertIn("escalation at 2026-04-28T09:14:28Z notified an actor the policy does not name", validate_envelope(self.envelope))

    def test_notified_actor_gains_no_decision_rights(self) -> None:
        approval = self.envelope["approvals"][0]
        approval["decided_by"]["identifier"] = "support-lead-oncall@acme-corp.example"
        self.assertIn("approval actor support-lead-oncall@acme-corp.example is not eligible under policy", validate_envelope(self.envelope))

    def test_every_escalation_has_its_audit_witness(self) -> None:
        self.envelope["audit_events"] = [e for e in self.envelope["audit_events"] if e["event_type"] != "approval.escalated"]
        refresh_audit(self.envelope)
        self.assertIn("audit approval.escalated witnesses disagree with the request escalations", validate_envelope(self.envelope))


class PolicyRefusalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/policy-denied-envelope.json")
        self.request = self.envelope["request"]
        self.refusal = self.request["policy_refusal"]

    def test_denied_lifecycle_names_its_rule(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])

    def test_standalone_request_checks_its_refusal(self) -> None:
        self.refusal["rule_ids"] = ["rule.email.external-recipient"]
        self.assertIn("policy refusal names rule rule.email.external-recipient that did not deny",
                      record_errors("approval-request", self.request))

    def test_refusal_only_for_a_denied_request(self) -> None:
        envelope = load("examples/approval-envelope.json")
        envelope["request"]["policy_refusal"] = self.refusal
        self.assertIn("policy refusal on a request the policy did not deny", validate_envelope(envelope))

    def test_refusal_cites_this_evaluation(self) -> None:
        self.refusal["evaluation_id"] = "eval_2026-04-28_other0001"
        self.assertIn("policy refusal cites another policy evaluation", validate_envelope(self.envelope))

    def test_refusal_reason_follows_the_snapshot(self) -> None:
        self.refusal["reason_code"] = "no_matching_rule"
        self.assertIn("policy refusal reason disagrees with the policy snapshot", validate_envelope(self.envelope))

    def test_unavailable_evaluator_is_reported_as_such(self) -> None:
        policy = self.request["policy"]
        policy.update(evaluation_status="evaluator_unavailable")
        policy.pop("matched_rules")
        self.refusal.pop("rule_ids")
        self.refusal["reason_code"] = "evaluator_unavailable"
        self.assertEqual(validate_envelope(self.envelope), [])
        self.refusal["reason_code"] = "no_matching_rule"
        self.assertIn("policy refusal reason disagrees with the policy snapshot", validate_envelope(self.envelope))


class GrantOriginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuing = load("examples/grant-issuing-envelope.json")
        self.cited = load("examples/grant-origin-envelope.json")
        self.issued = self.issuing["approvals"][0]["issued_grant"]
        self.grant = self.cited["approvals"][0]["standing_grant"]

    def test_issuing_and_citing_lifecycles(self) -> None:
        self.assertEqual(validate_envelope(self.issuing), [])
        self.assertEqual(validate_envelope(self.cited), [])
        self.assertEqual(collection_errors([self.issuing, self.cited]), [])

    def test_only_an_approving_decision_issues_a_grant(self) -> None:
        approval = self.issuing["approvals"][0]
        approval.update(decision="rejected", rejection_settlement={"state": "unresolved"})
        self.assertIn(f"approval {approval['approval_id']} issues standing grant {self.issued['grant_id']} without approving",
                      validate_envelope(self.issuing))

    def test_grant_starts_at_or_after_the_decision(self) -> None:
        self.issued["granted_at"] = "2026-04-27T09:14:00Z"
        approval_id = self.issuing["approvals"][0]["approval_id"]
        self.assertIn(f"approval {approval_id} issues standing grant {self.issued['grant_id']} before its decision", validate_envelope(self.issuing))

    def test_policy_can_require_the_origin(self) -> None:
        self.grant.pop("origin")
        approval_id = self.cited["approvals"][0]["approval_id"]
        self.assertIn(f"approval {approval_id} standing grant does not name the approval that issued it", validate_envelope(self.cited))

    def test_origin_must_have_issued_the_grant(self) -> None:
        self.issuing["approvals"][0].pop("issued_grant")
        self.assertIn(f"envelopes 0 and 1: standing grant {self.grant['grant_id']} names approval {self.grant['origin']['approval_id']}, which did not issue it",
                      collection_errors([self.issuing, self.cited]))

    def test_cited_terms_match_the_issued_terms(self) -> None:
        self.grant["max_uses"] = 1000
        self.assertIn(f"envelopes 0 and 1: standing grant {self.grant['grant_id']} changes the terms its approval issued",
                      collection_errors([self.issuing, self.cited]))

    def test_a_grant_is_issued_once(self) -> None:
        second = load("examples/grant-issuing-envelope.json")
        self.assertIn(f"envelopes 0 and 1: issue standing grant {self.issued['grant_id']} twice", collection_errors([self.issuing, second]))


class PolicyEvaluatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load("examples/approval-policy-external.json")
        self.evaluator = self.policy["evaluator"]

    def test_external_decision_point(self) -> None:
        self.assertEqual(record_errors("approval-policy", self.policy), [])

    def test_external_decision_names_its_protocol(self) -> None:
        self.evaluator.pop("protocol")
        self.assertTrue(record_errors("approval-policy", self.policy))

    def test_external_decision_keeps_its_answer(self) -> None:
        self.evaluator.pop("decision_id")
        self.assertIn("external policy decision lacks its decision_id or response time", record_errors("approval-policy", self.policy))

    def test_unavailable_decision_point_has_no_answer(self) -> None:
        self.policy.update(evaluation_status="evaluator_unavailable", outcome="deny")
        self.policy.pop("matched_rules")
        self.assertIn("an unavailable policy decision point cannot carry its answer", record_errors("approval-policy", self.policy))
        for key in ("decision_id", "responded_at"):
            self.evaluator.pop(key)
        self.assertEqual(record_errors("approval-policy", self.policy), [])

    def test_answer_precedes_the_snapshot(self) -> None:
        self.evaluator["responded_at"] = "2026-04-28T09:14:25Z"
        self.assertIn("policy evaluator responded after the snapshot was taken", record_errors("approval-policy", self.policy))

    def test_envelope_checks_its_evaluator(self) -> None:
        envelope = load("examples/approval-envelope.json")
        envelope["request"]["policy"]["evaluator"] = {"kind": "external_pdp", "identifier": "pdp.acme-corp.example", "protocol": "opa"}
        self.assertIn("external policy decision lacks its decision_id or response time", validate_envelope(envelope))


class SupersessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/superseded-envelope.json")
        self.successor = load("examples/approval-envelope.json")
        self.request = self.envelope["request"]

    def test_superseded_request_and_its_successor(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])
        self.assertEqual(collection_errors([self.envelope, self.successor]), [])

    def test_supersession_names_its_successor(self) -> None:
        self.request.pop("superseded_by")
        self.assertEqual(validate_envelope(self.envelope), ["envelope fails structural validation"])

    def test_successor_is_another_request(self) -> None:
        self.request["superseded_by"]["request_id"] = self.request["request_id"]
        self.assertIn("superseded request names itself as its successor", validate_envelope(self.envelope))

    def test_late_answer_to_a_superseded_request_is_refused(self) -> None:
        approval = dict(load("examples/grant-issuing-envelope.json")["approvals"][0])
        approval.pop("issued_grant")
        approval["decided_at"] = approval["recorded_at"] = "2026-04-27T09:14:30Z"
        self.envelope["approvals"] = [approval]
        self.assertIn(f"approval {approval['approval_id']} answers a request that was superseded", validate_envelope(self.envelope))

    def test_cancellation_witness_states_the_supersession(self) -> None:
        for event in self.envelope["audit_events"]:
            if event["event_type"] == "approval.cancelled":
                event["detail"]["reason_code"] = "cancelled_by_requester"
        refresh_audit(self.envelope)
        self.assertIn("audit cancellation reason disagrees with the supersession", validate_envelope(self.envelope))

    def test_successor_is_the_named_proposal(self) -> None:
        self.request["superseded_by"]["proposal_id"] = "prop_2026-04-28_other0001"
        self.assertIn(f"envelopes 0 and 1: request {self.request['request_id']} names a successor for another proposal or tenant",
                      collection_errors([self.envelope, self.successor]))

    def test_successor_comes_after(self) -> None:
        self.successor["proposal"]["created_at"] = "2026-04-27T09:00:00Z"
        self.assertIn(f"envelopes 0 and 1: request {self.request['request_id']} names a successor proposed before it",
                      collection_errors([self.envelope, self.successor]))


class TraceContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/traced-envelope.json")

    def test_traced_lifecycle(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])

    def test_events_stay_on_the_request_trace(self) -> None:
        event = self.envelope["audit_events"][4]
        event["trace_context"]["traceparent"] = "00-" + "1" * 32 + "-00f067aa0ba902b7-01"
        refresh_audit(self.envelope)
        self.assertIn(f"audit event {event['event_id']} belongs to another trace", validate_envelope(self.envelope))

    def test_event_trace_needs_a_request_trace(self) -> None:
        self.envelope["request"].pop("trace_context")
        self.assertIn(f"audit event {self.envelope['audit_events'][0]['event_id']} carries a trace context the request does not",
                      validate_envelope(self.envelope))

    def test_all_zero_trace_id_is_invalid(self) -> None:
        self.envelope["request"]["trace_context"]["traceparent"] = "00-" + "0" * 32 + "-00f067aa0ba902b7-01"
        self.assertIn("request trace context has an invalid trace ID", validate_envelope(self.envelope))

    def test_traceparent_shape(self) -> None:
        self.envelope["request"]["trace_context"]["traceparent"] = "4bf92f3577b34da6a3ce929d0e0e4736"
        self.assertEqual(validate_envelope(self.envelope), ["envelope fails structural validation"])


class NetworkEgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = load("examples/actions/network.egress.json")
        self.envelope = rebind_action(load("examples/approval-envelope.json"), "network.egress", self.payload)

    def test_complete_egress_lifecycle(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])

    def test_review_shows_destination_environment_and_scope(self) -> None:
        for field in ("host", "port", "protocol", "environment", "scope"):
            with self.subTest(field=field):
                envelope = rebind_action(load("examples/approval-envelope.json"), "network.egress", self.payload)
                review = envelope["review_snapshots"][0]
                review["content"]["target"].pop(field)
                review["content_hash"] = digest(review["content"])
                self.assertIn(f"review snapshot {review['snapshot_id']} changes the network.egress target", validate_envelope(envelope))

    def test_payload_names_one_destination(self) -> None:
        for host in ("*.npmjs.org", "https://registry.npmjs.org", "registry.npmjs.org/path", "Registry.npmjs.org"):
            with self.subTest(host=host):
                envelope = rebind_action(load("examples/approval-envelope.json"), "network.egress", dict(self.payload, host=host))
                self.assertEqual(validate_envelope(envelope), ["envelope fails structural validation"])

    def test_methods_only_for_http(self) -> None:
        envelope = rebind_action(load("examples/approval-envelope.json"), "network.egress", dict(self.payload, protocol="tcp"))
        self.assertEqual(validate_envelope(envelope), ["envelope fails structural validation"])


if __name__ == "__main__":
    unittest.main()
