from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_examples import refresh_audit  # noqa: E402
from validate_contracts import (  # noqa: E402
    apply_operations, digest, load, payload_errors, strict_json_loads, validate_envelope,
)


class LifecycleHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/approval-envelope.json")

    def assert_refused(self, envelope: dict, reason: str) -> None:
        refresh_audit(envelope)
        errors = validate_envelope(envelope)
        self.assertTrue(any(reason in error for error in errors), errors)

    def test_positive_terminal_and_recovery_lifecycles(self) -> None:
        for name in ("approval", "edited", "rejected", "expired", "recovered", "revoked"):
            with self.subTest(name=name):
                self.assertEqual(validate_envelope(load(f"examples/{name}-envelope.json")), [])

    def two_approvals(self, *, modified: bool = False) -> dict:
        envelope = self.envelope
        request = envelope["request"]
        request["policy"]["requirements"]["minimum_approvals"] = 2
        request["policy"]["requirements"]["separation_of_duties"]["eligible_approver_ids"].append("second@example.com")
        approval = deepcopy(envelope["approvals"][0])
        approval["approval_id"] = "approval_second_01"
        approval["decided_by"]["identifier"] = "second@example.com"
        approval["signatures"][0]["key_id"] = "second-signing-key"
        if modified:
            approval["modifications"] = [{"op": "replace", "path": "/payload/subject", "value": "Changed subject"}]
            effective = apply_operations(envelope["proposal"], approval["modifications"])
            approval["action_hash"] = digest(effective)
            approval["payload_hash"] = digest(effective["payload"])
            review = deepcopy(envelope["review_snapshots"][0])
            review["snapshot_id"] = "review_second_01"
            review["action_hash"] = approval["action_hash"]
            review["payload_hash"] = approval["payload_hash"]
            review["content"]["arguments"] = effective["payload"]
            review["content_hash"] = digest(review["content"])
            approval["review_snapshot_id"] = review["snapshot_id"]
            approval["review_content_hash"] = review["content_hash"]
            envelope["review_snapshots"].append(review)
            event = deepcopy(envelope["audit_events"][3])
            event["event_id"] = "event_second_review"
            event["references"]["review_snapshot_id"] = review["snapshot_id"]
            event["detail"].update(action_hash=review["action_hash"], payload_hash=review["payload_hash"], review_content_hash=review["content_hash"])
            envelope["audit_events"].insert(4, event)
        envelope["approvals"].append(approval)
        resolution = deepcopy(envelope["resolutions"][0])
        resolution.update(resolution_id="resolution_second_01", approval_id=approval["approval_id"], approval_record_hash=digest(approval), action_hash=approval["action_hash"])
        envelope["resolutions"].append(resolution)
        authority = envelope["authority_snapshots"][0]
        approver = deepcopy(authority["subjects"][0])
        approver["identifier"] = "second@example.com"
        authority["subjects"].append(approver)
        authority["authority_digest"] = digest(authority["subjects"])
        for event_type, record in (("approval.decided", approval), ("resolution.emitted", resolution)):
            original = next(e for e in envelope["audit_events"] if e["event_type"] == event_type)
            event = deepcopy(original)
            event["event_id"] = "event_second_" + event_type.replace(".", "_")
            event["references"]["approval_id"] = approval["approval_id"]
            event["detail"]["action_hash"] = approval["action_hash"]
            if event_type == "approval.decided":
                event["actor"] = deepcopy(approval["decided_by"])
                event["detail"]["payload_hash"] = approval["payload_hash"]
            else:
                event["references"]["resolution_id"] = resolution["resolution_id"]
            index = envelope["audit_events"].index(original)
            envelope["audit_events"].insert(index + 1, event)
        refresh_audit(envelope)
        return envelope

    def test_dispatch_must_cite_full_quorum(self) -> None:
        envelope = self.two_approvals()
        self.assert_refused(envelope, "dispatch " + envelope["dispatches"][0]["dispatch_id"] + " approval quorum")
        envelope["dispatches"][0]["approval_ids"].append("approval_second_01")
        self.assertEqual(validate_envelope(envelope), [])

    def test_approvals_for_different_actions_do_not_form_quorum(self) -> None:
        envelope = self.two_approvals(modified=True)
        envelope["dispatches"][0]["approval_ids"].append("approval_second_01")
        self.assert_refused(envelope, "mixes or lacks approved action hashes")

    def test_payload_revalidation_after_edits(self) -> None:
        for operation in ({"op": "remove", "path": "/payload/subject"},
                          {"op": "replace", "path": "/payload/to", "value": ["invalid-address"]},
                          {"op": "add", "path": "/payload/unreviewed", "value": True}):
            with self.subTest(operation=operation):
                envelope = deepcopy(self.envelope)
                envelope["approvals"][0]["modifications"] = [operation]
                self.assert_refused(envelope, "effective payload fails its action schema")

    def test_patch_cannot_remove_payload_container(self) -> None:
        self.envelope["approvals"][0]["modifications"] = [{"op":"remove", "path":"/payload"}]
        self.assert_refused(self.envelope, "effective action fails proposal schema")

    def test_review_target_follows_the_effective_recipients(self) -> None:
        envelope = load("examples/edited-envelope.json")
        approval = envelope["approvals"][0]
        approval["modifications"].append({"op":"replace", "path":"/payload/to/0", "value":"new@example.com"})
        effective = apply_operations(envelope["proposal"], approval["modifications"])
        approval["action_hash"] = digest(effective)
        approval["payload_hash"] = digest(effective["payload"])
        review = envelope["review_snapshots"][-1]
        review["content"]["arguments"] = deepcopy(effective["payload"])
        review["content"]["target"]["to"] = ["new@example.com"]
        review.update(action_hash=approval["action_hash"], payload_hash=approval["payload_hash"], content_hash=digest(review["content"]))
        approval["review_content_hash"] = review["content_hash"]
        envelope["resolutions"][0].update(action_hash=approval["action_hash"], approval_record_hash=digest(approval))
        envelope["authority_snapshots"][0]["action_hash"] = approval["action_hash"]
        envelope["dispatches"][0]["action_hash"] = approval["action_hash"]
        for event in envelope["audit_events"][4:]:
            if "action_hash" in event["detail"]:
                event["detail"]["action_hash"] = approval["action_hash"]
            if "payload_hash" in event["detail"]:
                event["detail"]["payload_hash"] = approval["payload_hash"]
            if "review_content_hash" in event["detail"]:
                event["detail"]["review_content_hash"] = review["content_hash"]
        refresh_audit(envelope)
        self.assertEqual(validate_envelope(envelope), [])

    def test_payload_schema_binding(self) -> None:
        for field, value, reason in (("digest", "sha256:" + "0" * 64, "payload schema digest mismatch"),
                                     ("id", "https://untrusted.example/v3.0.0/action.json", "trusted local catalog"),
                                     ("version", "0.0.0", "payload schema version mismatch")):
            envelope = deepcopy(self.envelope)
            envelope["proposal"]["payload_schema"][field] = value
            with self.subTest(field=field):
                self.assert_refused(envelope, reason)

    def test_trusted_custom_payload_catalog(self) -> None:
        action = deepcopy(self.envelope["proposal"])
        schema = {"$schema":"https://json-schema.org/draft/2020-12/schema", "$id":"https://contracts.example/v1.0.0/action.json", "x-action-type":"ticket.create", "type":"object", "required":["title"], "additionalProperties":False, "properties":{"title":{"type":"string"}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.json"
            path.write_text(json.dumps(schema))
            action.update(action_type="ticket.create", payload={"title":"Example"})
            action["payload_schema"] = {"id":schema["$id"], "version":"1.0.0", "digest":"sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertEqual(payload_errors(action, {schema["$id"]:path}), [])
            action["payload"]["extra"] = True
            self.assertIn("effective payload fails its action schema", payload_errors(action, {schema["$id"]:path}))
            action["action_type"] = "email.send"
            self.assertIn("payload schema action type mismatch", payload_errors(action, {schema["$id"]:path}))

    def test_unconsumed_request_cannot_dispatch(self) -> None:
        request = self.envelope["request"]
        request.update(status="approved", terminal_reason="approved", revision=2)
        request.pop("consumed_at")
        request.pop("dispatch_id")
        self.assert_refused(self.envelope, "provider invocation requires a consumed request")

    def test_consumption_causality_and_revisions(self) -> None:
        for field, value, reason in (("consumed_at", "2026-04-28T09:14:30Z", "consumed before its decision"),
                                     ("revision", 2, "consumption revisions"),
                                     ("terminal_at", "2026-04-28T09:14:30Z", "terminal state predates its decision")):
            envelope = deepcopy(self.envelope)
            envelope["request"][field] = value
            with self.subTest(field=field):
                self.assert_refused(envelope, reason)

    def test_expiry_is_exclusive_for_decision_consumption_and_execution(self) -> None:
        for target, field in (("approval", "decided_at"), ("request", "consumed_at"), ("dispatch", "started_at")):
            envelope = deepcopy(self.envelope)
            record = {"approval":envelope["approvals"][0], "request":envelope["request"], "dispatch":envelope["dispatches"][0]}[target]
            record[field] = envelope["request"]["expires_at"]
            with self.subTest(target=target):
                self.assert_refused(envelope, "expiry")

    def test_policy_evaluation_binding(self) -> None:
        self.envelope["approvals"][0]["policy_evaluation_id"] = "eval_different_01"
        self.assert_refused(self.envelope, "policy evaluation mismatch")

    def test_policy_binding_is_required(self) -> None:
        self.envelope["approvals"][0].pop("policy_evaluation_id")
        self.assertIn("envelope fails structural validation", validate_envelope(self.envelope))

    def test_authority_must_have_a_finite_exclusive_window(self) -> None:
        envelope = deepcopy(self.envelope)
        envelope["authority_snapshots"][0].pop("valid_until")
        self.assertIn("envelope fails structural validation", validate_envelope(envelope))
        envelope = deepcopy(self.envelope)
        envelope["authority_snapshots"][0]["valid_until"] = envelope["dispatches"][0]["started_at"]
        self.assert_refused(envelope, "used expired authority evidence")

    def test_authoritative_failure_can_retry_with_fresh_authority(self) -> None:
        envelope = load("examples/recovered-envelope.json")
        envelope["dispatches"].pop(1)
        first, retry = envelope["dispatches"]
        first.update(status="failed", retry_allowed=True, reason="provider_rejected")
        first.pop("reconciliation")
        retry["previous_dispatch_id"] = first["dispatch_id"]
        envelope["audit_events"] = [event for event in envelope["audit_events"] if event["event_type"] != "dispatch.reconciled"]
        next(event for event in envelope["audit_events"] if event["event_type"] == "dispatch.outcome_unknown")["event_type"] = "dispatch.failed"
        refresh_audit(envelope)
        self.assertEqual(validate_envelope(envelope), [])

    def test_read_only_reconciliation_can_finish_after_approval_expiry(self) -> None:
        envelope = load("examples/recovered-envelope.json")
        envelope["dispatches"].pop()
        envelope["authority_snapshots"].pop()
        record = envelope["dispatches"][1]
        expiry = envelope["request"]["expires_at"]
        record.update(status="reconciled_succeeded", retry_allowed=False, started_at=expiry, completed_at=expiry, recorded_at=expiry)
        record.pop("authority_snapshot_id")
        record["reconciliation"].update(status="succeeded", checked_at=expiry)
        envelope["audit_events"] = [event for event in envelope["audit_events"] if event["event_id"] not in {"event_retry_authority_02", "event_retry_02"}]
        event = next(e for e in envelope["audit_events"] if e["event_type"] == "dispatch.reconciled")
        event.update(occurred_at=expiry, recorded_at=expiry)
        envelope["audit_events"][-1].update(occurred_at=expiry, recorded_at=expiry)
        envelope["audit_snapshot"]["captured_at"] = envelope["captured_at"] = expiry
        refresh_audit(envelope)
        self.assertEqual(validate_envelope(envelope), [])

    def test_cancelled_and_failed_requests_need_no_approval(self) -> None:
        for status, terminal_reason in (("cancelled", "cancelled_by_requester"), ("failed", "delivery_failed")):
            envelope = load("examples/expired-envelope.json")
            envelope["request"].update(status=status, terminal_reason=terminal_reason)
            event = next(e for e in envelope["audit_events"] if e["event_type"] == "approval.expired")
            if status == "cancelled":
                event["event_type"] = "approval.cancelled"
            else:
                event["event_type"] = "dispatch.not_dispatched"
                event["references"]["dispatch_id"] = "dispatch_failure_01"
                dispatch = deepcopy(self.envelope["dispatches"][0])
                dispatch.update(dispatch_id="dispatch_failure_01", status="not_dispatched", approval_ids=[], reason="request_failed", started_at=event["occurred_at"], completed_at=event["occurred_at"], recorded_at=event["recorded_at"])
                dispatch.pop("authority_snapshot_id")
                dispatch.pop("provider")
                envelope["dispatches"] = [dispatch]
            refresh_audit(envelope)
            self.assertEqual(validate_envelope(envelope), [])

    def test_resolution_identity_cannot_fork(self) -> None:
        resolution = deepcopy(self.envelope["resolutions"][0])
        resolution["resolution_id"] = "resolution_fork_01"
        self.envelope["resolutions"].append(resolution)
        self.assert_refused(self.envelope, "more than one terminal resolution")

    def test_refusal_never_invokes_provider(self) -> None:
        envelope = load("examples/rejected-envelope.json")
        dispatch = envelope["dispatches"][0]
        dispatch.update(status="succeeded", provider=deepcopy(self.envelope["dispatches"][0]["provider"]), authority_snapshot_id=self.envelope["authority_snapshots"][0]["authority_snapshot_id"], approval_ids=self.envelope["dispatches"][0]["approval_ids"])
        envelope["authority_snapshots"] = deepcopy(self.envelope["authority_snapshots"])
        self.assert_refused(envelope, "refused request cannot invoke a provider")

    def test_refusal_cannot_allow_retry_or_claim_provider(self) -> None:
        for updates in ({"retry_allowed":True}, {"provider":{}}):
            envelope = load("examples/rejected-envelope.json")
            envelope["dispatches"][0].update(updates)
            self.assertIn("envelope fails structural validation", validate_envelope(envelope))

    def test_expired_request_cannot_terminate_early(self) -> None:
        envelope = load("examples/expired-envelope.json")
        envelope["request"]["terminal_at"] = envelope["request"]["requested_at"]
        self.assert_refused(envelope, "terminated before its expiry")

    def test_retry_lineage_cannot_skip_or_change_identity(self) -> None:
        for field, value, reason in (("previous_dispatch_id", "dispatch_missing_01", "linkage is broken"),
                                     ("attempt", 3, "attempt numbers must be contiguous"),
                                     ("max_attempts", 4, "changes max_attempts"),
                                     ("idempotency_key", "idem_different_01", "changes idempotency_key")):
            envelope = load("examples/recovered-envelope.json")
            envelope["dispatches"][-1][field] = value
            with self.subTest(field=field):
                self.assert_refused(envelope, reason)

    def test_unknown_outcome_cannot_retry_without_reconciliation(self) -> None:
        envelope = load("examples/recovered-envelope.json")
        envelope["dispatches"].pop(1)
        envelope["dispatches"][-1]["previous_dispatch_id"] = envelope["dispatches"][0]["dispatch_id"]
        self.assert_refused(envelope, "retry requires authoritative failure")

    def test_reconciliation_requires_unknown_history(self) -> None:
        envelope = load("examples/recovered-envelope.json")
        envelope["dispatches"][0] = deepcopy(self.envelope["dispatches"][0])
        self.assert_refused(envelope, "reconciliation must resolve the preceding unknown")

    def test_reconciliation_preserves_lookup_identity(self) -> None:
        envelope = load("examples/recovered-envelope.json")
        envelope["dispatches"][1]["reconciliation"]["lookup_key_hash"] = "sha256:" + "1" * 64
        self.assert_refused(envelope, "lookup identity")

    def test_success_cannot_be_retried_and_limit_cannot_extend(self) -> None:
        envelope = load("examples/recovered-envelope.json")
        envelope["dispatches"][1]["status"] = "reconciled_succeeded"
        envelope["dispatches"][1]["retry_allowed"] = False
        envelope["dispatches"][1]["reconciliation"]["status"] = "succeeded"
        self.assert_refused(envelope, "retry requires authoritative failure")
        envelope = load("examples/recovered-envelope.json")
        envelope["dispatches"][1]["max_attempts"] = 1
        self.assert_refused(envelope, "attempt ceiling cannot allow retry")

    def test_dispatch_ids_are_unique(self) -> None:
        self.envelope["dispatches"].append(deepcopy(self.envelope["dispatches"][0]))
        self.assert_refused(self.envelope, "reuse dispatch_id")

    def test_audit_unknown_reference_is_rejected_after_rehash(self) -> None:
        self.envelope["audit_events"][0]["references"]["dispatch_id"] = "dispatch_unknown_01"
        self.assert_refused(self.envelope, "references unknown dispatch_id")

    def test_every_exported_record_belongs_to_its_proposal(self) -> None:
        for key in ("validations", "review_snapshots", "approvals", "resolutions", "authority_snapshots", "dispatches"):
            envelope = deepcopy(self.envelope)
            envelope[key][0]["proposal_id"] = "prop_foreign_01"
            with self.subTest(key=key):
                self.assert_refused(envelope, "lifecycle record points at another proposal")

    def test_audit_reference_on_wrong_type_is_not_a_witness(self) -> None:
        event = next(e for e in self.envelope["audit_events"] if e["event_type"] == "approval.decided")
        event["references"].pop("approval_id")
        self.assert_refused(self.envelope, "lacks its approval_id witness")

    def test_audit_result_actor_and_decision_must_match(self) -> None:
        for kind in ("outcome", "actor", "decision"):
            envelope = deepcopy(self.envelope)
            if kind == "outcome":
                next(e for e in envelope["audit_events"] if e["event_type"] == "dispatch.succeeded")["event_type"] = "dispatch.failed"
                reason = "outcome disagrees"
            else:
                event = next(e for e in envelope["audit_events"] if e["event_type"] == "approval.decided")
                if kind == "actor":
                    event["actor"]["identifier"] = "other@example.com"
                    reason = "actor disagrees"
                else:
                    event["detail"]["decision"] = "rejected"
                    reason = "decision disagrees"
            with self.subTest(kind=kind):
                self.assert_refused(envelope, reason)

    def test_envelope_cannot_capture_future_records(self) -> None:
        self.envelope["captured_at"] = self.envelope["request"]["requested_at"]
        self.assert_refused(self.envelope, "capture predates a contained record")

    def test_invalid_patch_is_a_refusal_and_does_not_mutate_original(self) -> None:
        original = deepcopy(self.envelope["proposal"])
        self.envelope["approvals"][0]["modifications"] = [{"op":"replace", "path":"/payload/to/-1", "value":"other@example.com"}]
        self.assert_refused(self.envelope, "invalid JSON Patch")
        self.assertEqual(self.envelope["proposal"], original)

    def test_malformed_envelope_fails_closed(self) -> None:
        for value in (None, [], {}, {"proposal":{}}, {"schema_version":"3.1.0"}):
            self.assertEqual(validate_envelope(value), ["envelope fails structural validation"])


class JsonBoundaryTests(unittest.TestCase):
    def test_strict_json_rejects_ambiguity_at_every_depth(self) -> None:
        for source in ('{"a":1,"a":2}', '{"nested":{"a":1,"a":2}}', '{"a":1,"\\u0061":2}', '[NaN]', '[Infinity]', '[-Infinity]', '[1e9999]'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                strict_json_loads(source)
        self.assertEqual(strict_json_loads('{"a":1,"b":[true,null,1.5]}'), {"a":1,"b":[True,None,1.5]})

    def test_patch_rejects_invalid_indices_members_and_escapes(self) -> None:
        document = {"payload":{"values":[1,2], "flag":True}}
        for operation in (
            {"op":"replace", "path":"/payload/values/-1", "value":3},
            {"op":"add", "path":"/payload/values/4", "value":3},
            {"op":"replace", "path":"/payload/values/01", "value":3},
            {"op":"remove", "path":"/payload/values/2"},
            {"op":"replace", "path":"/payload/missing", "value":3},
            {"op":"replace", "path":"/payload/~2", "value":3},
            {"op":"test", "path":"/payload/flag", "value":1},
            {"op":"test", "path":"/payload", "value":{"values":[1,2],"flag":1}},
            {"op":"add", "path":"/payload/missing/child", "value":3},
            {"op":"remove", "path":"/payload/flag/child"},
        ):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                apply_operations(document, [operation])
        self.assertEqual(document, {"payload":{"values":[1,2], "flag":True}})

    def test_valid_json_patch_profile(self) -> None:
        original = {"payload":{"values":[1,2],"a/b":{"~key":1}}}
        result = apply_operations(original, [
            {"op":"add", "path":"/payload/values/2", "value":3},
            {"op":"add", "path":"/payload/values/-", "value":4},
            {"op":"replace", "path":"/payload/a~1b/~0key", "value":2},
            {"op":"test", "path":"/payload/values/0", "value":1.0},
        ])
        self.assertEqual(result["payload"]["values"], [1,2,3,4])
        self.assertEqual(result["payload"]["a/b"]["~key"], 2)
        self.assertEqual(original["payload"]["values"], [1,2])


if __name__ == "__main__":
    unittest.main()
