from __future__ import annotations

import contextlib
import hashlib
import io
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
    ROOT as REPO, audit_export_errors, collection_errors, digest, load, main, payload_errors,
    policy_outcome_errors, schema_catalog, validate_envelope, validator_for,
)

ACTION_TYPES = ("crm.update_record", "ticket.create", "db.update_row", "api.call", "n8n.trigger_workflow")


def rebind(envelope: dict, action_type: str, payload: dict) -> dict:
    """Move the reference lifecycle onto another action type and recompute every binding."""
    envelope = deepcopy(envelope)
    proposal = envelope["proposal"]
    schema_path = REPO / "schemas" / "actions" / f"{action_type}.schema.json"
    schema = load(schema_path)
    proposal.update(action_type=action_type, payload=deepcopy(payload))
    proposal["payload_schema"] = {
        "id": schema["$id"],
        "version": envelope["schema_version"],
        "digest": "sha256:" + hashlib.sha256(schema_path.read_bytes()).hexdigest(),
    }
    action_hash, payload_hash = digest(proposal), digest(payload)
    envelope["validations"][0]["action_hash"] = action_hash
    envelope["request"]["action_hash"] = action_hash
    envelope["request"]["policy"]["material_input_hash"] = action_hash
    review = envelope["review_snapshots"][0]
    review["content"].update(
        action_type=action_type, arguments=deepcopy(payload),
        target={key: payload[key] for key in schema["x-review-target"] if key in payload},
    )
    review.update(action_hash=action_hash, payload_hash=payload_hash, content_hash=digest(review["content"]))
    approval = envelope["approvals"][0]
    approval.update(action_hash=action_hash, payload_hash=payload_hash, review_content_hash=review["content_hash"])
    envelope["resolutions"][0].update(action_hash=action_hash, approval_record_hash=digest(approval))
    authority = envelope["authority_snapshots"][0]
    authority["action_hash"] = action_hash
    for subject in authority["subjects"]:
        subject["scopes"] = [action_type if scope == "email.send" else scope for scope in subject.get("scopes", [])]
    authority["authority_digest"] = digest(authority["subjects"])
    envelope["dispatches"][0]["action_hash"] = action_hash
    for event in envelope["audit_events"]:
        if "action_hash" in event["detail"]:
            event["detail"]["action_hash"] = action_hash
        if "payload_hash" in event["detail"]:
            event["detail"]["payload_hash"] = payload_hash
        if "review_content_hash" in event["detail"]:
            event["detail"]["review_content_hash"] = review["content_hash"]
    refresh_audit(envelope)
    return envelope


def schema_errors(schema: str, instance: object) -> list[str]:
    schemas, registry = schema_catalog()
    return [error.message for error in validator_for(schema, schemas, registry).iter_errors(instance)]


class PolicyOutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/approval-envelope.json")

    def test_outcome_is_a_closed_set(self) -> None:
        policy = load("examples/approval-policy.json")
        for value in ("allow", "true", "", "no_opinion"):
            with self.subTest(value=value):
                policy["outcome"] = value
                self.assertTrue(schema_errors("schemas/approval-policy.schema.json", policy))

    def test_auto_approve_outcome_requires_auto_approval_policy(self) -> None:
        policy = load("examples/approval-policy.json")
        policy["outcome"] = "auto_approve"
        self.assertTrue(schema_errors("schemas/approval-policy.schema.json", policy))
        policy["requirements"]["allow_auto_approval"] = True
        self.assertEqual(schema_errors("schemas/approval-policy.schema.json", policy), [])

    def test_auto_approval_needs_explicit_outcome(self) -> None:
        request = deepcopy(self.envelope["request"])
        approval = {"decision": "auto_approved"}
        for outcome in (None, "require_approval", "deny"):
            with self.subTest(outcome=outcome):
                request["policy"].pop("outcome", None)
                if outcome:
                    request["policy"]["outcome"] = outcome
                errors = policy_outcome_errors(request, [approval], [])
                self.assertIn("auto approval requires an explicit auto_approve policy outcome", errors)
        request["policy"]["outcome"] = "auto_approve"
        self.assertEqual(policy_outcome_errors(request, [approval], []), [])

    def test_denied_outcome_cannot_reach_dispatch(self) -> None:
        envelope = self.envelope
        envelope["request"]["policy"]["outcome"] = "deny"
        refresh_audit(envelope)
        errors = validate_envelope(envelope)
        for reason in (
            "denied policy outcome must end the request as policy_failed",
            "denied policy outcome cannot carry an approving decision",
            "denied policy outcome cannot invoke a provider",
        ):
            self.assertIn(reason, errors)


class ActionCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/approval-envelope.json")

    def test_every_built_in_action_type_has_a_reference_schema(self) -> None:
        enum = load("schemas/proposed-action.schema.json")["properties"]["action_type"]["enum"]
        for action_type in enum:
            with self.subTest(action_type=action_type):
                schema = load(f"schemas/actions/{action_type}.schema.json")
                self.assertEqual(schema["x-action-type"], action_type)
                self.assertFalse(schema["additionalProperties"])
                self.assertTrue(set(schema["x-review-target"]) <= set(schema["properties"]))

    def test_complete_lifecycle_for_each_action_type(self) -> None:
        for action_type in ACTION_TYPES:
            with self.subTest(action_type=action_type):
                payload = load(f"examples/actions/{action_type}.json")
                self.assertEqual(validate_envelope(rebind(self.envelope, action_type, payload)), [])

    def test_unknown_payload_members_are_refused(self) -> None:
        for action_type in ACTION_TYPES:
            with self.subTest(action_type=action_type):
                payload = load(f"examples/actions/{action_type}.json")
                payload["callback_url"] = "https://attacker.example/hook"
                envelope = rebind(self.envelope, action_type, load(f"examples/actions/{action_type}.json"))
                envelope["proposal"]["payload"] = payload
                self.assertIn("effective payload fails its action schema", payload_errors(envelope["proposal"]))

    def test_review_target_must_match_the_arguments(self) -> None:
        for action_type in ACTION_TYPES + ("email.send",):
            with self.subTest(action_type=action_type):
                if action_type == "email.send":
                    envelope = deepcopy(self.envelope)
                else:
                    envelope = rebind(self.envelope, action_type, load(f"examples/actions/{action_type}.json"))
                review = envelope["review_snapshots"][0]
                field = next(iter(review["content"]["target"]))
                review["content"]["target"][field] = "something-else"
                review["content_hash"] = digest(review["content"])
                errors = validate_envelope(envelope)
                self.assertIn(f"review snapshot {review['snapshot_id']} changes the {action_type} target", errors)


class RevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/revoked-envelope.json")

    def refused(self, envelope: dict, reason: str) -> None:
        refresh_audit(envelope)
        errors = validate_envelope(envelope)
        self.assertTrue(any(reason in error for error in errors), errors)

    def test_revoked_lifecycle_is_complete(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])

    def test_consumed_request_cannot_be_revoked(self) -> None:
        request = self.envelope["request"]
        request["consumed_at"] = request["terminal_at"]
        request["dispatch_id"] = self.envelope["dispatches"][0]["dispatch_id"]
        self.assertTrue(schema_errors("schemas/approval-request.schema.json", request))

    def test_revocation_only_on_revoked_requests(self) -> None:
        request = load("examples/approval-envelope.json")["request"]
        request["revocation"] = deepcopy(self.envelope["request"]["revocation"])
        self.assertTrue(schema_errors("schemas/approval-request.schema.json", request))

    def test_revocation_needs_an_approving_decision(self) -> None:
        approval = self.envelope["approvals"][0]
        approval.update(decision="rejected", rejection_settlement={"state": "unresolved"})
        self.envelope["resolutions"][0].update(decision="rejected", disposition="do_not_execute", retry_policy="never", approval_record_hash=digest(approval))
        for event in self.envelope["audit_events"]:
            if event["event_type"] in {"approval.decided", "resolution.emitted"}:
                event["detail"]["decision"] = "rejected"
        self.refused(self.envelope, "revoked request lacks an approving decision")

    def test_revocation_after_expiry_is_refused(self) -> None:
        request = self.envelope["request"]
        request["revocation"]["revoked_at"] = request["terminal_at"] = request["expires_at"]
        self.refused(self.envelope, "revocation occurred at or after request expiry")

    def test_revoked_request_cannot_invoke_provider(self) -> None:
        base = load("examples/approval-envelope.json")
        self.envelope["dispatches"] = base["dispatches"]
        self.refused(self.envelope, "provider invocation requires a consumed request")

    def test_revocation_needs_its_audit_witness(self) -> None:
        self.envelope["audit_events"] = [e for e in self.envelope["audit_events"] if e["event_type"] != "approval.revoked"]
        self.refused(self.envelope, "audit stream lacks required lifecycle events: approval.revoked")

    def test_revocation_witness_must_agree(self) -> None:
        event = next(e for e in self.envelope["audit_events"] if e["event_type"] == "approval.revoked")
        event["actor"]["identifier"] = "someone-else@example.com"
        self.refused(self.envelope, "audit revocation actor disagrees with request")


class AgentFeedbackTests(unittest.TestCase):
    SCHEMA = "schemas/resolution-record.schema.json"

    def setUp(self) -> None:
        self.envelope = load("examples/rejected-envelope.json")
        self.resolution = self.envelope["resolutions"][0]

    def test_rejection_carries_structured_feedback(self) -> None:
        self.assertEqual(validate_envelope(self.envelope), [])
        self.assertEqual(self.resolution["agent_feedback"]["reason_code"], "incorrect_content")

    def test_feedback_never_accompanies_an_approval(self) -> None:
        approved = load("examples/resolution-record.json")
        approved["agent_feedback"] = {"reason_code": "other", "message": "Looks fine"}
        self.assertTrue(schema_errors(self.SCHEMA, approved))

    def test_requested_changes_require_a_new_proposal(self) -> None:
        self.resolution.update(disposition="do_not_execute", retry_policy="never")
        self.assertTrue(schema_errors(self.SCHEMA, self.resolution))

    def test_questions_require_a_new_proposal(self) -> None:
        feedback = self.resolution["agent_feedback"]
        feedback.pop("requested_changes")
        feedback.update(reason_code="needs_information", questions=["Which invoice period does the customer mean?"])
        self.assertEqual(schema_errors(self.SCHEMA, self.resolution), [])
        self.resolution["retry_policy"] = "never"
        self.assertTrue(schema_errors(self.SCHEMA, self.resolution))

    def test_requested_changes_stay_inside_the_payload(self) -> None:
        for path in ("/tenant", "/payload_schema/id", "payload/subject", "/payload/~2"):
            with self.subTest(path=path):
                self.resolution["agent_feedback"]["requested_changes"][0]["path"] = path
                self.assertTrue(schema_errors(self.SCHEMA, self.resolution))

    def test_feedback_text_rejects_display_controls(self) -> None:
        self.resolution["agent_feedback"]["message"] = "Approve \u202eetaler"
        self.assertTrue(schema_errors(self.SCHEMA, self.resolution))

    def test_audit_reason_must_match_feedback(self) -> None:
        event = next(e for e in self.envelope["audit_events"] if e["event_type"] == "resolution.emitted")
        event["detail"]["reason_code"] = "policy_violation"
        refresh_audit(self.envelope)
        self.assertIn("audit resolution reason disagrees with agent feedback", validate_envelope(self.envelope))


def elicitation_envelope() -> dict:
    envelope = load("examples/approval-envelope.json")
    envelope["request"]["policy"]["requirements"]["allowed_channels"].append("mcp_elicitation")
    envelope["request"]["channels"].append({
        "channel": "mcp_elicitation", "target_hash": digest("mcp-session-01"),
        "delivery_status": "delivered", "notification_id": "elicitation-01", "sent_at": "2026-04-28T09:14:26Z",
    })
    approval = envelope["approvals"][0]
    approval["channel"] = "mcp_elicitation"
    approval["decided_by"]["authentication"]["method"] = "authenticated_session"
    envelope["resolutions"][0]["approval_record_hash"] = digest(approval)
    for event in envelope["audit_events"]:
        if event["event_type"] == "approval.decided":
            event["detail"]["channel"] = "mcp_elicitation"
    refresh_audit(envelope)
    return envelope


class ElicitationChannelTests(unittest.TestCase):
    def test_human_approval_through_elicitation(self) -> None:
        self.assertEqual(validate_envelope(elicitation_envelope()), [])

    def test_client_auto_decline_is_not_a_human_rejection(self) -> None:
        approval = elicitation_envelope()["approvals"][0]
        approval.update(decision="rejected", rejection_settlement={"state": "unresolved"})
        for kind, method, present in (("system", "service_identity", False), ("human", "unknown", True), ("human", "authenticated_session", False)):
            with self.subTest(kind=kind, method=method):
                approval["decided_by"]["kind"] = kind
                approval["decided_by"]["authentication"].update(method=method, human_present=present)
                self.assertTrue(schema_errors("schemas/approval-record.schema.json", approval))

    def test_answer_requires_a_delivered_elicitation(self) -> None:
        envelope = elicitation_envelope()
        envelope["request"]["channels"][-1]["delivery_status"] = "failed"
        errors = validate_envelope(envelope)
        self.assertIn(f"approval {envelope['approvals'][0]['approval_id']} answers an elicitation that was never delivered", errors)

    def test_high_risk_elicitation_approval_requires_a_signature(self) -> None:
        envelope = elicitation_envelope()
        envelope["proposal"]["risk"] = "high"
        envelope["approvals"][0].pop("signatures")
        self.assertTrue(schema_errors("schemas/approval-envelope.schema.json", envelope))


def renamed(envelope: dict, suffix: str) -> dict:
    envelope = deepcopy(envelope)
    envelope["proposal"]["proposal_id"] += suffix
    envelope["proposal"]["call_id"] += suffix
    envelope["proposal"]["idempotency_key"] += suffix
    envelope["request"]["request_id"] += suffix
    envelope["audit_snapshot"]["stream_id"] += suffix
    for dispatch in envelope["dispatches"]:
        dispatch["dispatch_id"] += suffix
    return envelope


class CollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/approval-envelope.json")

    def test_independent_lifecycles_pass(self) -> None:
        self.assertEqual(collection_errors([self.envelope, renamed(self.envelope, "_b")]), [])

    def test_one_call_cannot_raise_two_requests(self) -> None:
        second = renamed(self.envelope, "_b")
        second["proposal"]["call_id"] = self.envelope["proposal"]["call_id"]
        self.assertEqual(
            collection_errors([self.envelope, second]),
            ["envelopes 0 and 1: admit more than one approval request for one call"],
        )

    def test_idempotency_key_binds_one_action(self) -> None:
        second = renamed(self.envelope, "_b")
        second["proposal"]["idempotency_key"] = self.envelope["proposal"]["idempotency_key"]
        second["proposal"]["payload"]["subject"] = "Different action"
        self.assertIn("envelopes 0 and 1: idempotency_key binds two different actions", collection_errors([self.envelope, second]))

    def test_same_tenant_scope_only(self) -> None:
        second = renamed(self.envelope, "_b")
        second["proposal"]["call_id"] = self.envelope["proposal"]["call_id"]
        second["proposal"]["tenant"] = "other-tenant"
        self.assertEqual(collection_errors([self.envelope, second]), [])


class AuditExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = load("examples/audit-events.json")
        self.snapshot = load("examples/audit-snapshot.json")

    def test_complete_export_verifies(self) -> None:
        self.assertEqual(audit_export_errors(self.events, self.snapshot), [])

    def test_partial_export_continues_from_checkpoint(self) -> None:
        tail = self.events[4:]
        self.snapshot.update(entry_count=len(tail), first_sequence=tail[0]["sequence"], events_digest=digest(tail))
        anchor = self.events[3]["event_hash"]
        self.assertEqual(audit_export_errors(tail, self.snapshot, anchor), [])
        self.assertIn("audit export does not continue from the retained checkpoint", audit_export_errors(tail, self.snapshot, self.events[2]["event_hash"]))

    def test_dropped_final_event_is_detected(self) -> None:
        errors = audit_export_errors(self.events[:-1], self.snapshot)
        self.assertIn("audit snapshot entry_count is incomplete", errors)
        self.assertIn("audit snapshot root_event_hash mismatch", errors)

    def test_rewritten_event_is_detected(self) -> None:
        self.events[2]["detail"]["policy_revision"] = "rewritten"
        self.assertIn(f"audit event {self.events[2]['event_id']} hash mismatch", audit_export_errors(self.events, self.snapshot))

    def test_removed_middle_event_is_detected(self) -> None:
        del self.events[3]
        errors = audit_export_errors(self.events, self.snapshot)
        self.assertIn("audit sequence is not contiguous", errors)


class CommandTests(unittest.TestCase):
    def run_main(self, *argv: str) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(list(argv))
        return code, buffer.getvalue()

    def test_valid_records_exit_zero(self) -> None:
        code, output = self.run_main(
            "--envelope", str(REPO / "examples/approval-envelope.json"),
            "--record", "approval-record", str(REPO / "examples/webauthn-approval-record.json"),
            "--audit-events", str(REPO / "examples/audit-events.json"),
            "--audit-snapshot", str(REPO / "examples/audit-snapshot.json"),
        )
        self.assertEqual(code, 0, output)
        self.assertIn("All 3 inputs passed.", output)

    def test_invalid_record_exits_one_with_json(self) -> None:
        record = load("examples/resolution-record.json")
        record["decision"] = "maybe"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resolution.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            code, output = self.run_main("--json", "--record", "resolution-record", str(path))
        self.assertEqual(code, 1)
        result = json.loads(output)
        self.assertFalse(result["ok"])
        self.assertTrue(result["results"][0]["errors"])

    def test_ambiguous_json_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            path.write_text('{"proposal": {}, "proposal": {}}', encoding="utf-8")
            code, output = self.run_main("--envelope", str(path))
        self.assertEqual(code, 2)
        self.assertIn("duplicate JSON property", output)

    def test_jsonl_audit_export(self) -> None:
        events = load("examples/audit-events.json")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
            code, output = self.run_main("--audit-events", str(path), "--audit-snapshot", str(REPO / "examples/audit-snapshot.json"))
        self.assertEqual(code, 0, output)

    def test_custom_payload_schema_from_trusted_file(self) -> None:
        envelope = load("examples/approval-envelope.json")
        schema = load("schemas/actions/email.send.schema.json")
        schema["$id"] = "https://schemas.example.com/actions/v1.0.0/email.send.schema.json"
        with tempfile.TemporaryDirectory() as directory:
            schema_path = Path(directory) / "email.send.schema.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            envelope["proposal"]["payload_schema"] = {
                "id": schema["$id"], "version": "1.0.0",
                "digest": "sha256:" + hashlib.sha256(schema_path.read_bytes()).hexdigest(),
            }
            envelope_path = Path(directory) / "envelope.json"
            envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
            code, output = self.run_main("--envelope", str(envelope_path))
            self.assertEqual(code, 1)
            self.assertIn("payload schema is not available in the trusted local catalog", output)
            code, output = self.run_main("--envelope", str(envelope_path), "--schema-file", str(schema_path))
            self.assertNotIn("trusted local catalog", output)


if __name__ == "__main__":
    unittest.main()
