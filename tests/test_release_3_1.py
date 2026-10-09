from __future__ import annotations

import hashlib
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_examples import refresh_audit  # noqa: E402
from validate_contracts import (  # noqa: E402
    ROOT as REPO, digest, load, payload_errors, policy_outcome_errors, schema_catalog,
    validate_envelope, validator_for,
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


if __name__ == "__main__":
    unittest.main()
