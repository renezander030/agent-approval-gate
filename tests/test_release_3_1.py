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


if __name__ == "__main__":
    unittest.main()
