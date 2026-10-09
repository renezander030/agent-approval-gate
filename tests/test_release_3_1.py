from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_examples import refresh_audit  # noqa: E402
from validate_contracts import (  # noqa: E402
    load, policy_outcome_errors, schema_catalog, validate_envelope, validator_for,
)


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


if __name__ == "__main__":
    unittest.main()
