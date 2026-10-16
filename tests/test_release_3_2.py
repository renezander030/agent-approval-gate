from __future__ import annotations

import contextlib
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
from test_release_3_1 import rebind  # noqa: E402
from validate_contracts import (  # noqa: E402
    digest, effect_errors, load, main, policy_outcome_errors, policy_rule_errors, schema_catalog, validate_envelope, validator_for,
)

LOCAL_ACTION_TYPES = ("shell.exec", "file.write")


def schema_errors(schema: str, instance: object) -> list[str]:
    schemas, registry = schema_catalog()
    return [error.message for error in validator_for(schema, schemas, registry).iter_errors(instance)]


def rebind_approval(envelope: dict) -> dict:
    """Recompute the resolution receipt and audit chain after editing the approval record."""
    envelope["resolutions"][0]["approval_record_hash"] = digest(envelope["approvals"][0])
    refresh_audit(envelope)
    return envelope


def prompt_channel_envelope(channel: str) -> dict:
    envelope = load("examples/approval-envelope.json")
    envelope["request"]["policy"]["requirements"]["allowed_channels"].append(channel)
    envelope["request"]["channels"].append({
        "channel": channel, "target_hash": digest(f"{channel}-target-01"),
        "delivery_status": "delivered", "notification_id": f"{channel}-prompt-01", "sent_at": "2026-04-28T09:14:26Z",
    })
    approval = envelope["approvals"][0]
    approval["channel"] = channel
    approval["decided_by"]["authentication"]["method"] = "authenticated_session"
    for event in envelope["audit_events"]:
        if event["event_type"] == "approval.decided":
            event["detail"]["channel"] = channel
    return rebind_approval(envelope)


class LocalActionCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/approval-envelope.json")

    def test_complete_lifecycle_for_each_local_action(self) -> None:
        for action_type in LOCAL_ACTION_TYPES:
            with self.subTest(action_type=action_type):
                payload = load(f"examples/actions/{action_type}.json")
                self.assertEqual(validate_envelope(rebind(self.envelope, action_type, payload)), [])

    def test_review_shows_where_the_action_runs(self) -> None:
        for action_type, field in (("shell.exec", "working_directory"), ("shell.exec", "environment"),
                                   ("file.write", "environment"), ("file.write", "path")):
            with self.subTest(action_type=action_type, field=field):
                envelope = rebind(self.envelope, action_type, load(f"examples/actions/{action_type}.json"))
                review = envelope["review_snapshots"][0]
                review["content"]["target"].pop(field)
                review["content_hash"] = digest(review["content"])
                self.assertIn(f"review snapshot {review['snapshot_id']} changes the {action_type} target", validate_envelope(envelope))

    def test_dispatcher_scope_names_the_local_action(self) -> None:
        envelope = rebind(self.envelope, "shell.exec", load("examples/actions/shell.exec.json"))
        authority = envelope["authority_snapshots"][0]
        for subject in authority["subjects"]:
            subject["scopes"] = ["file.write" if scope == "shell.exec" else scope for scope in subject.get("scopes", [])]
        authority["authority_digest"] = digest(authority["subjects"])
        refresh_audit(envelope)
        self.assertIn(f"authority snapshot {authority['authority_snapshot_id']} does not authorize the action type", validate_envelope(envelope))


class EffectHintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/approval-envelope.json")

    def test_reviewed_effects_match_the_proposal(self) -> None:
        review = self.envelope["review_snapshots"][0]
        review["content"]["effects"]["open_world"] = False
        review["content_hash"] = digest(review["content"])
        refresh_audit(self.envelope)
        self.assertIn(f"review snapshot {review['snapshot_id']} changes the effect hints", validate_envelope(self.envelope))

    def test_read_only_and_destructive_contradict(self) -> None:
        proposal = self.envelope["proposal"]
        proposal["effects"].update(read_only=True, destructive=True)
        self.assertTrue(schema_errors("schemas/proposed-action.schema.json", proposal))

    def test_undeclared_hints_are_conservative(self) -> None:
        request = deepcopy(self.envelope["request"])
        request["policy"]["outcome"] = "auto_approve"
        request["policy"]["requirements"]["human_required_effects"] = ["destructive"]
        proposal = {"effects": {"open_world": False}}
        self.assertIn("effects destructive cannot be auto approved", effect_errors(proposal, [], request, []))
        proposal["effects"]["destructive"] = False
        self.assertEqual(effect_errors(proposal, [], request, []), [])

    def test_fired_effects_need_a_human(self) -> None:
        request = deepcopy(self.envelope["request"])
        approval = {"decision": "auto_approved", "decided_by": {"kind": "policy"}}
        for required, fires in ((["open_world"], True), (["not_idempotent"], False), (["not_read_only"], True), (["destructive"], False)):
            with self.subTest(required=required):
                request["policy"]["requirements"]["human_required_effects"] = required
                errors = effect_errors(self.envelope["proposal"], [], request, [approval])
                self.assertEqual(any("require a human approval" in error for error in errors), fires)


class RulePrecedenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load("examples/approval-policy-rules.json")

    def test_deny_beats_ask_beats_auto_approve(self) -> None:
        for effects, expected in (
            (["auto_approve"], "auto_approve"),
            (["auto_approve", "require_approval"], "require_approval"),
            (["require_approval", "deny", "auto_approve"], "deny"),
            ([], "deny"),
        ):
            with self.subTest(effects=effects):
                self.policy["matched_rules"] = [{"rule_id": f"rule.{index}", "effect": effect} for index, effect in enumerate(effects)]
                for outcome in ("require_approval", "auto_approve", "deny"):
                    self.policy["outcome"] = outcome
                    self.assertEqual(policy_rule_errors(self.policy) == [], outcome == expected)

    def test_rule_ids_are_unique(self) -> None:
        self.policy["matched_rules"].append(deepcopy(self.policy["matched_rules"][0]))
        self.assertIn("policy matched_rules repeat a rule_id", policy_rule_errors(self.policy))

    def test_lifecycle_outcome_follows_its_rules(self) -> None:
        envelope = load("examples/approval-envelope.json")
        envelope["request"]["policy"]["matched_rules"] = [{"rule_id": "rule.email.blocked-domain", "effect": "deny"}]
        refresh_audit(envelope)
        self.assertIn("policy outcome does not follow its matched rules (expected deny)", validate_envelope(envelope))

    def test_standalone_policy_record_is_checked(self) -> None:
        self.policy["outcome"] = "auto_approve"
        self.policy["requirements"]["allow_auto_approval"] = True
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps(self.policy), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--record", "approval-policy", str(path)]), 1)


def unavailable_envelope() -> dict:
    envelope = load("examples/approval-envelope.json")
    policy = envelope["request"]["policy"]
    policy.update(evaluation_status="evaluator_unavailable", outcome_reason="Evaluator timed out after 5 s")
    policy["requirements"]["on_evaluator_unavailable"] = "require_human_approval"
    refresh_audit(envelope)
    return envelope


class EvaluatorUnavailableTests(unittest.TestCase):
    def test_unavailable_evaluator_can_escalate_to_a_human(self) -> None:
        self.assertEqual(validate_envelope(unavailable_envelope()), [])

    def test_escalation_needs_the_policy_opt_in(self) -> None:
        for fallback in (None, "deny"):
            with self.subTest(fallback=fallback):
                envelope = unavailable_envelope()
                requirements = envelope["request"]["policy"]["requirements"]
                requirements.pop("on_evaluator_unavailable")
                if fallback:
                    requirements["on_evaluator_unavailable"] = fallback
                self.assertIn("unavailable evaluator must deny unless policy escalates to a human",
                              policy_outcome_errors(envelope["request"], envelope["approvals"], envelope["dispatches"]))

    def test_unavailable_evaluator_never_auto_approves(self) -> None:
        policy = unavailable_envelope()["request"]["policy"]
        policy["outcome"] = "auto_approve"
        policy["requirements"]["allow_auto_approval"] = True
        self.assertTrue(schema_errors("schemas/approval-policy.schema.json", policy))

    def test_unavailable_evaluator_has_no_matched_rules(self) -> None:
        policy = unavailable_envelope()["request"]["policy"]
        policy["matched_rules"] = [{"rule_id": "rule.cached", "effect": "require_approval"}]
        self.assertTrue(schema_errors("schemas/approval-policy.schema.json", policy))


class PromptChannelTests(unittest.TestCase):
    def test_human_approval_through_teams_and_cli(self) -> None:
        for channel in ("teams", "cli"):
            with self.subTest(channel=channel):
                self.assertEqual(validate_envelope(prompt_channel_envelope(channel)), [])

    def test_answer_requires_a_delivered_prompt(self) -> None:
        for channel, prompt in (("teams", "a Teams card"), ("cli", "a terminal prompt")):
            with self.subTest(channel=channel):
                envelope = prompt_channel_envelope(channel)
                envelope["request"]["channels"][-1]["delivery_status"] = "failed"
                approval_id = envelope["approvals"][0]["approval_id"]
                self.assertIn(f"approval {approval_id} answers {prompt} that was never delivered", validate_envelope(envelope))

    def test_prompt_decisions_name_a_present_human(self) -> None:
        for channel in ("teams", "cli"):
            approval = deepcopy(prompt_channel_envelope(channel)["approvals"][0])
            approval.update(decision="rejected", rejection_settlement={"state": "unresolved"})
            for kind, present in (("system", False), ("human", False)):
                with self.subTest(channel=channel, kind=kind, present=present):
                    approval["decided_by"]["kind"] = kind
                    approval["decided_by"]["authentication"]["human_present"] = present
                    self.assertTrue(schema_errors("schemas/approval-record.schema.json", approval))

    def test_policy_may_require_cli_signatures(self) -> None:
        envelope = prompt_channel_envelope("cli")
        envelope["request"]["policy"]["requirements"]["signature_required_channels"].append("cli")
        envelope["approvals"][0].pop("signatures")
        rebind_approval(envelope)
        approval_id = envelope["approvals"][0]["approval_id"]
        self.assertIn(f"approval {approval_id} lacks a required signature", validate_envelope(envelope))


if __name__ == "__main__":
    unittest.main()
