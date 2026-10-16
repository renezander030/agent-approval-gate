from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_examples import refresh_audit  # noqa: E402
from validate_contracts import digest, load, schema_catalog, validate_envelope, validator_for  # noqa: E402


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
