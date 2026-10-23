from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_examples import refresh_audit  # noqa: E402
from validate_contracts import load, record_errors, validate_envelope  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
