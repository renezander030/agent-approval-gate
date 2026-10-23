from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_examples import refresh_audit  # noqa: E402
from validate_contracts import load, validate_envelope  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
