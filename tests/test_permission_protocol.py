from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "integrations" / "permission_protocol"))

import adapter  # noqa: E402
from generate_examples import permission_protocol_example_key, rebind_approval  # noqa: E402
from validate_contracts import (  # noqa: E402
    decode_base64url, digest, encode_base64url, load, permission_protocol_canonical_bytes,
    permission_protocol_receipt_errors, record_errors, validate_envelope,
)

VECTORS = ROOT / "tests" / "permission-protocol"


def published_keys(*names: str) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for name in names:
        for key in json.loads((VECTORS / name).read_text())["keys"]:
            keys[key["key_id"]] = base64.b64decode(key["public_key_b64"])
    return keys


def published_receipt_errors(name: str, keys: dict[str, bytes]) -> list[str]:
    artifact = json.loads((VECTORS / name).read_text())["artifact"]
    errors, _ = permission_protocol_receipt_errors(
        base64.b64decode(artifact["payload_bytes_b64"]),
        "sha256:" + artifact["signed_payload_hash"],
        artifact["key_id"],
        base64.b64decode(artifact["signature_b64"]),
        keys.get(artifact["key_id"], b""),
    )
    return errors


class PublishedReceiptTests(unittest.TestCase):
    """The verifier agrees with the issuer's own vectors and a live production receipt."""

    def test_live_production_receipt_verifies(self) -> None:
        self.assertEqual(published_receipt_errors("live-deploy-gate-approve.json", published_keys("live-keys.json")), [])

    def test_execute_lane_approval_and_denial_verify(self) -> None:
        keys = published_keys("keys.json")
        self.assertEqual(published_receipt_errors("approve-human-execute-lane-refund.json", keys), [])
        self.assertEqual(published_receipt_errors("deny-kill-switch-execute-lane.json", keys), [])

    def test_tampered_receipt_is_refused(self) -> None:
        self.assertEqual(
            published_receipt_errors("tampered-approve-human-deploy-gate.json", published_keys("keys.json")),
            ["Ed25519 signature does not verify over the payload digest"],
        )


class ReceiptApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = load("examples/permission-protocol-approval-record.json")
        self.signature = self.record["signatures"][0]
        self.profile = self.signature["permission_protocol"]

    def payload(self) -> dict:
        return json.loads(decode_base64url(self.profile["payload_bytes"]))

    def resign(self, payload: dict, payload_bytes: bytes | None = None) -> None:
        payload_bytes = payload_bytes or permission_protocol_canonical_bytes(payload)
        payload_digest = hashlib.sha256(payload_bytes).digest()
        self.profile["payload_bytes"] = encode_base64url(payload_bytes)
        self.profile["signed_payload_hash"] = "sha256:" + payload_digest.hex()
        self.signature["value"] = encode_base64url(permission_protocol_example_key().sign(payload_digest))

    def assertRefused(self, reason: str) -> None:
        errors = record_errors("approval-record", self.record)
        self.assertTrue(any(reason in error for error in errors), errors)

    def test_example_record_passes(self) -> None:
        self.assertEqual(record_errors("approval-record", self.record), [])

    def test_receipt_in_a_complete_lifecycle(self) -> None:
        envelope = load("examples/approval-envelope.json")
        envelope["approvals"][0] = self.record
        self.assertEqual(validate_envelope(rebind_approval(envelope)), [])

    def test_changed_payload_byte(self) -> None:
        payload_bytes = bytearray(decode_base64url(self.profile["payload_bytes"]))
        payload_bytes[-3] ^= 1
        self.profile["payload_bytes"] = encode_base64url(bytes(payload_bytes))
        self.assertRefused("payload bytes do not match signed_payload_hash")

    def test_other_issuer_key(self) -> None:
        other = encode_base64url(hashlib.sha256(b"another issuer key").digest())
        self.profile["issuer_public_key"] = other
        self.profile["key_evidence"]["digest"] = digest(
            {"issuer": self.profile["issuer"], "key_id": self.signature["key_id"], "public_key": other}
        )
        self.assertRefused("Ed25519 signature does not verify")

    def test_key_evidence_names_another_key(self) -> None:
        self.profile["key_evidence"]["digest"] = digest({"issuer": "https://elsewhere.example"})
        self.assertRefused("key evidence does not bind the issuer key")

    def test_receipt_for_another_action(self) -> None:
        self.record["action_hash"] = "sha256:" + "0" * 64
        self.assertRefused("idemKey does not bind this request and action_hash")

    def test_receipt_for_another_revision(self) -> None:
        self.record["request_revision"] += 1
        self.assertRefused("idemKey does not bind this request and action_hash")

    def test_signed_request_without_the_binding(self) -> None:
        payload = self.payload()
        request = json.loads(payload["requestJson"])
        request["constraints"]["idempotencyKey"] = "caller-chosen"
        payload["requestJson"] = json.dumps(request, separators=(",", ":"), sort_keys=True)
        self.resign(payload)
        self.assertRefused("signed request does not carry the binding")

    def test_denial_cannot_back_an_approval(self) -> None:
        payload = self.payload()
        payload["status"] = "DENIED"
        self.resign(payload)
        self.assertRefused("signed status does not match the approved decision")

    def test_policy_engine_decider(self) -> None:
        payload = self.payload()
        payload.update(deciderId="system/pp-permission-router", deciderAuthMethod="policy")
        self.resign(payload)
        self.assertRefused("does not name a human decider")

    def test_api_key_decider(self) -> None:
        payload = self.payload()
        payload.update(deciderId="api_key:key_1", deciderAuthMethod="api_key")
        self.resign(payload)
        self.assertRefused("decider did not authenticate with a session")

    def test_demo_receipt(self) -> None:
        payload = self.payload()
        payload["scope"] = "demo"
        self.resign(payload)
        self.assertRefused("is not a production receipt")

    def test_unsupported_canonicalization(self) -> None:
        payload = self.payload()
        payload["canonicalization"] = "jcs_v3"
        self.resign(payload)
        self.assertRefused("canonicalization 'jcs_v3' is not supported")

    def test_non_canonical_bytes(self) -> None:
        payload = self.payload()
        self.resign(payload, json.dumps(payload, indent=1).encode("utf-8"))
        self.assertRefused("not the jcs_v2 canonical form")

    def test_field_outside_jcs_v2(self) -> None:
        payload = self.payload()
        payload["approvalId"] = "apr_1"
        self.resign(payload)
        self.assertRefused("fields outside jcs_v2: approvalId")

    def test_receipt_is_not_the_authentication_evidence(self) -> None:
        self.record["decided_by"]["authentication"]["evidence_ref"] = "permission-protocol-receipt:other"
        self.assertRefused("is not the approval's authentication evidence")

    def test_receipt_on_another_channel(self) -> None:
        self.record["channel"] = "email"
        self.assertRefused("approval must use the web channel")

    def test_receipt_signed_after_the_record(self) -> None:
        self.record["recorded_at"] = "2026-04-28T09:14:29Z"
        self.assertRefused("was signed after the approval was recorded")

    def test_profile_fields_belong_to_its_algorithm(self) -> None:
        self.signature["algorithm"] = "ed25519"
        errors = record_errors("approval-record", self.record)
        self.assertTrue(errors and not any("Permission Protocol" in error for error in errors), errors)


class AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = load("examples/approval-envelope.json")
        self.key_set = load("examples/permission-protocol-key-set.json")
        self.artifact = load("examples/permission-protocol-artifact.json")["artifact"]

    def test_execute_request_carries_the_binding(self) -> None:
        proposal, approval = self.envelope["proposal"], self.envelope["approvals"][0]
        body = adapter.execute_request(proposal, approval["request_id"], 1, approval["action_hash"])
        self.assertEqual(
            body["constraints"]["idempotencyKey"],
            f"agent-approval-gate:{approval['request_id']}:1:{approval['action_hash']}",
        )
        self.assertEqual(body["action"]["parameters"], proposal["payload"])

    def test_revoked_issuer_key_is_refused(self) -> None:
        key_set = deepcopy(self.key_set)
        key_set["keys"][0]["status"] = "revoked"
        with self.assertRaises(ValueError):
            adapter.receipt_signature(self.artifact, key_set, key_set_uri="urn:test")

    def test_artifact_hash_mismatch_is_refused(self) -> None:
        artifact = dict(self.artifact, signed_payload_hash="0" * 64)
        with self.assertRaises(ValueError):
            adapter.receipt_signature(artifact, self.key_set, key_set_uri="urn:test")

    def test_denial_needs_a_rejection_settlement(self) -> None:
        payload = json.loads(base64.b64decode(self.artifact["payload_bytes_b64"]))
        payload["status"] = "DENIED"
        artifact = dict(self.artifact, payload_bytes_b64=base64.b64encode(json.dumps(payload).encode()).decode())
        approval = self.envelope["approvals"][0]
        with self.assertRaises(ValueError):
            adapter.approval_record(
                artifact, self.key_set, approval_id="approval_x", request_id=approval["request_id"],
                request_revision=approval["request_revision"],
                proposal_id=approval["proposal_id"], action_hash=approval["action_hash"],
                payload_hash=approval["payload_hash"], review_snapshot=self.envelope["review_snapshots"][-1],
                approver={"identifier": "rene@acme-corp.example"}, recorded_at=approval["recorded_at"],
                key_set_uri="urn:test",
            )


if __name__ == "__main__":
    unittest.main()
