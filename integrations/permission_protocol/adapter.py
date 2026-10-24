#!/usr/bin/env python3
"""Reference adapter: route a held ProposedAction to Permission Protocol and record its receipt.

This is a reference, not an SDK. It shows the three hand-offs and keeps each one small:

1. ``execute_request`` builds the execute-lane request. Its idempotency key binds the
   gate's request id, request revision and effective action_hash, and the issuer signs
   that key into the receipt as ``idemKey``.
2. ``submit``, ``fetch_artifact`` and ``fetch_key_set`` talk to the issuer over HTTPS.
3. ``approval_record`` turns the signed receipt artifact into an ApprovalRecord whose
   ``pp-receipt-ed25519`` signature the conformance validator checks offline.

Only step 3 is covered by this repository's tests. The receipt format is the published
one (permission-protocol/receipt-spec, jcs_v2); the HTTP request and response shapes of
step 2 follow the issuer's public docs and have not been exercised against a live tenant.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
from typing import Any

import rfc8785

DEFAULT_BASE_URL = "https://app.permissionprotocol.com"
KEY_SET_PATH = "/.well-known/permission-protocol/keys.json"
SCHEMA_VERSION = "3.4.0"


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def binding(request_id: str, request_revision: int, action_hash: str) -> str:
    return f"agent-approval-gate:{request_id}:{request_revision}:{action_hash}"


def execute_request(
    proposal: dict[str, Any],
    request_id: str,
    request_revision: int,
    action_hash: str,
    *,
    environment: str = "production",
    reversibility: str = "IRREVERSIBLE",
) -> dict[str, Any]:
    """The execute-lane body for one held action, sent while the request waits at ``request_revision``."""
    action_type = proposal["action_type"]
    tool, _, operation = action_type.partition(".")
    return {
        "action": {
            "tool": tool,
            "operation": operation or action_type,
            "parameters": proposal["payload"],
        },
        "actor": {"agentId": proposal["agent"]["identity"], "runId": proposal["agent"]["run_id"]},
        "intent": {
            "category": "agent-approval-gate",
            "name": action_type,
            "summary": f"{action_type} held by request {request_id}",
        },
        "context": {"environment": environment, "reversibility": reversibility},
        "constraints": {
            "idempotencyKey": binding(request_id, request_revision, action_hash),
        },
    }


def _call(method: str, url: str, api_key: str | None, body: Any = None) -> Any:
    headers = {"Accept": "application/json"}
    data = None
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    with urllib.request.urlopen(urllib.request.Request(url, data, headers, method=method), timeout=15) as reply:
        return json.loads(reply.read().decode("utf-8"))


def submit(body: dict[str, Any], api_key: str, base_url: str = DEFAULT_BASE_URL) -> Any:
    return _call("POST", base_url.rstrip("/") + "/api/v1/execute", api_key, body)


def fetch_artifact(receipt_id: str, api_key: str, base_url: str = DEFAULT_BASE_URL) -> dict[str, Any]:
    reply = _call("GET", f"{base_url.rstrip('/')}/api/v1/receipts/{receipt_id}/artifact", api_key)
    return reply["artifact"]


def fetch_key_set(base_url: str = DEFAULT_BASE_URL) -> dict[str, Any]:
    """Fetch once and retain your own copy: a verifier pinned to a stored key set needs no network."""
    return _call("GET", base_url.rstrip("/") + KEY_SET_PATH, None)


def receipt_signature(artifact: dict[str, Any], key_set: dict[str, Any], *, key_set_uri: str) -> dict[str, Any]:
    """The ApprovalRecord signature entry for one receipt artifact."""
    key = next(item for item in key_set["keys"] if item["key_id"] == artifact["key_id"])
    if key.get("status") == "revoked":
        raise ValueError(f"issuer key {key['key_id']} is revoked")
    issuer = key_set["issuer"]
    public_key = base64url(base64.b64decode(key["public_key_b64"]))
    payload_bytes = base64.b64decode(artifact["payload_bytes_b64"])
    if hashlib.sha256(payload_bytes).hexdigest() != artifact["signed_payload_hash"]:
        raise ValueError("artifact payload does not match its signed_payload_hash")
    canonicalization = json.loads(payload_bytes)["canonicalization"]
    return {
        "algorithm": "pp-receipt-ed25519",
        "key_id": artifact["key_id"],
        "value": base64url(base64.b64decode(artifact["signature_b64"])),
        "permission_protocol": {
            "receipt_id": artifact["receipt_id"],
            "issuer": issuer,
            "canonicalization": canonicalization,
            "payload_bytes": base64url(payload_bytes),
            "signed_payload_hash": "sha256:" + artifact["signed_payload_hash"],
            "issuer_public_key": public_key,
            "key_evidence": {
                "kind": "permission_protocol_key",
                "uri": key_set_uri,
                "digest": digest({"issuer": issuer, "key_id": key["key_id"], "public_key": public_key}),
                "label": "Retained copy of the issuer's published key set",
            },
        },
    }


def approval_record(
    artifact: dict[str, Any],
    key_set: dict[str, Any],
    *,
    approval_id: str,
    request_id: str,
    request_revision: int,
    proposal_id: str,
    action_hash: str,
    payload_hash: str,
    review_snapshot: dict[str, Any],
    approver: dict[str, Any],
    recorded_at: str,
    key_set_uri: str,
    policy_evaluation_id: str | None = None,
    comment: str | None = None,
    rejection_settlement: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """An ApprovalRecord for the decision the receipt signs. ``approver`` is the gate's identity for the signer."""
    payload = json.loads(base64.b64decode(artifact["payload_bytes_b64"]))
    decided_at = payload["createdAt"].split(".")[0] + "Z"
    decision = {"APPROVED": "approved", "DENIED": "rejected"}[payload["status"]]
    if decision == "rejected" and rejection_settlement is None:
        raise ValueError("a denied receipt needs the rejection_settlement the gate recorded")
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "approval_id": approval_id,
        "request_id": request_id,
        "proposal_id": proposal_id,
        "request_revision": request_revision,
        "action_hash": action_hash,
        "payload_hash": payload_hash,
        "review_snapshot_id": review_snapshot["snapshot_id"],
        "review_content_hash": review_snapshot["content_hash"],
        "decision": decision,
        "decided_by": {
            "kind": "human",
            **approver,
            "authentication": {
                "method": "authenticated_session",
                "human_present": True,
                "assurance": "high" if payload.get("deciderAuthMethod") != "session" else "substantial",
                "authenticated_at": decided_at,
                "evidence_ref": f"permission-protocol-receipt:{artifact['receipt_id']}",
            },
        },
        "decided_at": decided_at,
        "recorded_at": recorded_at,
        "channel": "web",
    }
    if comment:
        record["comment"] = comment
    if policy_evaluation_id:
        record["policy_evaluation_id"] = policy_evaluation_id
    if rejection_settlement:
        record["rejection_settlement"] = rejection_settlement
    record["signatures"] = [receipt_signature(artifact, key_set, key_set_uri=key_set_uri)]
    return record
