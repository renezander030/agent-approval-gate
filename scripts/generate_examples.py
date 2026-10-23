#!/usr/bin/env python3
"""Regenerate hashes and the composed release example deterministically."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_contracts import (  # noqa: E402
    digest as digest_value, encode_base64url as base64url, execution_grant_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SCHEMAS = ROOT / "schemas"


def load(name: str) -> Any:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def write(name: str, value: Any) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    (EXAMPLES / name).write_text(rendered, encoding="utf-8")


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_audit(envelope: dict[str, Any]) -> None:
    previous = None
    for index, event in enumerate(envelope["audit_events"], 1):
        event["sequence"] = index
        event["previous_event_hash"] = previous
        event["event_hash"] = digest_value({k: v for k, v in event.items() if k != "event_hash"})
        previous = event["event_hash"]
    events = envelope["audit_events"]
    envelope["audit_snapshot"].update(
        entry_count=len(events), first_sequence=1, last_sequence=len(events),
        events_digest=digest_value(events), root_event_hash=previous,
    )


def refuse_dispatch(envelope: dict[str, Any], reason: str, **changes: Any) -> dict[str, Any]:
    """Turn the lifecycle's dispatch into a not_dispatched refusal, and its audit witness with it."""
    dispatch = envelope["dispatches"][0]
    dispatch.update(status="not_dispatched", reason=reason, **changes)
    dispatch.pop("provider")
    for event in envelope["audit_events"]:
        if event["event_type"] == "dispatch.succeeded":
            event.update(event_type="dispatch.not_dispatched", occurred_at=dispatch["completed_at"], recorded_at=dispatch["recorded_at"])
            event["detail"] = {"action_hash": dispatch["action_hash"], "reason_code": reason}
    return dispatch


def rebind_action(envelope: dict[str, Any], action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Move the reference lifecycle onto another action type and recompute every binding."""
    envelope = deepcopy(envelope)
    proposal = envelope["proposal"]
    schema_path = SCHEMAS / "actions" / f"{action_type}.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    proposal.update(action_type=action_type, payload=deepcopy(payload))
    proposal["payload_schema"] = {
        "id": schema["$id"],
        "version": envelope["schema_version"],
        "digest": digest_file(schema_path),
    }
    action_hash, payload_hash = digest_value(proposal), digest_value(payload)
    envelope["validations"][0]["action_hash"] = action_hash
    envelope["request"]["action_hash"] = action_hash
    envelope["request"]["policy"]["material_input_hash"] = action_hash
    review = envelope["review_snapshots"][0]
    review["content"].update(
        action_type=action_type, arguments=deepcopy(payload),
        target={key: payload[key] for key in schema["x-review-target"] if key in payload},
    )
    review.update(action_hash=action_hash, payload_hash=payload_hash, content_hash=digest_value(review["content"]))
    approval = envelope["approvals"][0]
    approval.update(action_hash=action_hash, payload_hash=payload_hash, review_content_hash=review["content_hash"])
    envelope["resolutions"][0].update(action_hash=action_hash, approval_record_hash=digest_value(approval))
    authority = envelope["authority_snapshots"][0]
    authority["action_hash"] = action_hash
    for subject in authority["subjects"]:
        subject["scopes"] = [action_type if scope == "email.send" else scope for scope in subject.get("scopes", [])]
    authority["authority_digest"] = digest_value(authority["subjects"])
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


def lifecycle_examples(base: dict[str, Any]) -> None:
    edited = deepcopy(base)
    approval = edited["approvals"][0]
    approval["modifications"] = [{"op": "replace", "path": "/payload/subject", "value": "Re: invoice export restored"}]
    effective = deepcopy(edited["proposal"])
    effective["payload"]["subject"] = "Re: invoice export restored"
    action_hash = digest_value(effective)
    payload_hash = digest_value(effective["payload"])
    review = deepcopy(edited["review_snapshots"][0])
    review.update(snapshot_id="review_edited_01", action_hash=action_hash, payload_hash=payload_hash, rendered_at="2026-04-28T09:14:26Z")
    review["content"]["arguments"] = deepcopy(effective["payload"])
    review["content_hash"] = digest_value(review["content"])
    edited["review_snapshots"].append(review)
    approval.update(action_hash=action_hash, payload_hash=payload_hash, review_snapshot_id=review["snapshot_id"], review_content_hash=review["content_hash"])
    edited["resolutions"][0].update(action_hash=action_hash, approval_record_hash=digest_value(approval))
    edited["authority_snapshots"][0]["action_hash"] = action_hash
    edited["dispatches"][0]["action_hash"] = action_hash
    review_event = deepcopy(edited["audit_events"][3])
    review_event.update(event_id="event_edited_review_01", occurred_at=review["rendered_at"], recorded_at=review["rendered_at"])
    review_event["references"]["review_snapshot_id"] = review["snapshot_id"]
    review_event["detail"].update(action_hash=action_hash, payload_hash=payload_hash, review_content_hash=review["content_hash"])
    edited["audit_events"].insert(4, review_event)
    for event in edited["audit_events"][5:]:
        if "action_hash" in event["detail"]:
            event["detail"]["action_hash"] = action_hash
        if "payload_hash" in event["detail"]:
            event["detail"]["payload_hash"] = payload_hash
    refresh_audit(edited)
    write("edited-envelope.json", edited)

    rejected = deepcopy(base)
    request = rejected["request"]
    request.update(status="rejected", revision=2, terminal_reason="rejected")
    request.pop("consumed_at")
    request.pop("dispatch_id")
    approval = rejected["approvals"][0]
    approval.update(decision="rejected", rejection_settlement={"state": "unresolved"})
    resolution = rejected["resolutions"][0]
    resolution.update(decision="rejected", disposition="revise_and_resubmit", retry_policy="new_proposal", approval_record_hash=digest_value(approval))
    resolution["agent_feedback"] = {
        "reason_code": "incorrect_content",
        "message": "The reply promises a restore date that engineering has not confirmed.",
        "requested_changes": [{"path": "/payload/body_text", "note": "Remove the restore date and link the status page instead."}],
    }
    rejected["authority_snapshots"] = []
    refuse_dispatch(rejected, "approval_rejected", approval_ids=[]).pop("authority_snapshot_id")
    rejected["audit_events"] = [e for e in rejected["audit_events"] if e["event_type"] != "authority.checked"]
    for event in rejected["audit_events"]:
        if event["event_type"] in {"approval.decided", "resolution.emitted"}:
            event["detail"]["decision"] = "rejected"
        if event["event_type"] == "resolution.emitted":
            event["detail"]["reason_code"] = resolution["agent_feedback"]["reason_code"]
    refresh_audit(rejected)
    write("rejected-envelope.json", rejected)

    expired = deepcopy(base)
    expiry = expired["request"]["expires_at"]
    expired["request"].update(status="expired", revision=2, terminal_at=expiry, terminal_reason="deadline_elapsed")
    for key in ("consumed_at", "dispatch_id", "decision_record_id"):
        expired["request"].pop(key)
    for key in ("approvals", "resolutions", "authority_snapshots", "dispatches"):
        expired[key] = []
    expiry_event = deepcopy(expired["audit_events"][4])
    expiry_event.update(event_type="approval.expired", occurred_at=expiry, recorded_at=expiry, actor=deepcopy(expired["request"]["requested_by"]), references={"request_id": expired["request"]["request_id"]}, detail={"reason_code": "deadline_elapsed"})
    snapshot_event = deepcopy(expired["audit_events"][-1])
    snapshot_event.update(occurred_at=expiry, recorded_at=expiry)
    expired["audit_events"] = expired["audit_events"][:4] + [expiry_event, snapshot_event]
    expired["captured_at"] = expired["audit_snapshot"]["captured_at"] = expiry
    refresh_audit(expired)
    write("expired-envelope.json", expired)

    revoked = deepcopy(base)
    revoked_at = "2026-04-28T09:14:34Z"
    request = revoked["request"]
    request.update(status="revoked", revision=3, terminal_at=revoked_at, terminal_reason="approval_revoked")
    request.pop("consumed_at")
    request.pop("dispatch_id")
    revoker = deepcopy(revoked["approvals"][0]["decided_by"])
    request["revocation"] = {"revoked_at": revoked_at, "revoked_by": revoker, "reason_code": "target_changed", "safe_detail": "Customer replied on another thread before dispatch"}
    revoked["authority_snapshots"] = []
    refuse_dispatch(revoked, "approval_revoked", approval_ids=[], started_at="2026-04-28T09:14:35Z",
                    completed_at="2026-04-28T09:14:35Z", recorded_at="2026-04-28T09:14:35Z").pop("authority_snapshot_id")
    events = [e for e in revoked["audit_events"] if e["event_type"] != "authority.checked"]
    revocation_event = deepcopy(next(e for e in events if e["event_type"] == "approval.decided"))
    revocation_event.update(event_id="event_revoked_01", event_type="approval.revoked", occurred_at=revoked_at, recorded_at=revoked_at, actor=deepcopy(revoker), references={"request_id": request["request_id"]}, detail={"reason_code": "target_changed"})
    index = next(i for i, e in enumerate(events) if e["event_type"] == "dispatch.not_dispatched")
    events[index]["references"].pop("approval_id")
    events.insert(index, revocation_event)
    revoked["audit_events"] = events
    refresh_audit(revoked)
    write("revoked-envelope.json", revoked)

    recovered = deepcopy(base)
    first = recovered["dispatches"][0]
    first.update(status="outcome_unknown", reason="provider_response_lost", reconciliation={"lookup_key_hash": digest_value("provider-lookup-01"), "status": "pending"})
    first.pop("provider")
    reconciled = deepcopy(first)
    reconciled.update(dispatch_id="dispatch_reconciled_01", previous_dispatch_id=first["dispatch_id"], status="reconciled_not_applied", retry_allowed=True, started_at="2026-04-28T09:14:35Z", completed_at="2026-04-28T09:14:35Z", recorded_at="2026-04-28T09:14:35Z")
    reconciled.pop("reason")
    reconciled["reconciliation"].update(status="not_applied", checked_at="2026-04-28T09:14:35Z", evidence={"kind":"reconciliation", "uri":"urn:example:lookup:01", "digest":digest_value("not-applied")})
    retry = deepcopy(base["dispatches"][0])
    retry.update(dispatch_id="dispatch_retry_02", previous_dispatch_id=reconciled["dispatch_id"], attempt=2, started_at="2026-04-28T09:14:36Z", completed_at="2026-04-28T09:14:37Z", recorded_at="2026-04-28T09:14:37Z", authority_snapshot_id="authority_retry_02")
    retry_authority = deepcopy(recovered["authority_snapshots"][0])
    retry_authority.update(authority_snapshot_id="authority_retry_02", checked_at="2026-04-28T09:14:36Z")
    recovered["authority_snapshots"].append(retry_authority)
    recovered["dispatches"] = [first, reconciled, retry]
    events = recovered["audit_events"]
    first_event = events[-2]
    first_event["event_type"] = "dispatch.outcome_unknown"
    first_event["detail"].pop("provider_result_hash")
    reconciliation_event = deepcopy(first_event)
    reconciliation_event.update(event_id="event_reconciled_01", event_type="dispatch.reconciled", occurred_at=reconciled["completed_at"], recorded_at=reconciled["recorded_at"])
    reconciliation_event["references"]["dispatch_id"] = reconciled["dispatch_id"]
    authority_event = deepcopy(events[-3])
    authority_event.update(event_id="event_retry_authority_02", occurred_at=retry_authority["checked_at"], recorded_at=retry_authority["checked_at"])
    authority_event["references"]["authority_snapshot_id"] = retry_authority["authority_snapshot_id"]
    retry_event = deepcopy(base["audit_events"][-2])
    retry_event.update(event_id="event_retry_02", occurred_at=retry["completed_at"], recorded_at=retry["recorded_at"])
    retry_event["references"]["dispatch_id"] = retry["dispatch_id"]
    retry_event["detail"]["attempt"] = 2
    final_event = events[-1]
    final_event.update(occurred_at="2026-04-28T09:14:38Z", recorded_at="2026-04-28T09:14:38Z")
    recovered["audit_events"] = events[:-1] + [reconciliation_event, authority_event, retry_event, final_event]
    recovered["captured_at"] = recovered["audit_snapshot"]["captured_at"] = "2026-04-28T09:14:38Z"
    refresh_audit(recovered)
    write("recovered-envelope.json", recovered)

    payload = json.loads((EXAMPLES / "actions" / "file.write.json").read_text(encoding="utf-8"))
    precondition = {"resource": payload["path"], "kind": "content_digest", "expected": digest_value("exports:\n  per_minute: 20\n")}
    guarded = deepcopy(base)
    guarded["proposal"]["target_precondition"] = precondition
    guarded["review_snapshots"][0]["content"]["target_precondition"] = deepcopy(precondition)
    guarded = rebind_action(guarded, "file.write", payload)
    guarded["dispatches"][0]["precondition_check"] = {"checked_at": guarded["dispatches"][0]["started_at"], "result": "matched", "observed_hash": precondition["expected"]}
    refresh_audit(guarded)
    write("precondition-envelope.json", guarded)

    stale = deepcopy(guarded)
    dispatch = refuse_dispatch(stale, "precondition_failed")
    dispatch["precondition_check"].update(result="changed", observed_hash=digest_value("exports:\n  per_minute: 30\n"))
    refresh_audit(stale)
    write("precondition-failed-envelope.json", stale)

    standing = deepcopy(base)
    standing["proposal"]["risk"] = "medium"
    standing["review_snapshots"][0]["content"]["risk"] = "medium"
    policy = standing["request"]["policy"]
    policy.update(outcome="auto_approve", matched_rules=[{"rule_id": "rule.support.granted-reply", "effect": "auto_approve"}])
    requirements = policy["requirements"]
    requirements.update(human_only=False, allow_auto_approval=True, allowed_channels=["email", "web", "policy"],
                        require_standing_grant=True, human_required_effects=["destructive"])
    requirements.pop("required_roles")
    requirements["separation_of_duties"].pop("eligible_approver_ids")
    granter = deepcopy(standing["approvals"][0]["decided_by"])
    approval = standing["approvals"][0]
    approval.pop("signatures", None)
    approval.pop("comment", None)
    approval.update(
        decision="auto_approved", channel="policy", decided_at="2026-04-28T09:14:27Z", recorded_at="2026-04-28T09:14:27Z",
        decided_by={"kind": "policy", "identifier": policy["policy_id"], "authentication": {"method": "policy_engine", "human_present": False, "assurance": "high", "authenticated_at": "2026-04-28T09:14:27Z"}},
        standing_grant={
            "grant_id": "grant_2026-04-27_support-replies", "granted_by": granter,
            "granted_at": "2026-04-27T16:02:00Z", "expires_at": "2026-05-04T16:02:00Z",
            "scope": {"tenant": standing["proposal"]["tenant"], "action_types": ["email.send"], "max_risk": "medium"},
            "max_uses": 200, "use_number": 14,
        },
    )
    authority = standing["authority_snapshots"][0]
    for subject in authority["subjects"]:
        if subject["kind"] == "approver":
            subject["identifier"] = policy["policy_id"]
    authority["authority_digest"] = digest_value(authority["subjects"])
    for event in standing["audit_events"]:
        if event["event_type"] == "approval.decided":
            event.update(actor=deepcopy(approval["decided_by"]), occurred_at=approval["decided_at"], recorded_at=approval["recorded_at"])
            event["detail"].update(decision="auto_approved", channel="policy")
            event["detail"].pop("wait_ms", None)
        if event["event_type"] == "resolution.emitted":
            event["detail"]["decision"] = "auto_approved"
    standing["resolutions"][0]["decision"] = "auto_approved"
    standing = rebind_action(standing, "email.send", standing["proposal"]["payload"])
    write("standing-grant-envelope.json", standing)
    write("standing-grant-approval-record.json", standing["approvals"][0])

    granted = deepcopy(base)
    granted["request"]["policy"]["requirements"]["require_execution_grant"] = True
    dispatch = granted["dispatches"][0]
    dispatch["execution_grant"] = {"digest": digest_value(execution_grant_manifest(dispatch)), "issued_at": dispatch["started_at"]}
    write("granted-dispatch-record.json", dispatch)
    refresh_audit(granted)
    write("granted-envelope.json", granted)

    delegated = deepcopy(base)
    proposal = delegated["proposal"]
    child = proposal["delegation_chain"][0]
    root = {
        "agent": {"identity": "agent.support-orchestrator.prod", "name": "support-orchestrator", "version": "2.1.0", "run_id": "run_2026-04-28_5f9e1a00"},
        "call_id": "call_2026-04-28_7e19a001", "delegated_at": "2026-04-28T09:14:21Z",
    }
    child["parent_call_id"] = proposal["parent_call_id"] = root["call_id"]
    proposal["delegation_chain"].insert(0, root)
    delegated = rebind_action(delegated, proposal["action_type"], proposal["payload"])
    request = delegated["request"]
    request["parent_call_id"] = root["call_id"]
    request["relay"] = [{"call_id": root["call_id"], "agent_identity": root["agent"]["identity"], "relayed_at": "2026-04-28T09:14:27Z"}]
    relay_event = deepcopy(next(e for e in delegated["audit_events"] if e["event_type"] == "approval.requested"))
    relay_event.update(event_id="event_relayed_01", event_type="approval.relayed", occurred_at="2026-04-28T09:14:27Z", recorded_at="2026-04-28T09:14:27Z",
                       references={"request_id": request["request_id"]}, detail={"metadata": {"call_id": root["call_id"]}})
    relay_event["actor"]["identifier"] = root["agent"]["identity"]
    index = next(i for i, e in enumerate(delegated["audit_events"]) if e["event_type"] == "approval.decided")
    delegated["audit_events"].insert(index, relay_event)
    notice = {
        "schema_version": delegated["schema_version"], "notice_id": "notice_2026-04-28_child01",
        **{key: request[key] for key in ("request_id", "proposal_id", "call_id", "tenant", "action_hash")},
        "request_revision": 1, "status": "pending", "recipient_call_id": proposal["call_id"],
        "issued_at": "2026-04-28T09:14:25Z", "expires_at": request["expires_at"], "channels": ["email"],
        "resume": "await_resolution", "message": "Waiting for a support lead to approve this reply.",
    }
    parent_notice = dict(notice, notice_id="notice_2026-04-28_parent01", recipient_call_id=root["call_id"],
                         issued_at="2026-04-28T09:14:26Z", next_check_at="2026-04-28T09:44:26Z", resume="poll_request")
    delegated["pending_notices"] = [notice, parent_notice]
    write("approval-pending-notice.json", parent_notice)
    refresh_audit(delegated)
    write("delegated-envelope.json", delegated)

    escalated = deepcopy(base)
    request = escalated["request"]
    request["policy"]["requirements"]["escalation"] = {"after_seconds": 2, "notify_actor_ids": ["support-lead-oncall@acme-corp.example"]}
    request["escalations"] = [{"escalated_at": "2026-04-28T09:14:28Z", "notified_actor_ids": ["support-lead-oncall@acme-corp.example"], "channel": "email"}]
    escalation_event = deepcopy(next(e for e in escalated["audit_events"] if e["event_type"] == "approval.requested"))
    escalation_event.update(event_id="event_escalated_01", event_type="approval.escalated", occurred_at="2026-04-28T09:14:28Z", recorded_at="2026-04-28T09:14:28Z",
                            references={"request_id": request["request_id"]}, detail={"channel": "email", "reason_code": "no_decision_yet"})
    index = next(i for i, e in enumerate(escalated["audit_events"]) if e["event_type"] == "approval.decided")
    escalated["audit_events"].insert(index, escalation_event)
    refresh_audit(escalated)
    write("escalated-envelope.json", escalated)

    denied = deepcopy(base)
    request = denied["request"]
    policy = request["policy"]
    policy.update(outcome="deny", matched_rules=[
        {"rule_id": "rule.email.external-recipient", "effect": "require_approval"},
        {"rule_id": "rule.email.legal-hold-account", "effect": "deny"},
    ], outcome_reason="The recipient account is under a legal hold.")
    request.update(status="failed", revision=2, terminal_at=request["requested_at"], terminal_reason="policy_failed")
    for key in ("consumed_at", "dispatch_id", "decision_record_id"):
        request.pop(key)
    request["policy_refusal"] = {
        "evaluation_id": policy["evaluation_id"], "reason_code": "denied_by_rule", "rule_ids": ["rule.email.legal-hold-account"],
        "message": "Replies to accounts under a legal hold go through the legal team, not the support queue.",
        "policy_owner": "legal-ops@acme-corp.example", "next_step": "contact_policy_owner",
    }
    for key in ("approvals", "resolutions", "authority_snapshots", "dispatches"):
        denied[key] = []
    snapshot_event = deepcopy(denied["audit_events"][-1])
    snapshot_event.update(occurred_at="2026-04-28T09:14:27Z", recorded_at="2026-04-28T09:14:27Z")
    denied["audit_events"] = denied["audit_events"][:4] + [snapshot_event]
    denied["captured_at"] = denied["audit_snapshot"]["captured_at"] = "2026-04-28T09:14:27Z"
    refresh_audit(denied)
    write("policy-denied-envelope.json", denied)


def main() -> None:
    proposal = load("email-reply-approval.json")
    proposal["payload_schema"]["digest"] = digest_file(
        SCHEMAS / "actions" / "email.send.schema.json"
    )
    write("email-reply-approval.json", proposal)

    action_hash = digest_value(proposal)
    payload_hash = digest_value(proposal["payload"])

    validation = load("validation-record.json")
    validation["action_hash"] = action_hash
    write("validation-record.json", validation)

    policy = load("approval-policy.json")
    policy["material_input_hash"] = action_hash
    write("approval-policy.json", policy)
    rule_trace = deepcopy(policy)
    rule_trace["matched_rules"] = [
        {"rule_id": "rule.email.external-recipient", "effect": "require_approval"},
        {"rule_id": "rule.support.linked-ticket", "effect": "auto_approve"},
    ]
    write("approval-policy-rules.json", rule_trace)

    review_snapshot = load("review-snapshot.json")
    review_snapshot["action_hash"] = action_hash
    review_snapshot["payload_hash"] = payload_hash
    review_snapshot["content"]["arguments"] = deepcopy(proposal["payload"])
    review_snapshot["content_hash"] = digest_value(review_snapshot["content"])
    write("review-snapshot.json", review_snapshot)

    request = load("approval-request.json")
    request["action_hash"] = action_hash
    request["policy"] = deepcopy(policy)
    write("approval-request.json", request)

    approval = load("email-reply-approval-record.json")
    approval["action_hash"] = action_hash
    approval["payload_hash"] = payload_hash
    approval["review_content_hash"] = review_snapshot["content_hash"]
    write("email-reply-approval-record.json", approval)

    webauthn_approval = load("webauthn-approval-record.json")
    webauthn_approval["action_hash"] = action_hash
    webauthn_approval["payload_hash"] = payload_hash
    webauthn_approval["review_content_hash"] = review_snapshot["content_hash"]
    webauthn_approval.pop("signatures", None)
    signed_object_hash = digest_value(webauthn_approval)
    challenge = base64url(bytes.fromhex(signed_object_hash.removeprefix("sha256:")))
    origin = "https://approve.acme-corp.example"
    rp_id = "acme-corp.example"
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": False,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    previous_sign_count = 8
    sign_count = 9
    authenticator_data = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([0x05])
        + sign_count.to_bytes(4, "big")
    )
    private_key = ec.derive_private_key(20260925, ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    credential_id = base64url(hashlib.sha256(public_key).digest())
    signature_value = private_key.sign(
        authenticator_data + hashlib.sha256(client_data).digest(),
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
    )
    registration = {
        "credential_id": credential_id,
        "credential_public_key": base64url(public_key),
        "rp_id": rp_id,
        "actor": webauthn_approval["decided_by"]["identifier"],
        "previous_sign_count": previous_sign_count,
    }
    webauthn_approval["signatures"] = [
        {
            "algorithm": "webauthn-es256",
            "key_id": credential_id,
            "value": base64url(signature_value),
            "signed_object_hash": signed_object_hash,
            "webauthn": {
                "credential_id": credential_id,
                "credential_public_key": base64url(public_key),
                "public_key_format": "spki-der",
                "authenticator_data": base64url(authenticator_data),
                "client_data_json": base64url(client_data),
                "rp_id": rp_id,
                "origin": origin,
                "user_verification": "required",
                "previous_sign_count": previous_sign_count,
                "sign_count": sign_count,
                "registration_evidence": {
                    "kind": "webauthn_registration",
                    "uri": "urn:acme:webauthn-registration:rene:2026-04-01",
                    "digest": digest_value(registration),
                    "label": "Independently retained credential registration",
                },
            },
        }
    ]
    write("webauthn-approval-record.json", webauthn_approval)

    resolution = load("resolution-record.json")
    resolution["action_hash"] = action_hash
    resolution["approval_record_hash"] = digest_value(approval)
    write("resolution-record.json", resolution)

    authority_snapshot = load("authority-snapshot.json")
    authority_snapshot["action_hash"] = action_hash
    authority_snapshot["authority_digest"] = digest_value(
        authority_snapshot["subjects"]
    )
    write("authority-snapshot.json", authority_snapshot)

    dispatch = load("dispatch-record.json")
    dispatch["action_hash"] = action_hash
    write("dispatch-record.json", dispatch)

    audit_snapshot = load("audit-snapshot.json")
    events = load("audit-events.json")
    for event in events:
        detail = event["detail"]
        if "action_hash" in detail:
            detail["action_hash"] = action_hash
        if "payload_hash" in detail:
            detail["payload_hash"] = payload_hash
        if "review_content_hash" in detail:
            detail["review_content_hash"] = review_snapshot["content_hash"]
        if "audit_snapshot_id" in event["references"]:
            event["references"]["audit_snapshot_id"] = audit_snapshot["snapshot_id"]

    envelope = {
        "schema_version": "3.3.0",
        "captured_at": "2026-04-28T09:14:35Z",
        "proposal": proposal,
        "validations": [validation],
        "review_snapshots": [review_snapshot],
        "request": request,
        "approvals": [approval],
        "resolutions": [resolution],
        "authority_snapshots": [authority_snapshot],
        "dispatches": [dispatch],
        "audit_events": events,
        "audit_snapshot": audit_snapshot,
    }
    refresh_audit(envelope)
    write("audit-events.json", events)
    write("audit-snapshot.json", audit_snapshot)
    write("approval-envelope.json", envelope)
    lifecycle_examples(envelope)


if __name__ == "__main__":
    main()
