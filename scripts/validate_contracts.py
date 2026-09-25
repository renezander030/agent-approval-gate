#!/usr/bin/env python3
"""Validate schemas, examples, negative vectors, and cross-record invariants."""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]


def load(path: str | Path) -> Any:
    target = Path(path)
    if not target.is_absolute():
        target = ROOT / target
    return json.loads(target.read_text(encoding="utf-8"))


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def schema_catalog() -> tuple[dict[str, dict[str, Any]], Registry]:
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted((ROOT / "schemas").rglob("*.json")):
        schema = load(path)
        Draft202012Validator.check_schema(schema)
        identifier = schema.get("$id")
        if not identifier:
            raise ValueError(f"{path.relative_to(ROOT)} has no $id")
        schemas[str(path.relative_to(ROOT))] = schema
        resources.append((identifier, Resource.from_contents(schema)))
    return schemas, Registry().with_resources(resources)


def validator_for(
    schema_path: str, schemas: dict[str, dict[str, Any]], registry: Registry
) -> Draft202012Validator:
    return Draft202012Validator(
        schemas[schema_path], registry=registry, format_checker=FormatChecker()
    )


def _pointer_parent(document: Any, path: str) -> tuple[Any, str]:
    if not path.startswith("/"):
        raise ValueError(f"JSON Pointer must start with '/': {path}")
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in path[1:].split("/")]
    current = document
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current, tokens[-1]


def apply_operations(document: Any, operations: list[dict[str, Any]]) -> Any:
    result = deepcopy(document)
    for operation in operations:
        parent, key = _pointer_parent(result, operation["path"])
        op = operation["op"]
        if op == "remove":
            if isinstance(parent, list):
                parent.pop(int(key))
            else:
                del parent[key]
        elif op in {"add", "replace"}:
            value = deepcopy(operation["value"])
            if isinstance(parent, list):
                index = len(parent) if key == "-" else int(key)
                if op == "add":
                    parent.insert(index, value)
                else:
                    parent[index] = value
            else:
                parent[key] = value
        elif op == "test":
            actual = parent[int(key)] if isinstance(parent, list) else parent[key]
            if actual != operation["value"]:
                raise ValueError(f"test operation failed at {operation['path']}")
        else:
            raise ValueError(f"unsupported operation: {op}")
    return result


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonicalization_errors() -> list[str]:
    errors: list[str] = []
    corpus = load("tests/canonicalization.json")
    for vector in corpus["vectors"]:
        canonical = rfc8785.dumps(vector["value"])
        if canonical.hex() != vector["canonical_hex"]:
            errors.append(f"canonicalization {vector['name']}: byte vector mismatch")
        if digest(vector["value"]) != vector["digest"]:
            errors.append(f"canonicalization {vector['name']}: digest mismatch")
    for vector in corpus["invalid"]:
        try:
            rfc8785.dumps(vector["value"])
        except Exception:
            pass
        else:
            errors.append(f"canonicalization {vector['name']}: invalid value was accepted")
    return errors


def semantic_errors(envelope: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    proposal = envelope["proposal"]
    validations = envelope["validations"]
    review_snapshots = envelope["review_snapshots"]
    request = envelope["request"]
    approvals = envelope["approvals"]
    resolutions = envelope["resolutions"]
    authority_snapshots = envelope["authority_snapshots"]
    dispatches = envelope["dispatches"]
    events = envelope["audit_events"]
    audit_snapshot = envelope["audit_snapshot"]

    initial_action_hash = digest(proposal)
    if request["action_hash"] != initial_action_hash:
        errors.append("request action_hash does not match the proposed action")
    if request["policy"]["material_input_hash"] != initial_action_hash:
        errors.append("policy material_input_hash does not match the proposed action")

    for field in ("proposal_id", "call_id", "tenant"):
        if request[field] != proposal[field]:
            errors.append(f"request {field} does not match proposal")

    created_at = parse_time(proposal["created_at"])
    proposal_expires_at = parse_time(proposal["expires_at"])
    requested_at = parse_time(request["requested_at"])
    request_expires_at = parse_time(request["expires_at"])
    if not created_at < proposal_expires_at:
        errors.append("proposal expires_at must be after created_at")
    if requested_at < created_at:
        errors.append("request predates the proposed action")
    if not requested_at < request_expires_at:
        errors.append("request expires_at must be after requested_at")
    if request_expires_at > proposal_expires_at:
        errors.append("request expiry cannot outlive proposal expiry")
    if parse_time(request["policy"]["evaluated_at"]) > requested_at:
        errors.append("policy evaluation occurred after the approval request")

    delegation_chain = proposal["delegation_chain"]
    delegation_call_ids = [hop["call_id"] for hop in delegation_chain]
    if len(delegation_call_ids) != len(set(delegation_call_ids)):
        errors.append("delegation chain reuses a call_id")
    for index, hop in enumerate(delegation_chain):
        if index == 0 and "parent_call_id" in hop:
            errors.append("root delegation hop cannot have parent_call_id")
        if index > 0 and hop.get("parent_call_id") != delegation_chain[index - 1]["call_id"]:
            errors.append("delegation chain parent_call_id linkage is broken")
        if index > 0 and parse_time(hop["delegated_at"]) < parse_time(
            delegation_chain[index - 1]["delegated_at"]
        ):
            errors.append("delegation chain times are not monotonic")
        if parse_time(hop["delegated_at"]) > created_at:
            errors.append("delegation occurred after the proposal was created")
    terminal_hop = delegation_chain[-1]
    if terminal_hop["call_id"] != proposal["call_id"]:
        errors.append("terminal delegation hop does not match proposal call_id")
    if terminal_hop["agent"] != proposal["agent"]:
        errors.append("terminal delegation hop does not match proposal agent")
    expected_parent = terminal_hop.get("parent_call_id")
    if proposal.get("parent_call_id") != expected_parent:
        errors.append("proposal parent_call_id does not match delegation chain")

    validation_by_id = {item["validation_id"]: item for item in validations}
    if len(validation_by_id) != len(validations):
        errors.append("validation records reuse validation_id")
    validation = validation_by_id.get(request["validation_id"])
    if validation is None:
        errors.append("request names an unknown validation record")
    else:
        if validation["proposal_id"] != proposal["proposal_id"]:
            errors.append("validation record points at another proposal")
        if validation["action_hash"] != initial_action_hash:
            errors.append("validation record action_hash mismatch")
        if validation["outcome"] != "passed":
            errors.append("approval request was admitted without passed validation")
        required_checks = {
            "proposal_schema",
            "payload_schema",
            "semantic_preconditions",
            "policy_inputs",
            "authorization_inputs",
        }
        check_names = [item["name"] for item in validation["checks"]]
        if len(check_names) != len(set(check_names)):
            errors.append("validation record repeats a check name")
        passed_checks = {
            item["name"] for item in validation["checks"] if item["status"] == "passed"
        }
        if not required_checks.issubset(passed_checks):
            errors.append("validation record lacks all mandatory passed checks")
        if any(item["status"] == "failed" for item in validation["checks"]):
            errors.append("passed validation record contains a failed check")
        if parse_time(validation["validated_at"]) > requested_at:
            errors.append("approval request predates validation")

    snapshot_by_id = {item["snapshot_id"]: item for item in review_snapshots}
    if len(snapshot_by_id) != len(review_snapshots):
        errors.append("review snapshots reuse snapshot_id")
    for snapshot in review_snapshots:
        if snapshot["content_hash"] != digest(snapshot["content"]):
            errors.append(f"review snapshot {snapshot['snapshot_id']} content_hash mismatch")
        identity = snapshot["content"]["action_identity"]
        if identity["proposal_id"] != proposal["proposal_id"]:
            errors.append(f"review snapshot {snapshot['snapshot_id']} points at another proposal")
        if identity["call_id"] != proposal["call_id"]:
            errors.append(f"review snapshot {snapshot['snapshot_id']} points at another call")
        if identity["agent_identity"] != proposal["agent"]["identity"]:
            errors.append(f"review snapshot {snapshot['snapshot_id']} points at another agent")
        if snapshot["content"]["action_type"] != proposal["action_type"]:
            errors.append(f"review snapshot {snapshot['snapshot_id']} changes action_type")
        if snapshot["content"]["risk"] != proposal["risk"]:
            errors.append(f"review snapshot {snapshot['snapshot_id']} changes risk")
        if snapshot["content"]["expires_at"] != proposal["expires_at"]:
            errors.append(f"review snapshot {snapshot['snapshot_id']} changes expiry")
        rendered_at = parse_time(snapshot["rendered_at"])
        if rendered_at < created_at:
            errors.append(f"review snapshot {snapshot['snapshot_id']} predates proposal")
        if rendered_at > request_expires_at:
            errors.append(f"review snapshot {snapshot['snapshot_id']} was rendered after expiry")
        if proposal["action_type"] == "email.send":
            expected_target = {
                key: proposal["payload"][key] for key in ("from", "to", "cc")
            }
            if snapshot["content"]["target"] != expected_target:
                errors.append(
                    f"review snapshot {snapshot['snapshot_id']} changes the email target"
                )

    initial_snapshot = snapshot_by_id.get(request["review_snapshot_id"])
    if initial_snapshot is None:
        errors.append("request names an unknown review snapshot")
    else:
        if initial_snapshot["action_hash"] != initial_action_hash:
            errors.append("initial review snapshot action_hash mismatch")
        if initial_snapshot["payload_hash"] != digest(proposal["payload"]):
            errors.append("initial review snapshot payload_hash mismatch")
        if initial_snapshot["content"]["arguments"] != proposal["payload"]:
            errors.append("initial review snapshot omits or changes action arguments")

    approved_records = [
        approval
        for approval in approvals
        if approval["decision"] in {"approved", "auto_approved"}
    ]
    effective_hashes: dict[str, str] = {}
    for approval in approvals:
        if approval["proposal_id"] != proposal["proposal_id"]:
            errors.append(f"approval {approval['approval_id']} points at another proposal")
        if approval["request_id"] != request["request_id"]:
            errors.append(f"approval {approval['approval_id']} points at another request")
        effective_action = apply_operations(proposal, approval.get("modifications", []))
        expected_action_hash = digest(effective_action)
        expected_payload_hash = digest(effective_action["payload"])
        effective_hashes[approval["approval_id"]] = expected_action_hash
        if approval["action_hash"] != expected_action_hash:
            errors.append(f"approval {approval['approval_id']} action_hash mismatch")
        if approval["payload_hash"] != expected_payload_hash:
            errors.append(f"approval {approval['approval_id']} payload_hash mismatch")
        review_snapshot = snapshot_by_id.get(approval["review_snapshot_id"])
        if review_snapshot is None:
            errors.append(
                f"approval {approval['approval_id']} names an unknown review snapshot"
            )
        else:
            if parse_time(review_snapshot["rendered_at"]) > parse_time(
                approval["decided_at"]
            ):
                errors.append(
                    f"approval {approval['approval_id']} predates its review snapshot"
                )
            if review_snapshot["action_hash"] != expected_action_hash:
                errors.append(
                    f"approval {approval['approval_id']} review action_hash mismatch"
                )
            if review_snapshot["payload_hash"] != expected_payload_hash:
                errors.append(
                    f"approval {approval['approval_id']} review payload_hash mismatch"
                )
            if review_snapshot["content_hash"] != approval["review_content_hash"]:
                errors.append(
                    f"approval {approval['approval_id']} review content_hash mismatch"
                )
            if review_snapshot["content"]["arguments"] != effective_action["payload"]:
                errors.append(
                    f"approval {approval['approval_id']} review omitted effective arguments"
                )
        if approval["request_revision"] >= request["revision"]:
            errors.append(
                f"approval {approval['approval_id']} did not observe a pending request revision"
            )
        decided_at = parse_time(approval["decided_at"])
        recorded_at = parse_time(approval["recorded_at"])
        if recorded_at < decided_at:
            errors.append(f"approval {approval['approval_id']} was recorded before its decision")
        if approval["decision"] in {"approved", "auto_approved", "rejected"}:
            if decided_at < requested_at:
                errors.append(f"approval {approval['approval_id']} predates its request")
            if parse_time(approval["decided_at"]) > request_expires_at:
                errors.append(f"approval {approval['approval_id']} was decided after expiry")

    requirements = request["policy"]["requirements"]
    if len(approved_records) < requirements["minimum_approvals"]:
        errors.append("approval quorum is not satisfied")
    if requirements["distinct_approvers"]:
        actors = {
            (approval["decided_by"]["kind"], approval["decided_by"]["identifier"])
            for approval in approved_records
        }
        if len(actors) != len(approved_records):
            errors.append("approval policy requires distinct approvers")
    allowed_channels = set(requirements["allowed_channels"])
    signature_channels = set(requirements.get("signature_required_channels", []))
    if not signature_channels.issubset(allowed_channels):
        errors.append("signature-required channels must also be allowed channels")
    required_roles = set(requirements.get("required_roles", []))
    separation = requirements["separation_of_duties"]
    eligible_approvers = set(separation.get("eligible_approver_ids", []))
    excluded_actors = set(separation.get("excluded_actor_ids", []))
    excluded_keys = set(separation.get("excluded_key_ids", []))
    delegated_agent_ids = {
        hop["agent"]["identity"] for hop in proposal["delegation_chain"]
    }
    observed_signing_keys: set[str] = set()
    for approval in approved_records:
        approver_id = approval["decided_by"]["identifier"]
        if approval["channel"] not in allowed_channels:
            errors.append(f"approval channel {approval['channel']} is not allowed by policy")
        if requirements["human_only"] and approval["decided_by"]["kind"] != "human":
            errors.append("human-only policy contains a non-human approval")
        if not requirements["allow_auto_approval"] and approval["decision"] == "auto_approved":
            errors.append("policy forbids auto approval")
        actor_roles = set(approval["decided_by"].get("roles", []))
        missing_roles = sorted(required_roles - actor_roles)
        if missing_roles:
            errors.append(
                f"approval {approval['approval_id']} lacks required roles: "
                + ", ".join(missing_roles)
            )
        if approval["channel"] in signature_channels:
            if not approval.get("signatures"):
                errors.append(f"approval {approval['approval_id']} lacks a required signature")
        if separation["requester_must_not_approve"]:
            if approver_id == request["requested_by"]["identifier"]:
                errors.append("requester cannot approve its own request")
        if separation["agent_must_not_approve"] and approver_id in delegated_agent_ids:
            errors.append("delegated agent cannot approve its own action")
        if approver_id in excluded_actors:
            errors.append(f"approval actor {approver_id} is excluded by policy")
        if eligible_approvers and approver_id not in eligible_approvers:
            errors.append(f"approval actor {approver_id} is not eligible under policy")
        for signature in approval.get("signatures", []):
            key_id = signature["key_id"]
            if key_id in excluded_keys:
                errors.append(f"approval signing key {key_id} is excluded by policy")
            if separation["distinct_signing_keys"] and key_id in observed_signing_keys:
                errors.append("approval policy requires distinct signing keys")
            observed_signing_keys.add(key_id)

    approval_by_id = {approval["approval_id"]: approval for approval in approvals}
    if len(approval_by_id) != len(approvals):
        errors.append("approval records reuse approval_id")
    resolved_approval_ids: set[str] = set()
    resolution_ids: set[str] = set()
    for resolution in resolutions:
        resolution_id = resolution["resolution_id"]
        if resolution_id in resolution_ids:
            errors.append("resolution records reuse resolution_id")
        resolution_ids.add(resolution_id)
        approval = approval_by_id.get(resolution["approval_id"])
        if approval is None:
            errors.append(f"resolution {resolution_id} names an unknown approval")
            continue
        resolved_approval_ids.add(approval["approval_id"])
        if resolution["approval_record_hash"] != digest(approval):
            errors.append(f"resolution {resolution_id} approval_record_hash mismatch")
        for field in ("request_id", "proposal_id", "action_hash", "decision"):
            if resolution[field] != approval[field]:
                errors.append(f"resolution {resolution_id} {field} mismatch")
        if resolution["call_id"] != proposal["call_id"]:
            errors.append(f"resolution {resolution_id} call_id mismatch")
        emitted_at = parse_time(resolution["emitted_at"])
        last_attempt_at = parse_time(resolution["delivery"]["last_attempt_at"])
        if emitted_at < parse_time(approval["recorded_at"]):
            errors.append(f"resolution {resolution_id} predates its approval record")
        if last_attempt_at < emitted_at:
            errors.append(f"resolution {resolution_id} was delivered before it was emitted")
        if "acknowledged_at" in resolution["delivery"]:
            if parse_time(resolution["delivery"]["acknowledged_at"]) < last_attempt_at:
                errors.append(
                    f"resolution {resolution_id} was acknowledged before delivery"
                )
    missing_resolutions = set(approval_by_id) - resolved_approval_ids
    if missing_resolutions:
        errors.append("approval records lack durable resolution receipts")

    authority_by_id = {
        item["authority_snapshot_id"]: item for item in authority_snapshots
    }
    if len(authority_by_id) != len(authority_snapshots):
        errors.append("authority snapshots reuse authority_snapshot_id")
    for authority in authority_snapshots:
        authority_id = authority["authority_snapshot_id"]
        if authority["authority_digest"] != digest(authority["subjects"]):
            errors.append(f"authority snapshot {authority_id} digest mismatch")
        if authority["proposal_id"] != proposal["proposal_id"]:
            errors.append(f"authority snapshot {authority_id} points at another proposal")
        if authority["request_id"] != request["request_id"]:
            errors.append(f"authority snapshot {authority_id} points at another request")
        checked_at = parse_time(authority["checked_at"])
        if "valid_until" in authority:
            if parse_time(authority["valid_until"]) < checked_at:
                errors.append(f"authority snapshot {authority_id} expires before its check")
        if authority["status"] == "active":
            if any(subject["status"] != "active" for subject in authority["subjects"]):
                errors.append(
                    f"authority snapshot {authority_id} is active but contains inactive authority"
                )
        elif not any(
            subject["status"] == authority["status"]
            for subject in authority["subjects"]
        ):
            errors.append(
                f"authority snapshot {authority_id} status lacks a matching subject"
            )
        required_subjects = {"approver", "policy", "workspace", "dispatcher"}
        present_subjects = {subject["kind"] for subject in authority["subjects"]}
        if not required_subjects.issubset(present_subjects):
            errors.append(f"authority snapshot {authority_id} is incomplete")
        active_approvers = {
            subject["identifier"]
            for subject in authority["subjects"]
            if subject["kind"] == "approver" and subject["status"] == "active"
        }
        expected_approvers = {
            approval["decided_by"]["identifier"] for approval in approved_records
        }
        if authority["status"] == "active" and not expected_approvers.issubset(
            active_approvers
        ):
            errors.append(
                f"authority snapshot {authority_id} omits an approving identity"
            )
        matching_policy = [
            subject
            for subject in authority["subjects"]
            if subject["kind"] == "policy"
            and subject["identifier"] == request["policy"]["policy_id"]
            and subject["revision"] == request["policy"]["revision"]
        ]
        if not matching_policy:
            errors.append(
                f"authority snapshot {authority_id} does not bind the approved policy"
            )
        tenant_scope = f"tenant:{proposal['tenant']}"
        if not any(
            subject["kind"] == "workspace"
            and tenant_scope in subject.get("scopes", [])
            for subject in authority["subjects"]
        ):
            errors.append(
                f"authority snapshot {authority_id} does not bind the proposal tenant"
            )
        if not any(
            subject["kind"] == "dispatcher"
            and proposal["action_type"] in subject.get("scopes", [])
            for subject in authority["subjects"]
        ):
            errors.append(
                f"authority snapshot {authority_id} does not authorize the action type"
            )

    approval_ids = {approval["approval_id"] for approval in approved_records}
    for dispatch in dispatches:
        if dispatch["proposal_id"] != proposal["proposal_id"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} points at another proposal")
        if dispatch["request_id"] != request["request_id"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} points at another request")
        if not set(dispatch["approval_ids"]).issubset(approval_ids):
            errors.append(f"dispatch {dispatch['dispatch_id']} cites a non-approving record")
        expected_hashes = {
            effective_hashes[item]
            for item in dispatch["approval_ids"]
            if item in effective_hashes
        }
        if dispatch["action_hash"] not in expected_hashes:
            errors.append(f"dispatch {dispatch['dispatch_id']} action_hash is not approved")
        if dispatch["idempotency_key"] != proposal["idempotency_key"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} changed the idempotency key")
        if dispatch["attempt"] > dispatch["max_attempts"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} exceeds max_attempts")
        started_at = parse_time(dispatch["started_at"])
        authority = authority_by_id.get(dispatch["authority_snapshot_id"])
        if authority is None:
            errors.append(
                f"dispatch {dispatch['dispatch_id']} names an unknown authority snapshot"
            )
        else:
            checked_at = parse_time(authority["checked_at"])
            if authority["action_hash"] != dispatch["action_hash"]:
                errors.append(
                    f"dispatch {dispatch['dispatch_id']} authority action_hash mismatch"
                )
            if checked_at > started_at:
                errors.append(
                    f"dispatch {dispatch['dispatch_id']} started before authority check"
                )
            if "consumed_at" in request and checked_at < parse_time(request["consumed_at"]):
                errors.append(
                    f"dispatch {dispatch['dispatch_id']} authority check predates consumption"
                )
            if "valid_until" in authority and started_at > parse_time(authority["valid_until"]):
                errors.append(
                    f"dispatch {dispatch['dispatch_id']} used expired authority evidence"
                )
            if dispatch["status"] != "not_dispatched" and authority["status"] != "active":
                errors.append(
                    f"dispatch {dispatch['dispatch_id']} used inactive authority"
                )
            cited_approval_times = [
                parse_time(approval_by_id[item]["recorded_at"])
                for item in dispatch["approval_ids"]
                if item in approval_by_id
            ]
            if cited_approval_times and checked_at < max(cited_approval_times):
                errors.append(
                    f"dispatch {dispatch['dispatch_id']} authority check predates approval"
                )
        completed_at = (
            parse_time(dispatch["completed_at"])
            if dispatch.get("completed_at")
            else None
        )
        recorded_at = parse_time(dispatch["recorded_at"])
        if started_at > proposal_expires_at:
            errors.append(f"dispatch {dispatch['dispatch_id']} started after proposal expiry")
        if completed_at and completed_at < started_at:
            errors.append(f"dispatch {dispatch['dispatch_id']} completed before it started")
        if recorded_at < (completed_at or started_at):
            errors.append(f"dispatch {dispatch['dispatch_id']} was recorded too early")

    if request["status"] == "consumed":
        if request["decision_record_id"] not in approval_ids:
            errors.append("consumed request does not name an approving decision")
        if request["dispatch_id"] not in {item["dispatch_id"] for item in dispatches}:
            errors.append("consumed request does not name a known dispatch")
        consumed_at = parse_time(request["consumed_at"])
        if consumed_at < requested_at:
            errors.append("request was consumed before it was created")
        matching_dispatches = [
            item for item in dispatches if item["dispatch_id"] == request["dispatch_id"]
        ]
        if matching_dispatches and parse_time(matching_dispatches[0]["started_at"]) < consumed_at:
            errors.append("dispatch started before the request was consumed")

    expected_previous: str | None = None
    previous_recorded_at: datetime | None = None
    stream_ids: set[str] = set()
    for expected_sequence, event in enumerate(events, start=1):
        stream_ids.add(event["stream_id"])
        if event["sequence"] != expected_sequence:
            errors.append("audit sequence is not contiguous")
        if event["previous_event_hash"] != expected_previous:
            errors.append(f"audit event {event['event_id']} has a broken previous hash")
        unhashed = {key: value for key, value in event.items() if key != "event_hash"}
        expected_event_hash = digest(unhashed)
        if event["event_hash"] != expected_event_hash:
            errors.append(f"audit event {event['event_id']} hash mismatch")
        if event["proposal_id"] != proposal["proposal_id"]:
            errors.append(f"audit event {event['event_id']} points at another proposal")
        if event["tenant"] != proposal["tenant"]:
            errors.append(f"audit event {event['event_id']} points at another tenant")
        occurred_at = parse_time(event["occurred_at"])
        recorded_at = parse_time(event["recorded_at"])
        if recorded_at < occurred_at:
            errors.append(f"audit event {event['event_id']} was recorded before it occurred")
        if previous_recorded_at and recorded_at < previous_recorded_at:
            errors.append("audit event recording times are not monotonic")
        expected_previous = event["event_hash"]
        previous_recorded_at = recorded_at
    if len(stream_ids) != 1:
        errors.append("audit events span more than one stream")

    if audit_snapshot["stream_id"] not in stream_ids:
        errors.append("audit snapshot points at another stream")
    if audit_snapshot["entry_count"] != len(events):
        errors.append("audit snapshot entry_count is incomplete")
    if audit_snapshot["first_sequence"] != events[0]["sequence"]:
        errors.append("audit snapshot first_sequence mismatch")
    if audit_snapshot["last_sequence"] != events[-1]["sequence"]:
        errors.append("audit snapshot last_sequence mismatch")
    if audit_snapshot["events_digest"] != digest(events):
        errors.append("audit snapshot events_digest mismatch")
    if audit_snapshot["root_event_hash"] != events[-1]["event_hash"]:
        errors.append("audit snapshot root_event_hash mismatch")
    if parse_time(audit_snapshot["captured_at"]) < parse_time(events[-1]["recorded_at"]):
        errors.append("audit snapshot predates its final event")

    event_types = {event["event_type"] for event in events}
    required_event_types = {
        "proposal.received",
        "validation.passed",
        "approval.requested",
        "review.presented",
        "approval.decided",
        "resolution.emitted",
        "authority.checked",
        "audit.snapshotted",
    }
    missing_event_types = sorted(required_event_types - event_types)
    if missing_event_types:
        errors.append(
            "audit stream lacks required lifecycle events: "
            + ", ".join(missing_event_types)
        )
    if not event_types.intersection(
        {
            "dispatch.succeeded",
            "dispatch.failed",
            "dispatch.outcome_unknown",
            "dispatch.reconciled",
            "dispatch.not_dispatched",
        }
    ):
        errors.append("audit stream has no terminal dispatch event")
    expected_audit_references = {
        "validation_id": {item["validation_id"] for item in validations},
        "review_snapshot_id": {item["snapshot_id"] for item in review_snapshots},
        "request_id": {request["request_id"]},
        "approval_id": set(approval_by_id),
        "resolution_id": {item["resolution_id"] for item in resolutions},
        "authority_snapshot_id": set(authority_by_id),
        "dispatch_id": {item["dispatch_id"] for item in dispatches},
        "audit_snapshot_id": {audit_snapshot["snapshot_id"]},
    }
    observed_audit_references: dict[str, set[str]] = {
        key: set() for key in expected_audit_references
    }
    for event in events:
        for key, value in event["references"].items():
            if key in observed_audit_references:
                observed_audit_references[key].add(value)
    for key, expected in expected_audit_references.items():
        if not expected.issubset(observed_audit_references[key]):
            errors.append(f"audit stream omits a {key} lifecycle reference")
    return errors


def n8n_reference_errors() -> list[str]:
    errors: list[str] = []
    workflow = load("examples/n8n-approval-workflow.json")
    nodes = workflow.get("nodes", [])
    names = [node.get("name") for node in nodes]
    if len(names) != len(set(names)):
        errors.append("n8n workflow has duplicate node names")
    by_name = {node["name"]: node for node in nodes}
    required_nodes = {
        "Validate full JSON Schema",
        "Persist validation record",
        "Append validation passed event",
        "Create durable approval request",
        "Append approval requested event",
        "Persist review snapshot",
        "Append review presented event",
        "Wait for signed callback",
        "Resolve callback atomically",
        "Deliver durable resolution",
        "Append resolution audit event",
        "Consume approval once",
        "Revalidate dispatch authority",
        "Append authority audit event",
        "Authority active?",
        "Dispatch exactly once",
        "Append dispatch audit event",
        "Append terminal refusal event",
        "Export complete audit snapshot",
    }
    missing = sorted(required_nodes - set(by_name))
    if missing:
        errors.append(f"n8n workflow is missing required nodes: {', '.join(missing)}")
    for node in nodes:
        if node.get("type") in {"n8n-nodes-base.code", "n8n-nodes-base.function"}:
            errors.append("n8n workflow must not implement trust-boundary logic in a Code node")
    wait = by_name.get("Wait for signed callback", {})
    parameters = wait.get("parameters", {})
    if parameters.get("resume") != "webhook" or parameters.get("limitWaitTime") is not True:
        errors.append("n8n wait node must use a bounded webhook resume")
    connections = workflow.get("connections", {})
    adjacency: dict[str, set[str]] = {name: set() for name in by_name}
    for source, outputs in connections.items():
        if source not in by_name:
            errors.append(f"n8n connection has unknown source node {source}")
        for channel in outputs.values():
            for branch in channel:
                for edge in branch:
                    if edge.get("node") not in by_name:
                        errors.append(f"n8n connection has unknown target node {edge.get('node')}")
                    elif source in adjacency:
                        adjacency[source].add(edge["node"])
    reachable: set[str] = set()
    pending = ["Webhook: ProposedAction in"]
    while pending:
        current = pending.pop()
        if current in reachable or current not in adjacency:
            continue
        reachable.add(current)
        pending.extend(adjacency[current] - reachable)
    unreachable = sorted(required_nodes - reachable)
    if unreachable:
        errors.append(f"n8n required nodes are unreachable: {', '.join(unreachable)}")
    rendered = json.dumps(workflow, sort_keys=True)
    if "'/v1/" in rendered or '"/v1/' in rendered:
        errors.append("n8n workflow still references a v1 contract endpoint")
    for endpoint in (
        "/v2/validate",
        "/v2/validations",
        "/v2/requests",
        "/v2/review-snapshots",
        "/v2/resolutions",
        "/v2/authority-snapshots",
        "/v2/events",
        "/v2/snapshots",
    ):
        if endpoint not in rendered:
            errors.append(f"n8n workflow does not reference {endpoint}")
    for variable in (
        "APPROVAL_VALIDATOR_URL",
        "APPROVAL_GATE_URL",
        "APPROVAL_AUDIT_URL",
        "APPROVAL_DISPATCH_URL",
        "APPROVAL_POLICY_ID",
        "TG_APPROVER_CHAT_ID",
    ):
        if variable not in rendered:
            errors.append(f"n8n workflow does not reference {variable}")
    return errors


def validate_repository() -> list[str]:
    failures: list[str] = []
    schemas, registry = schema_catalog()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    for path, schema in schemas.items():
        identifier = schema["$id"]
        if f"/v{version}/" not in identifier:
            failures.append(f"{path}: $id is not pinned to v{version}")
        if "/main/" in identifier:
            failures.append(f"{path}: $id points at mutable main")

    for corpus_path in ("tests/conformance.json", "tests/adversarial.json"):
        corpus = load(corpus_path)
        for vector in corpus["positive"]:
            validator = validator_for(vector["schema"], schemas, registry)
            instance = load(vector["instance"])
            instances = instance if vector.get("items") else [instance]
            vector_has_schema_errors = False
            for index, item in enumerate(instances):
                item_errors = sorted(
                    validator.iter_errors(item), key=lambda error: list(error.path)
                )
                vector_has_schema_errors = vector_has_schema_errors or bool(item_errors)
                for error in item_errors:
                    location = "/".join(str(part) for part in error.path) or "<root>"
                    failures.append(
                        f"{corpus_path} positive {vector['name']}[{index}] "
                        f"{location}: {error.message}"
                    )
            if vector.get("semantic") and not vector_has_schema_errors:
                failures.extend(
                    f"{corpus_path} positive {vector['name']}: {error}"
                    for error in semantic_errors(instance)
                )

        for vector in corpus["negative"]:
            validator = validator_for(vector["schema"], schemas, registry)
            instance = apply_operations(load(vector["instance"]), vector["operations"])
            schema_errors = list(validator.iter_errors(instance))
            if vector["expect"] == "schema":
                if not schema_errors:
                    failures.append(
                        f"{corpus_path} negative {vector['name']}: "
                        "unexpectedly passed schema validation"
                    )
                continue
            if schema_errors:
                failures.append(
                    f"{corpus_path} negative {vector['name']}: "
                    "failed schema before semantic check"
                )
                continue
            if not semantic_errors(instance):
                failures.append(
                    f"{corpus_path} negative {vector['name']}: "
                    "unexpectedly passed semantic validation"
                )
    failures.extend(canonicalization_errors())
    failures.extend(f"n8n reference: {error}" for error in n8n_reference_errors())
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    failures = validate_repository()
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    if not args.quiet:
        print("All schemas, examples, negative vectors, and lifecycle invariants passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
