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


def semantic_errors(envelope: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    proposal = envelope["proposal"]
    request = envelope["request"]
    approvals = envelope["approvals"]
    dispatches = envelope["dispatches"]
    events = envelope["audit_events"]

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
    for approval in approved_records:
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

    approval_ids = {approval["approval_id"] for approval in approved_records}
    for dispatch in dispatches:
        if dispatch["proposal_id"] != proposal["proposal_id"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} points at another proposal")
        if dispatch["request_id"] != request["request_id"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} points at another request")
        if not set(dispatch["approval_ids"]).issubset(approval_ids):
            errors.append(f"dispatch {dispatch['dispatch_id']} cites a non-approving record")
        expected_hashes = {effective_hashes[item] for item in dispatch["approval_ids"] if item in effective_hashes}
        if dispatch["action_hash"] not in expected_hashes:
            errors.append(f"dispatch {dispatch['dispatch_id']} action_hash is not approved")
        if dispatch["idempotency_key"] != proposal["idempotency_key"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} changed the idempotency key")
        if dispatch["attempt"] > dispatch["max_attempts"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} exceeds max_attempts")
        started_at = parse_time(dispatch["started_at"])
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

    event_types = {event["event_type"] for event in events}
    if "proposal.received" not in event_types:
        errors.append("audit stream has no proposal.received event")
    if "approval.decided" not in event_types:
        errors.append("audit stream has no approval.decided event")
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
        "Create durable approval request",
        "Wait for signed callback",
        "Resolve callback atomically",
        "Consume approval once",
        "Dispatch exactly once",
        "Append dispatch audit event",
        "Append terminal refusal event",
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
    for source, outputs in connections.items():
        if source not in by_name:
            errors.append(f"n8n connection has unknown source node {source}")
        for channel in outputs.values():
            for branch in channel:
                for edge in branch:
                    if edge.get("node") not in by_name:
                        errors.append(f"n8n connection has unknown target node {edge.get('node')}")
    rendered = json.dumps(workflow, sort_keys=True)
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

    corpus = load("tests/conformance.json")
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
                failures.append(f"positive {vector['name']}[{index}] {location}: {error.message}")
        if vector.get("semantic") and not vector_has_schema_errors:
            failures.extend(
                f"positive {vector['name']}: {error}"
                for error in semantic_errors(instance)
            )

    for vector in corpus["negative"]:
        validator = validator_for(vector["schema"], schemas, registry)
        instance = apply_operations(load(vector["instance"]), vector["operations"])
        schema_errors = list(validator.iter_errors(instance))
        if vector["expect"] == "schema":
            if not schema_errors:
                failures.append(f"negative {vector['name']}: unexpectedly passed schema validation")
            continue
        if schema_errors:
            failures.append(f"negative {vector['name']}: failed schema before semantic check")
            continue
        if not semantic_errors(instance):
            failures.append(f"negative {vector['name']}: unexpectedly passed semantic validation")
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
