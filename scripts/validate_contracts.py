#!/usr/bin/env python3
"""Validate schemas, examples, negative vectors, and cross-record invariants."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
from copy import deepcopy
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]


def load(path: str | Path) -> Any:
    target = Path(path)
    if not target.is_absolute():
        target = ROOT / target
    return strict_json_loads(target.read_text(encoding="utf-8"))


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def decode_base64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if encode_base64url(decoded) != value:
        raise ValueError("non-canonical base64url encoding")
    return decoded


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON property: {key}")
        value[key] = item
    return value


def strict_json_loads(value: str) -> Any:
    def reject_constant(_: str) -> Any:
        raise ValueError("non-finite JSON number")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number

    return json.loads(
        value, object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=reject_constant, parse_float=finite_float,
    )


def webauthn_signature_errors(approval: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    unsigned_approval = {
        key: value for key, value in approval.items() if key != "signatures"
    }
    signed_object_hash = digest(unsigned_approval)
    signatures = approval.get("signatures", [])
    webauthn_signatures = [
        signature
        for signature in signatures
        if signature.get("algorithm") == "webauthn-es256"
    ]
    if webauthn_signatures:
        if approval.get("channel") != "web":
            errors.append("WebAuthn approval must use the web channel")
        actor = approval.get("decided_by", {})
        authentication = actor.get("authentication", {})
        if actor.get("kind") != "human" or not authentication.get("human_present"):
            errors.append("WebAuthn approval must identify a present human")
        if authentication.get("method") != "authenticated_session":
            errors.append("WebAuthn approval must come from an authenticated session")

    for signature in webauthn_signatures:
        key_id = signature["key_id"]
        assertion = signature["webauthn"]
        prefix = f"WebAuthn signature {key_id}"
        if signature["signed_object_hash"] != signed_object_hash:
            errors.append(f"{prefix} does not bind the unsigned approval record")
        if key_id != assertion["credential_id"]:
            errors.append(f"{prefix} key_id does not match credential_id")

        registration_binding = {
            "credential_id": assertion["credential_id"],
            "credential_public_key": assertion["credential_public_key"],
            "rp_id": assertion["rp_id"],
            "actor": approval.get("decided_by", {}).get("identifier"),
            "previous_sign_count": assertion["previous_sign_count"],
        }
        if assertion["registration_evidence"]["digest"] != digest(
            registration_binding
        ):
            errors.append(
                f"{prefix} registration evidence does not bind the credential"
            )

        try:
            client_data_json = decode_base64url(assertion["client_data_json"])
            authenticator_data = decode_base64url(assertion["authenticator_data"])
            public_key_der = decode_base64url(assertion["credential_public_key"])
            signature_value = decode_base64url(signature["value"])
        except (binascii.Error, ValueError, TypeError) as error:
            errors.append(f"{prefix} contains invalid base64url: {error}")
            continue

        try:
            client_data = strict_json_loads(client_data_json.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            errors.append(f"{prefix} contains invalid clientDataJSON: {error}")
            continue
        if not isinstance(client_data, dict):
            errors.append(f"{prefix} clientDataJSON is not an object")
            continue

        expected_challenge = encode_base64url(
            bytes.fromhex(signed_object_hash.removeprefix("sha256:"))
        )
        if client_data.get("type") != "webauthn.get":
            errors.append(f"{prefix} clientDataJSON has the wrong type")
        if client_data.get("challenge") != expected_challenge:
            errors.append(f"{prefix} challenge does not bind the approval record")
        if client_data.get("origin") != assertion["origin"]:
            errors.append(f"{prefix} clientDataJSON origin mismatch")
        if client_data.get("crossOrigin", False) is not False:
            errors.append(f"{prefix} cross-origin assertion is not allowed")
        if "topOrigin" in client_data:
            errors.append(f"{prefix} topOrigin is not allowed by this profile")

        try:
            origin = urlparse(assertion["origin"])
            origin_host = (origin.hostname or "").rstrip(".").lower()
            _ = origin.port
        except ValueError as error:
            errors.append(f"{prefix} origin is invalid: {error}")
            origin = None
            origin_host = ""
        rp_id = assertion["rp_id"].rstrip(".").lower()
        if origin is None or origin.scheme != "https" or not origin_host:
            errors.append(f"{prefix} origin must be an HTTPS origin")
        elif (
            origin.path
            or origin.params
            or origin.query
            or origin.fragment
            or origin.username
            or origin.password
        ):
            errors.append(f"{prefix} origin must not contain extra URL components")
        if origin_host != rp_id and not origin_host.endswith("." + rp_id):
            errors.append(f"{prefix} origin is outside the RP ID scope")

        if len(authenticator_data) < 37:
            errors.append(f"{prefix} authenticator data is shorter than 37 bytes")
            continue
        if len(authenticator_data) != 37:
            errors.append(
                f"{prefix} authenticator data contains unsupported extension data"
            )
        if authenticator_data[:32] != hashlib.sha256(rp_id.encode("utf-8")).digest():
            errors.append(f"{prefix} RP ID hash mismatch")
        flags = authenticator_data[32]
        if not flags & 0x01:
            errors.append(f"{prefix} lacks the user-presence flag")
        if not flags & 0x04:
            errors.append(f"{prefix} lacks the user-verification flag")
        if flags & 0x40:
            errors.append(f"{prefix} assertion unexpectedly contains attested data")
        if flags & 0x80:
            errors.append(f"{prefix} assertion extensions are not supported")
        if flags & 0x22:
            errors.append(f"{prefix} sets a reserved authenticator flag")
        if flags & 0x10 and not flags & 0x08:
            errors.append(f"{prefix} backup state is set without backup eligibility")
        parsed_sign_count = int.from_bytes(authenticator_data[33:37], "big")
        if parsed_sign_count != assertion["sign_count"]:
            errors.append(f"{prefix} sign_count does not match authenticator data")
        previous_sign_count = assertion["previous_sign_count"]
        if parsed_sign_count or previous_sign_count:
            if parsed_sign_count <= previous_sign_count:
                errors.append(f"{prefix} sign counter did not advance")

        try:
            public_key = serialization.load_der_public_key(public_key_der)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                errors.append(f"{prefix} public key is not an EC key")
                continue
            if not isinstance(public_key.curve, ec.SECP256R1):
                errors.append(f"{prefix} public key is not P-256")
                continue
            signed_data = authenticator_data + hashlib.sha256(client_data_json).digest()
            public_key.verify(
                signature_value,
                signed_data,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError) as error:
            errors.append(f"{prefix} cryptographic verification failed: {error}")
    return errors


@lru_cache(maxsize=1)
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


def _array_index(token: str, length: int, *, add: bool = False) -> int:
    if add and token == "-":
        return length
    if not re.fullmatch(r"0|[1-9][0-9]*", token):
        raise ValueError("invalid JSON Pointer array index")
    index = int(token)
    if index > length or (index == length and not add):
        raise ValueError("JSON Pointer array index is out of bounds")
    return index


def _pointer_parent(document: Any, path: str) -> tuple[Any, str]:
    if not path.startswith("/"):
        raise ValueError(f"JSON Pointer must start with '/': {path}")
    if re.search(r"~(?![01])", path):
        raise ValueError("invalid JSON Pointer escape")
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in path[1:].split("/")]
    current = document
    for token in tokens[:-1]:
        if isinstance(current, list):
            current = current[_array_index(token, len(current))]
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise ValueError("JSON Pointer parent does not exist")
    return current, tokens[-1]


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_json_equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    return left == right


def apply_operations(document: Any, operations: list[dict[str, Any]]) -> Any:
    result = deepcopy(document)
    for operation in operations:
        op = operation["op"]
        if op not in {"add", "remove", "replace", "test"}:
            raise ValueError(f"unsupported operation: {op}")
        if operation["path"] == "":
            if op == "remove":
                raise ValueError("removing the document root is not supported")
            if op == "test":
                if not _json_equal(result, operation["value"]):
                    raise ValueError("test operation failed at root")
            else:
                result = deepcopy(operation["value"])
            continue
        parent, key = _pointer_parent(result, operation["path"])
        if not isinstance(parent, (dict, list)):
            raise ValueError("JSON Pointer parent is not a container")
        if isinstance(parent, list):
            index = _array_index(key, len(parent), add=op == "add")
        elif op != "add" and key not in parent:
            raise ValueError("JSON Pointer target does not exist")
        if op == "remove":
            if isinstance(parent, list):
                parent.pop(index)
            else:
                del parent[key]
        elif op in {"add", "replace"}:
            value = deepcopy(operation["value"])
            if isinstance(parent, list):
                if op == "add":
                    parent.insert(index, value)
                else:
                    parent[index] = value
            else:
                parent[key] = value
        elif op == "test":
            actual = parent[index] if isinstance(parent, list) else parent[key]
            if not _json_equal(actual, operation["value"]):
                raise ValueError(f"test operation failed at {operation['path']}")
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


def payload_errors(action: dict[str, Any], schema_files: dict[str, Path] | None = None) -> list[str]:
    """Use locally supplied released bytes; never resolve an agent-selected URL."""
    if "payload" not in action:
        return ["effective action has no payload"]
    files = {
        load(path)["$id"]: path
        for path in (ROOT / "schemas" / "actions").glob("*.json")
    }
    files.update(schema_files or {})
    binding = action["payload_schema"]
    path = files.get(binding["id"])
    if path is None:
        return ["payload schema is not available in the trusted local catalog"]
    try:
        schema = load(path)
        if schema["$id"] != binding["id"]:
            return ["payload schema ID mismatch"]
        if f"/v{binding['version']}/" not in binding["id"]:
            return ["payload schema version mismatch"]
        expected_type = schema.get("x-action-type", path.name.removesuffix(".schema.json"))
        if expected_type != action["action_type"]:
            return ["payload schema action type mismatch"]
        file_hash = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if binding["digest"] != file_hash:
            return ["payload schema digest mismatch"]
        Draft202012Validator.check_schema(schema)
        _, registry = schema_catalog()
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        if list(validator.iter_errors(action["payload"])):
            return ["effective payload fails its action schema"]
    except Exception:
        return ["payload schema could not be validated from the trusted catalog"]
    return []


def validate_envelope(envelope: Any, schema_files: dict[str, Path] | None = None) -> list[str]:
    schemas, registry = schema_catalog()
    validator = validator_for("schemas/approval-envelope.schema.json", schemas, registry)
    if list(validator.iter_errors(envelope)):
        return ["envelope fails structural validation"]
    try:
        return semantic_errors(envelope, schema_files)
    except (ValueError, TypeError, KeyError, IndexError, rfc8785.CanonicalizationError):
        return ["envelope contains invalid semantic input"]


def dispatch_history_errors(dispatches: list[dict[str, Any]], request: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    previous: dict[str, Any] | None = None
    for record in dispatches:
        if record["retry_allowed"] and record["attempt"] >= record["max_attempts"]:
            errors.append("dispatch at attempt ceiling cannot allow retry")
        reconciled = record["status"].startswith("reconciled_")
        if previous is None:
            if reconciled or record["attempt"] != 1 or "previous_dispatch_id" in record:
                errors.append("dispatch history must start with an initial attempt")
            if request["status"] == "consumed" and record["dispatch_id"] != request["dispatch_id"]:
                errors.append("dispatch history does not start at the consumed dispatch")
        else:
            if record.get("previous_dispatch_id") != previous["dispatch_id"]:
                errors.append("dispatch history previous_dispatch_id linkage is broken")
            for field in ("action_hash", "idempotency_key", "max_attempts"):
                if record[field] != previous[field]:
                    errors.append(f"dispatch history changes {field}")
            if set(record["approval_ids"]) != set(previous["approval_ids"]):
                errors.append("dispatch history changes the consumed approval set")
            if parse_time(record["started_at"]) < parse_time(previous["recorded_at"]):
                errors.append("dispatch history starts before prior outcome was recorded")
            if reconciled:
                if previous["status"] != "outcome_unknown" or record["attempt"] != previous["attempt"]:
                    errors.append("reconciliation must resolve the preceding unknown attempt")
                if previous.get("reconciliation") and record["reconciliation"]["lookup_key_hash"] != previous["reconciliation"]["lookup_key_hash"]:
                    errors.append("reconciliation changed its lookup identity")
                if parse_time(record["reconciliation"]["checked_at"]) < parse_time(previous["recorded_at"]):
                    errors.append("reconciliation evidence predates the unknown outcome")
                if parse_time(record["reconciliation"]["checked_at"]) > parse_time(record["recorded_at"]):
                    errors.append("reconciliation was recorded before its evidence")
            else:
                if previous["status"] not in {"failed", "reconciled_not_applied"} or not previous["retry_allowed"]:
                    errors.append("retry requires authoritative failure or reconciled non-application")
                if record["attempt"] != previous["attempt"] + 1:
                    errors.append("retry attempt numbers must be contiguous")
        previous = record
    return errors


def audit_binding_errors(envelope: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    request = envelope["request"]
    records = {
        "validation_id": {x["validation_id"]: x for x in envelope["validations"]},
        "review_snapshot_id": {x["snapshot_id"]: x for x in envelope["review_snapshots"]},
        "request_id": {request["request_id"]: request},
        "approval_id": {x["approval_id"]: x for x in envelope["approvals"]},
        "resolution_id": {x["resolution_id"]: x for x in envelope["resolutions"]},
        "authority_snapshot_id": {x["authority_snapshot_id"]: x for x in envelope["authority_snapshots"]},
        "dispatch_id": {x["dispatch_id"]: x for x in envelope["dispatches"]},
        "audit_snapshot_id": {envelope["audit_snapshot"]["snapshot_id"]: envelope["audit_snapshot"]},
        "policy_evaluation_id": {request["policy"]["evaluation_id"]: request["policy"]},
    }
    witness_types = {
        "validation_id": {"validation.passed", "validation.rejected"},
        "review_snapshot_id": {"review.presented"},
        "request_id": {"approval.requested"},
        "approval_id": {"approval.decided"},
        "resolution_id": {"resolution.emitted"},
        "authority_snapshot_id": {"authority.checked"},
        "dispatch_id": {"dispatch.not_dispatched", "dispatch.succeeded", "dispatch.failed", "dispatch.outcome_unknown", "dispatch.reconciled"},
        "audit_snapshot_id": {"audit.snapshotted"},
    }
    witnessed: dict[str, set[str]] = {key: set() for key in witness_types}
    event_ids: set[str] = set()
    for event in envelope["audit_events"]:
        if event["event_id"] in event_ids:
            errors.append("audit events reuse event_id")
        event_ids.add(event["event_id"])
        refs = event["references"]
        event_type = event["event_type"]
        for key, value in refs.items():
            if value not in records[key]:
                errors.append(f"audit event references unknown {key}")
                continue
            if event_type in witness_types.get(key, set()):
                witnessed[key].add(value)
        primary_keys = [key for key, types in witness_types.items() if event_type in types]
        for key in primary_keys:
            if key not in refs:
                errors.append(f"audit {event_type} lacks its {key} witness")
        detail = event["detail"]
        primary = next((records[key].get(refs.get(key)) for key in primary_keys if records[key].get(refs.get(key))), None)
        if primary is None:
            continue
        for key in ("action_hash", "payload_hash", "decision", "attempt"):
            if key in detail and key in primary and detail[key] != primary[key]:
                errors.append(f"audit {event_type} {key} disagrees with its record")
        for key in ("approval_id", "request_id", "proposal_id"):
            if key in refs and key in primary and refs[key] != primary[key]:
                errors.append(f"audit {event_type} {key} disagrees with its record")
        if "policy_revision" in detail and detail["policy_revision"] != request["policy"]["revision"]:
            errors.append("audit policy revision mismatch")
        if event_type == "validation.passed" and primary["outcome"] != "passed":
            errors.append("audit validation outcome disagrees with validation record")
        if event_type == "validation.rejected" and primary["outcome"] == "passed":
            errors.append("audit validation outcome disagrees with validation record")
        if event_type == "review.presented" and "review_content_hash" in detail and detail["review_content_hash"] != primary["content_hash"]:
            errors.append("audit review content hash disagrees with snapshot")
        if event_type == "approval.decided":
            if event["actor"]["kind"] != primary["decided_by"]["kind"] or event["actor"]["identifier"] != primary["decided_by"]["identifier"]:
                errors.append("audit decision actor disagrees with approval")
            if parse_time(event["occurred_at"]) != parse_time(primary["decided_at"]):
                errors.append("audit decision time disagrees with approval")
        if event_type.startswith("dispatch."):
            expected = {
                "succeeded": "dispatch.succeeded", "failed": "dispatch.failed",
                "not_dispatched": "dispatch.not_dispatched", "outcome_unknown": "dispatch.outcome_unknown",
                "reconciled_succeeded": "dispatch.reconciled", "reconciled_not_applied": "dispatch.reconciled",
            }[primary["status"]]
            if event_type != expected:
                errors.append("audit dispatch outcome disagrees with dispatch record")
            if "provider_result_hash" in detail and detail["provider_result_hash"] != primary.get("provider", {}).get("result_hash"):
                errors.append("audit provider result hash disagrees with dispatch record")
        witness_time = {
            "validation.passed": "validated_at", "validation.rejected": "validated_at",
            "review.presented": "rendered_at", "approval.requested": "requested_at",
            "resolution.emitted": "emitted_at", "authority.checked": "checked_at",
            "dispatch.succeeded": "completed_at", "dispatch.failed": "completed_at",
            "dispatch.outcome_unknown": "completed_at", "dispatch.not_dispatched": "completed_at",
            "dispatch.reconciled": "completed_at", "audit.snapshotted": "captured_at",
        }.get(event_type)
        if witness_time and parse_time(event["occurred_at"]) != parse_time(primary[witness_time]):
            errors.append("audit witness time disagrees with its record")
    for key, witnesses in witnessed.items():
        if set(records[key]) - witnesses:
            errors.append(f"audit stream lacks typed witnesses for {key}")
    return errors


def policy_outcome_errors(
    request: dict[str, Any], approvals: list[dict[str, Any]], dispatches: list[dict[str, Any]]
) -> list[str]:
    """Only an explicit, closed policy outcome may select an approval path."""
    errors: list[str] = []
    outcome = request["policy"].get("outcome")
    auto_approvals = [item for item in approvals if item["decision"] == "auto_approved"]
    if auto_approvals and outcome != "auto_approve":
        errors.append("auto approval requires an explicit auto_approve policy outcome")
    if outcome == "deny":
        if request["status"] != "failed" or request.get("terminal_reason") != "policy_failed":
            errors.append("denied policy outcome must end the request as policy_failed")
        if any(item["decision"] in {"approved", "auto_approved"} for item in approvals):
            errors.append("denied policy outcome cannot carry an approving decision")
        if any(item["status"] != "not_dispatched" for item in dispatches):
            errors.append("denied policy outcome cannot invoke a provider")
    return errors


def semantic_errors(envelope: dict[str, Any], schema_files: dict[str, Path] | None = None) -> list[str]:
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

    errors.extend(payload_errors(proposal, schema_files))
    for records in (validations, review_snapshots, approvals, resolutions, authority_snapshots, dispatches):
        if any(record["proposal_id"] != proposal["proposal_id"] for record in records):
            errors.append("lifecycle record points at another proposal")
    if request["status"] == "pending":
        errors.append("complete envelope cannot contain a pending request")
    invocation_statuses = {"succeeded", "failed", "outcome_unknown"}
    invokes_provider = any(item["status"] in invocation_statuses for item in dispatches)
    if invokes_provider and request["status"] != "consumed":
        errors.append("provider invocation requires a consumed request")
    if request["status"] in {"rejected", "expired", "cancelled", "failed"} and invokes_provider:
        errors.append("refused request cannot invoke a provider")

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
                key: snapshot["content"]["arguments"][key]
                for key in ("from", "to", "cc")
                if key in snapshot["content"]["arguments"]
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
        errors.extend(webauthn_signature_errors(approval))
        if approval["proposal_id"] != proposal["proposal_id"]:
            errors.append(f"approval {approval['approval_id']} points at another proposal")
        if approval["request_id"] != request["request_id"]:
            errors.append(f"approval {approval['approval_id']} points at another request")
        operations = approval.get("modifications", [])
        if any(op["path"] != "/payload" and not op["path"].startswith("/payload/") for op in operations):
            errors.append("approval modifications must remain inside payload")
            continue
        try:
            effective_action = apply_operations(proposal, operations)
        except (ValueError, TypeError, KeyError, IndexError):
            errors.append(f"approval {approval['approval_id']} has invalid JSON Patch")
            continue
        schemas, registry = schema_catalog()
        effective_validator = validator_for("schemas/proposed-action.schema.json", schemas, registry)
        if list(effective_validator.iter_errors(effective_action)):
            errors.append(f"approval {approval['approval_id']} effective action fails proposal schema")
            errors.extend(payload_errors(effective_action, schema_files))
            continue
        errors.extend(payload_errors(effective_action, schema_files))
        if approval["policy_evaluation_id"] != request["policy"]["evaluation_id"]:
            errors.append(f"approval {approval['approval_id']} policy evaluation mismatch")
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
            if parse_time(approval["decided_at"]) >= request_expires_at:
                errors.append(f"approval {approval['approval_id']} was decided after expiry")

    requirements = request["policy"]["requirements"]
    errors.extend(policy_outcome_errors(request, approvals, dispatches))
    if request["status"] in {"approved", "consumed"} and len(approved_records) < requirements["minimum_approvals"]:
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
        if approval["approval_id"] in resolved_approval_ids:
            errors.append("approval has more than one terminal resolution receipt")
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
    dispatch_by_id = {item["dispatch_id"]: item for item in dispatches}
    if len(dispatch_by_id) != len(dispatches):
        errors.append("dispatch records reuse dispatch_id")
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
        if dispatch["status"] == "not_dispatched":
            if dispatch["action_hash"] not in set(effective_hashes.values()) | {initial_action_hash}:
                errors.append("refusal dispatch action_hash does not match lifecycle")
        else:
            if expected_hashes != {dispatch["action_hash"]}:
                errors.append(f"dispatch {dispatch['dispatch_id']} mixes or lacks approved action hashes")
            cited = [approval_by_id[item] for item in dispatch["approval_ids"] if item in approval_ids]
            if len(cited) < requirements["minimum_approvals"]:
                errors.append(f"dispatch {dispatch['dispatch_id']} approval quorum is not satisfied")
        if dispatch["idempotency_key"] != proposal["idempotency_key"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} changed the idempotency key")
        if dispatch["attempt"] > dispatch["max_attempts"]:
            errors.append(f"dispatch {dispatch['dispatch_id']} exceeds max_attempts")
        started_at = parse_time(dispatch["started_at"])
        authority = authority_by_id.get(dispatch.get("authority_snapshot_id"))
        if authority is None:
            if dispatch["status"] in invocation_statuses or "authority_snapshot_id" in dispatch:
                errors.append(f"dispatch {dispatch['dispatch_id']} names an unknown authority snapshot")
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
            if dispatch["status"] in invocation_statuses and started_at >= parse_time(authority["valid_until"]):
                errors.append(
                    f"dispatch {dispatch['dispatch_id']} used expired authority evidence"
                )
            if dispatch["status"] in invocation_statuses and authority["status"] != "active":
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
        if dispatch["status"] in invocation_statuses and started_at >= min(proposal_expires_at, request_expires_at):
            errors.append(f"dispatch {dispatch['dispatch_id']} started after proposal expiry")
        if completed_at and completed_at < started_at:
            errors.append(f"dispatch {dispatch['dispatch_id']} completed before it started")
        if recorded_at < (completed_at or started_at):
            errors.append(f"dispatch {dispatch['dispatch_id']} was recorded too early")

    terminal_at = parse_time(request["terminal_at"]) if "terminal_at" in request else None
    decision_record = approval_by_id.get(request.get("decision_record_id"))
    if terminal_at is not None:
        if terminal_at < requested_at:
            errors.append("request terminal state predates its request")
        if decision_record and terminal_at < parse_time(decision_record["recorded_at"]):
            errors.append("request terminal state predates its decision record")
    if request["status"] == "approved" and (not decision_record or decision_record["decision"] not in {"approved", "auto_approved"}):
        errors.append("approved request lacks an approving decision")
    if request["status"] == "rejected" and (not decision_record or decision_record["decision"] != "rejected"):
        errors.append("rejected request lacks a rejecting decision")
    if request["status"] == "expired" and terminal_at and terminal_at < request_expires_at:
        errors.append("expired request terminated before its expiry")
    if request["status"] == "consumed":
        if request["decision_record_id"] not in approval_ids:
            errors.append("consumed request does not name an approving decision")
        if request["dispatch_id"] not in {item["dispatch_id"] for item in dispatches}:
            errors.append("consumed request does not name a known dispatch")
        consumed_at = parse_time(request["consumed_at"])
        if consumed_at < requested_at:
            errors.append("request was consumed before it was created")
        if consumed_at >= request_expires_at:
            errors.append("request was consumed at or after expiry")
        if terminal_at and consumed_at < terminal_at:
            errors.append("request was consumed before its terminal decision")
        if decision_record and consumed_at < parse_time(decision_record["recorded_at"]):
            errors.append("request was consumed before its decision was recorded")
        if decision_record and request["revision"] < decision_record["request_revision"] + 2:
            errors.append("consumed request lacks decision and consumption revisions")
        matching_dispatches = [
            item for item in dispatches if item["dispatch_id"] == request["dispatch_id"]
        ]
        if matching_dispatches and parse_time(matching_dispatches[0]["started_at"]) < consumed_at:
            errors.append("dispatch started before the request was consumed")
        if matching_dispatches and request["decision_record_id"] not in matching_dispatches[0]["approval_ids"]:
            errors.append("consumption decision is not in the initial dispatch approval set")
    errors.extend(dispatch_history_errors(dispatches, request))
    captured_at = parse_time(envelope["captured_at"])
    for records, fields in ((validations, ("validated_at",)), (review_snapshots, ("rendered_at",)),
                           (approvals, ("recorded_at",)), (resolutions, ("emitted_at",)),
                           (authority_snapshots, ("checked_at",)), (dispatches, ("recorded_at",)),
                           (events, ("recorded_at",)), ([audit_snapshot], ("captured_at",))):
        if any(parse_time(record[field]) > captured_at for record in records for field in fields):
            errors.append("envelope capture predates a contained record")

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
        "audit.snapshotted",
    }
    if approvals:
        required_event_types.add("approval.decided")
    if resolutions:
        required_event_types.add("resolution.emitted")
    if authority_snapshots:
        required_event_types.add("authority.checked")
    if request["status"] == "expired":
        required_event_types.add("approval.expired")
    if request["status"] == "cancelled":
        required_event_types.add("approval.cancelled")
    missing_event_types = sorted(required_event_types - event_types)
    if missing_event_types:
        errors.append(
            "audit stream lacks required lifecycle events: "
            + ", ".join(missing_event_types)
        )
    if dispatches and not event_types.intersection(
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
    errors.extend(audit_binding_errors(envelope))
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
    if re.search(r"/v[12]/", rendered):
        errors.append("n8n workflow still references an older contract endpoint")
    for endpoint in (
        "/v3/validate",
        "/v3/validations",
        "/v3/requests",
        "/v3/review-snapshots",
        "/v3/resolutions",
        "/v3/authority-snapshots",
        "/v3/events",
        "/v3/snapshots",
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

    for corpus_path in ("tests/conformance.json", "tests/adversarial.json", "tests/hardening.json"):
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
            if vector.get("webauthn") and not vector_has_schema_errors:
                failures.extend(
                    f"{corpus_path} positive {vector['name']}: {error}"
                    for error in webauthn_signature_errors(instance)
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
            vector_errors = (
                webauthn_signature_errors(instance)
                if vector.get("webauthn")
                else semantic_errors(instance)
            )
            if not vector_errors:
                failures.append(
                    f"{corpus_path} negative {vector['name']}: "
                    "unexpectedly passed semantic validation"
                )
            if vector.get("expect_error") and not any(vector["expect_error"] in error for error in vector_errors):
                failures.append(f"{corpus_path} negative {vector['name']}: expected refusal reason was not reported")
    failures.extend(canonicalization_errors())
    failures.extend(f"n8n reference: {error}" for error in n8n_reference_errors())
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        failures = validate_repository()
    except (ValueError, TypeError, KeyError, IndexError, rfc8785.CanonicalizationError):
        failures = ["contract input could not be validated"]
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    if not args.quiet:
        print("All schemas, examples, negative vectors, and lifecycle invariants passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
