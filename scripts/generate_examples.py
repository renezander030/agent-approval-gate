#!/usr/bin/env python3
"""Regenerate hashes and the composed release example deterministically."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import rfc8785


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SCHEMAS = ROOT / "schemas"


def load(name: str) -> Any:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def write(name: str, value: Any) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    (EXAMPLES / name).write_text(rendered, encoding="utf-8")


def digest_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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
    previous_hash: str | None = None
    for event in events:
        event["previous_event_hash"] = previous_hash
        detail = event["detail"]
        if "action_hash" in detail:
            detail["action_hash"] = action_hash
        if "payload_hash" in detail:
            detail["payload_hash"] = payload_hash
        if "review_content_hash" in detail:
            detail["review_content_hash"] = review_snapshot["content_hash"]
        if "audit_snapshot_id" in event["references"]:
            event["references"]["audit_snapshot_id"] = audit_snapshot["snapshot_id"]
        unhashed = {key: value for key, value in event.items() if key != "event_hash"}
        event["event_hash"] = digest_value(unhashed)
        previous_hash = event["event_hash"]
    write("audit-events.json", events)

    audit_snapshot["entry_count"] = len(events)
    audit_snapshot["first_sequence"] = events[0]["sequence"]
    audit_snapshot["last_sequence"] = events[-1]["sequence"]
    audit_snapshot["events_digest"] = digest_value(events)
    audit_snapshot["root_event_hash"] = events[-1]["event_hash"]
    write("audit-snapshot.json", audit_snapshot)

    envelope = {
        "schema_version": "2.0.0",
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
    write("approval-envelope.json", envelope)


if __name__ == "__main__":
    main()
