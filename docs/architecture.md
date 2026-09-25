# Architecture

## Threat model

The gate assumes an agent can produce malformed input, repeat old messages, reorder
calls, and try to route around policy. The agent must not possess the side-effect
credential. Approval adapters, storage, the policy evaluator, and the deterministic
dispatcher remain ordinary code inside the trusted boundary.

The contracts defend six boundaries:

- **shape** — only versioned, action-specific documents enter the queue;
- **identity** — a decision resolves one known pending request and call;
- **provenance** — nested delegation preserves stable agents and parent call identity;
- **integrity** — approval binds the exact effective action that will execute;
- **authority** — eligibility and authorization are checked at decision and dispatch;
- **outcome** — retries cannot turn an unknown provider result into a duplicate effect.

They do not make a platform-held signature independently verifiable against the
platform itself. Email and Telegram compatibility remains an explicit design choice.

## 1. ProposedAction: the agent drafts and stops

The agent emits a `ProposedAction`; it never calls the side-effect API. The document
includes stable proposal, call, run, agent, delegation, tenant, payload-schema,
expiry, risk, and idempotency identities. The dispatcher credential exists only
beyond the approval boundary. Nested calls preserve their parent IDs; repeated display
names never substitute for stable agent identity.

Validate the top-level schema and the payload schema at ingress. Version 2 ships a strict
`email.send` reference. Other payload schemas live next to the dispatcher that owns
them and follow the same `payload_schema` ID, version, and digest pattern.

Canonicalize the complete proposal with RFC 8785 and hash the canonical bytes with
SHA-256. Prefix the lowercase digest with `sha256:`. The result is the initial
`action_hash`; changing the action type, call identity, tenant, arguments, expiry,
risk, idempotency key, rationale, or payload-schema identity produces a new action.

## 2. Validation, policy evaluation, and durable admission

Write a `ValidationRecord` for the exact action before notifying an approver. It names
the validator and records structural, payload, semantic, policy-input, and
authorization-input checks. Only `passed` is admissible; rejected, failed, absent, or
mismatched validation fails closed.

Evaluate policy before notifying an approver. `ApprovalPolicySnapshot` records:

- immutable policy ID, human revision, and content digest;
- one evaluation ID and a digest of the material inputs;
- quorum, distinct-approver, human-only, channel, signature, auto-approval, and
  separation-of-duties rules.

The approval request embeds that snapshot. Callers never pass the policy fields as
unrelated strings that can drift independently.

Persist `ApprovalRequest` before sending any link or message. It is the authority for
whether a callback is pending. Resolve it with an atomic compare-and-set over at
least `request_id`, current revision, tenant, callback nonce, action hash, and status.
Payload shape is not identity authority.

```text
pending -> approved -> consumed
        -> rejected
        -> expired
        -> cancelled
        -> failed
```

Every transition increments `revision` and appends an audit event. Duplicate callbacks
return the recorded terminal result; they do not write a second decision. A stale,
unknown, cross-tenant, or already-consumed ID fails closed and is itself auditable.

Keep only the callback nonce hash in durable request and audit records. The raw nonce
belongs in the one-time link and expires with the request.

Before notification, persist a `ReviewSnapshot` containing the complete arguments and
other decision material rendered to the approver. The request and decision carry its
identity, and the decision also carries its content hash. A callback for a stale or
altered display fails even when the underlying request ID still exists.

## 3. ApprovalRecord: bind the decision to bytes

One approver writes one append-only `ApprovalRecord`. The record always includes both:

- `action_hash` — the RFC 8785 SHA-256 of the complete effective ProposedAction;
- `payload_hash` — the RFC 8785 SHA-256 of the effective payload alone.

Approver edits are RFC 6902 JSON Patch operations restricted to `/payload`. Apply the
patch to a copy of the original proposal, validate the resulting payload again, then
compute the effective hashes. Never edit the stored proposal in place.

For signed channels, sign the RFC 8785 canonicalization of the ApprovalRecord with the
`signatures` property omitted. The signed object therefore covers request and proposal
identity, both hashes, actor, event and ingestion time, channel, policy evaluation,
and modifications. `key_id` makes rotation explicit.

### Actor invariants

- `approved` requires a human actor, non-policy channel, and an authentication record
  whose `human_present` value is true.
- `auto_approved` requires a policy actor, the policy channel, and the exact
  `policy_evaluation_id`; it is forbidden by a human-only policy.
- A high-risk approval over email or Telegram requires a signature in the composed
  envelope profile.
- Quorum and role checks run across records in the semantic validator because JSON
  Schema cannot compare a policy integer with an array length or enforce identity
  uniqueness across documents.
- Separation-of-duties checks compare stable actor, requester, agent, eligibility,
  exclusion, and signing-key identities; display names do not participate.

### Rejection settlement

A rejected or expired decision states what the approver wanted, not whether an effect
landed. Settlement remains a separate fact inside the record:

- `verified_clean` requires who checked, when, and digest-addressed evidence;
- `compensated` additionally requires the proposal ID of the reversing action;
- `unresolved` deliberately forbids verification fields so it cannot look complete.

`unresolved` is valid to write and invalid to ignore. Alert on its age. Compensation
never deletes the original action or record.

## 4. Deliver the terminal resolution

Emit a `ResolutionRecord` for every decision. It binds the complete approval record,
proposal, call, action hash, terminal disposition, and delivery target. A failed agent
resume retries delivery of the same receipt; it never repeats approval, changes the
decision, or creates a second execution grant.

## 5. Revalidate authority, consume once, then dispatch idempotently

Immediately before dispatch, snapshot the current status of the approving identity,
policy, workspace, and dispatcher. Missing, revoked, unknown, stale, or digest-invalid
authority fails closed without provider invocation.

An approved request is consumed atomically before dispatch. Consumption binds one
terminal decision set to one `dispatch_id`; a second consumer receives the existing
result or a conflict, never a fresh execution grant.

The deterministic dispatcher revalidates the proposal and effective payload, checks
quorum and policy, recomputes both hashes, and sends the proposal's stable
`idempotency_key` to the provider. Each attempt writes a `DispatchRecord` with a hard
`max_attempts` ceiling.

Provider outcomes are not boolean:

| Status | Meaning | Retry rule |
|---|---|---|
| `succeeded` | Provider accepted and returned authoritative evidence | Never retry |
| `failed` | Provider authoritatively rejected or failed before acceptance | Retry only within policy and attempt ceiling |
| `not_dispatched` | Gate refused before provider invocation | Never call the provider |
| `outcome_unknown` | Request may have landed but the response was lost | Never retry blindly |
| `reconciled_succeeded` | Read-only lookup proves the effect landed | Never retry |
| `reconciled_not_applied` | Read-only lookup proves it did not land | A bounded retry may be allowed |

Reconciliation receives a lookup reference, not an execution credential. Retain the
provider record and recovery reference long enough to cover the provider's idempotency
window. If that evidence expires, preserve `unavailable`; do not rewrite uncertainty as
failure.

## 6. Audit stream and complete export: evidence, not authority

Each proposal has one stream with monotonically increasing `sequence`. Event 1 has a
null `previous_event_hash`. Every later event carries the prior event hash. Compute
`event_hash` over the RFC 8785 canonical event with `event_hash` omitted.

The chain detects deletion, insertion, reordering, duplication, and cross-stream
splicing when a trusted checkpoint is retained separately. It does not prevent someone
who controls both the stream and every checkpoint from rewriting all evidence.

A chain alone cannot prove that its tail was included in an export. `AuditSnapshot`
therefore binds the complete ordered event array to its count, first and last sequence,
canonical digest, and terminal event hash. Verify all five before treating a bundle as
complete.

The stream records actor identity on every path, including validation rejection,
notification, view, decision, expiry, refusal, unknown provider outcome, and
reconciliation. It carries both `occurred_at` and `recorded_at`: event time answers
what was true; ingestion time answers when the system learned it.

Audit details and failure records contain hashes, bounded reason classes, redacted safe
detail, policy revision, timing, attempt number, and safe references. They never contain
raw payloads, credentials, callback tokens, provider secrets, or unrestricted model
transcripts. Classification and retention are explicit per event; deletion must also
respect legal hold.

## Schema and semantic validation

JSON Schema enforces the shape and local conditional rules. It cannot recompute hashes,
compare IDs across records, order timestamps, count a policy-defined quorum, or verify a
hash chain. `scripts/validate_contracts.py` demonstrates those semantic checks over the
release examples and negative corpus.

Production systems should perform the same checks in their implementation language at
each boundary, not invoke the repository's development script as a network service.

## Channel choice

| Channel | Trust | Latency | Notes |
|---|---:|---:|---|
| Authenticated web | High | Low | Best place for strong human-presence evidence |
| Slack signed interaction | High | Low | Verify the platform signature and tenant |
| Telegram | Medium | Very low | Sign high-risk records and bind callback nonce |
| Email | Low | High | Sign high-risk records; resist forwarding and replay |
| n8n form | Medium | Low | Keep the request identity and callback validation outside the form fields |
| Policy | Machine | Very low | Allowed only when the immutable policy snapshot permits auto approval |

A UI control that an automation-capable agent can click is not, by itself, a human
boundary. `decided_by.authentication` records the host's actual assurance; it must not
claim `human_present: true` unless the host can enforce that distinction.

## Explicit non-goals

- Prompt-injection prevention. The gate limits consequences after an injection.
- Rate limits, budgets, batching, and high-volume approval UX.
- Automatic compensation. A compensating action is a new proposal through the gate.
- ACL synchronization between source and destination systems. Surface the risk to the
  approver in deployment-specific review evidence; enforce it in the integration.
- Third-party-verifiable proof when the platform holds the signing key.
- A framework, SDK, CLI, daemon, queue, hosted service, or MCP server.

The rejection-settlement split was originally contributed from a separate action-safety
case by [@manahshah](https://dev.to/manahshah). The event-time and cross-system access
boundary observations were raised by [@zenovay](https://dev.to/zenovay).
