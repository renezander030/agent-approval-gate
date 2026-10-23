# Changelog

## 3.3.0

Approvals that stay legible while they wait, travel through delegated agents, and end
in a refusal or a replacement.

### Added

- `ApprovalRequest.relay`: the ancestor calls that carried a delegated call's review to
  its approver, each witnessed by an `approval.relayed` event. A relaying agent never
  decides, and the decision binds the delegated call's exact action.
- `ApprovalPendingNotice`: what the gate returns to the proposing call and its parent
  calls while a human decides: request, action hash, deadline, channels, and whether
  to await the resolution or poll after `next_check_at`. Envelopes can carry the
  notices they issued, and `--record approval-pending-notice` checks one alone.
- `requirements.escalation` and `ApprovalRequest.escalations`: named actors are told
  after a delay, with an `approval.escalated` witness. Escalation grants no decision
  rights and no extra time.
- `ApprovalRequest.policy_refusal`: a policy denial names the deciding evaluation, the
  denying rules, a redacted message, the policy owner, and the next step, checked
  against the policy snapshot.
- `ApprovalRecord.issued_grant` and `standing_grant.origin`: a standing grant is issued
  explicitly by a human approval, an auto approval can name that origin, and
  `requirements.require_grant_origin` makes it mandatory. Envelope sets check that the
  origin issued the same terms.
- `ApprovalPolicySnapshot.evaluator`: an embedded engine or an external policy decision
  point with its protocol, decision ID, and response time.
- `terminal_reason: "superseded"` with `superseded_by`: a pending request replaced by a
  newer proposal names its successor, and later decisions on it are refused.
- W3C `trace_context` on requests and audit events, outside the hashed action.
- A `network.egress` reference action schema for one host, port, and protocol from a
  named environment, for a connection or a session with a time bound.
- Complete [delegated](examples/delegated-envelope.json),
  [escalated](examples/escalated-envelope.json),
  [policy-denied](examples/policy-denied-envelope.json),
  [grant-issuing](examples/grant-issuing-envelope.json),
  [grant-origin](examples/grant-origin-envelope.json),
  [superseded](examples/superseded-envelope.json), and
  [traced](examples/traced-envelope.json) lifecycles, and portable vectors in
  `tests/release-3.3.json`.

### Compatibility

Every addition is optional on existing records, and the new enum values extend closed
sets. Schema IDs and `schema_version` move to `3.3.0`; continue validating stored v3.2
records with the v3.2.0 schemas and do not relabel them. Records produced under 3.3 must
cite the v3.3.0 payload schema ID and digest.

## 3.2.0

Policies you can explain, pre-approvals with limits, and dispatches that prove which
approval and which target state they ran on.

### Added

- `ApprovalPolicySnapshot.matched_rules`: every matching rule with its `deny`,
  `require_approval`, or `auto_approve` effect. The outcome follows deny >
  require_approval > auto_approve, and no matching rule is `deny`. Standalone policy
  and request records are checked the same way.
- `evaluation_status: evaluator_unavailable` with
  `requirements.on_evaluator_unavailable`: an evaluator that cannot answer leads to
  `deny`, or to a human approval when the policy opts in, and never to auto approval.
- `ProposedAction.effects`: read-only, destructive, idempotent, and open-world hints
  in the hashed action and every review snapshot, with
  `requirements.human_required_effects` to require a human for chosen effects.
- Standing grants: an auto approval cites a human's grant with expiry, tenant,
  action types, maximum risk, a use ceiling, and the use it consumes, with
  `requirements.require_standing_grant`. A set of envelopes consumes each use once.
- `ProposedAction.target_precondition` and `DispatchRecord.precondition_check`: the
  target version, ETag, or content digest the approver saw is checked before every
  invocation, and a changed target ends as `not_dispatched` with
  `precondition_failed`.
- `DispatchRecord.execution_grant`: a digest over the dispatch's request, approvals,
  action hash, authority snapshot, idempotency key, and attempt that a provider or
  tool verifies before acting, with `requirements.require_execution_grant`.
- `shell.exec` and `file.write` reference action schemas whose review target names
  the command or path together with its directory and execution environment.
- `teams` and `cli` approval channels for decisions on a Teams card or a terminal
  prompt.
- [`docs/framework-mapping.md`](docs/framework-mapping.md): where each record comes
  from in LangGraph, the OpenAI Agents SDK, the Vercel AI SDK, Google ADK,
  pydantic-ai, Mastra, MCP, and coding-agent hooks.
- Complete [standing-grant](examples/standing-grant-envelope.json),
  [precondition](examples/precondition-envelope.json),
  [precondition-failed](examples/precondition-failed-envelope.json), and
  [execution-grant](examples/granted-envelope.json) lifecycles, and portable vectors
  in `tests/release-3.2.json`.

### Compatibility

Every addition is optional on existing records, and the new enum values extend
closed sets. Schema IDs and `schema_version` move to `3.2.0`; continue validating
stored v3.1 records with the v3.1.0 schemas and do not relabel them. Records produced
under 3.2 must cite the v3.2.0 payload schema ID and digest.

## 3.1.0

Approval paths that fail closed, approvals that can be withdrawn until dispatch, and
records you can verify in your own pipeline.

### Added

- `ApprovalPolicySnapshot.outcome`: a closed `require_approval`, `auto_approve`, or
  `deny` result. Auto approval requires an explicit `auto_approve` outcome under a
  policy that allows it; a `deny` outcome ends the request as `policy_failed` and
  never reaches a provider.
- Revocation of an approved request before consumption: `revoked` status,
  `approval_revoked` terminal and dispatch reasons, a `revocation` record with actor,
  time, and reason, an `approval.revoked` audit event, and a complete
  [revoked lifecycle](examples/revoked-envelope.json).
- `ResolutionRecord.agent_feedback` for refusals: reason code, redacted message,
  requested payload changes, and questions, returned with
  `revise_and_resubmit` and `new_proposal`.
- An `mcp_elicitation` approval channel with a [profile](docs/mcp-elicitation.md) for
  MCP servers that collect decisions through form-mode elicitation. Approved and
  rejected elicitation decisions name a present, authenticated human.
- Strict reference payload schemas for `crm.update_record`, `ticket.create`,
  `db.update_row`, `api.call`, and `n8n.trigger_workflow`, with example payloads.
- `x-review-target` on action schemas: the review snapshot target must equal those
  members of the reviewed arguments for every action type.
- Validator inputs for your own files: `--envelope`, `--record KIND FILE`,
  `--schema-file`, `--audit-events` with `--audit-snapshot` and `--anchor`, and
  `--json`, with exit status 0, 1, or 2.
- Set checks across envelopes: unique proposal, request, dispatch, and audit-stream
  identities, one approval request per call, and one action per idempotency key.
- Offline verification of exported audit ranges, including partial exports anchored
  to a retained checkpoint hash.
- A GitHub Action (`action.yml`) that runs the validator in any repository.
- Portable conformance vectors in `tests/release-3.1.json`.

### Compatibility

Every addition is optional on existing records. Schema IDs and `schema_version` move
to `3.1.0`; continue validating stored v3.0 records with the v3.0.0 schemas and do
not relabel them. Records produced under 3.1 that use `email.send` must cite the
v3.1.0 payload schema ID and digest.

## 3.0.0

This release enforces the approval and execution boundaries across complete success,
edited-action, refusal, expiry, and recovery lifecycles.

### Changed

- Revalidate original and edited payloads against trusted local action schemas,
  including action type, released version, schema ID, and exact file digest.
- Require consumed request state before provider invocation, with causal decision,
  terminal, consumption, and dispatch times and exclusive expiry boundaries.
- Represent rejection, expiry, cancellation, and failure without inventing approvals
  or authority checks. Refused dispatches cannot invoke a provider or allow retries.
- Link dispatch history with `previous_dispatch_id`, stable action and idempotency
  identities, fixed attempt ceilings, and contiguous retry attempt numbers.
- Require `policy_evaluation_id` on every decision and bind it to the request policy.
  Authority evidence requires an explicit `valid_until` boundary.
- Verify typed audit witnesses against actual records, actors, outcomes, times, and
  identities; reject foreign references and captures that precede included evidence.
- Count the complete dispatch quorum only from approvals for one effective action.
- Enforce JSON Patch target existence, exact array bounds, pointer escapes, and JSON
  value equality without conflating booleans and numbers.
- Reject duplicate JSON keys at every depth and non-finite numbers at ingress.

### Added

- Complete edited-action, rejected, expired, and reconciled-retry examples plus
  portable refusal vectors and focused lifecycle regressions.
- n8n reference endpoint contracts for `/v3/` integrations.

### Migration

Continue validating stored v2 records with their original schemas. For new v3 records,
add the request policy evaluation ID to every approval and a finite authority validity
window. Link retry and reconciliation records to the preceding dispatch record; retain
the initial consumed dispatch identity and stable idempotency key. Recompute hashes
and signatures after adopting the v3 schema IDs. Do not relabel historical records.

## 2.1.0

This release adds an optional WebAuthn proof profile for independently verifiable
cryptographic attribution of high-risk approvals completed in an authenticated web UI.

### Added

- `webauthn-es256` approval signatures carrying the exact client data,
  authenticator data, P-256 credential public key, RP ID, origin, signature counters,
  and digest-addressed credential-registration evidence needed for offline checking.
- A deterministic passkey approval example with a real ES256 assertion and negative
  vectors for record binding, origin scope, signature counters, channel restrictions,
  and cryptographic verification.
- Semantic verification of the WebAuthn challenge, `webauthn.get` type, origin,
  RP ID hash, user-presence and user-verification flags, signature counter, P-256 key,
  and assertion signature.

### Changed

- Approval signatures may bind the SHA-256 of the RFC 8785 canonical approval record
  with `signatures` omitted as the WebAuthn challenge.
- WebAuthn proofs are restricted to high-assurance, human-present authenticated web
  sessions. Existing HMAC and Ed25519 signature profiles are unchanged.
- Schema IDs are pinned to the immutable `v2.1.0` release.

### Migration

Version 2.0 records remain valid against the v2.0.0 schemas. Adopt the v2.1.0 schemas
only when producing or verifying the optional WebAuthn profile; do not rewrite stored
records in place.

## 2.0.0

This major release makes the approval lifecycle independently traceable from nested
agent delegation through review, resolution delivery, dispatch-time authorization,
and audit export. The new lifecycle records are required in a complete envelope.

### Added

- Stable agent identities and delegation chains that preserve parent and terminal
  call provenance across nested handoffs and serialization.
- Immutable pre-admission validation records covering proposal, payload, semantic,
  policy-input, and authority-input checks.
- Review snapshots that bind the complete arguments and exact decision material shown
  to an approver to the action and payload hashes.
- Policy-level separation-of-duties rules for requester, agent, eligible and excluded
  approvers, and signing keys.
- Durable terminal resolution receipts with delivery and acknowledgement tracked
  separately from the approval decision.
- Dispatch-time authority snapshots for the approver, policy, workspace, and
  dispatcher, with revoked or unknown authority failing closed.
- Audit snapshot manifests that prove event-set completeness with count, sequence
  bounds, canonical digest, and terminal chain hash.
- A language-neutral RFC 8785 corpus with exact UTF-8 bytes, SHA-256 digests,
  Unicode, number, ordering, timestamp, and unsafe-integer cases.
- Adversarial conformance vectors for bidirectional text, reused call identities,
  altered review arguments, forged review hashes, rejected validation, unsafe failure
  detail, self-approval, revoked authority, resolution tampering, and audit omission.

### Changed

- Complete approval envelopes now require validation, review, resolution, authority,
  and audit snapshot records.
- Approval requests and records bind the validation result, review snapshot, request
  revision, and reviewed-content hash.
- Dispatch records require the authority snapshot used immediately before invocation.
- Failures use a bounded reason taxonomy and a redacted `safe_detail` field.
- Schema IDs are pinned to the immutable `v2.0.0` release.

### Migration

Version 2 is intentionally not wire-compatible with version 1. Add stable agent and
delegation identities, emit and retain each new lifecycle record, enforce the new
cross-record bindings, and validate canonicalization with the release corpus before
accepting or dispatching v2 documents. Continue validating stored v1 records with the
v1.0.0 schemas; do not rewrite their version in place.

## 1.0.0

The first versioned contract release turns the reference pattern into a portable,
testable lifecycle without turning the repository into a framework.

### Added

- Durable approval requests with explicit pending and terminal states, expiry,
  callback nonce hashing, revision checks, and single-use consumption.
- Complete action-envelope hashing over call identity, payload-schema identity,
  tenant, expiry, risk, idempotency key, and arguments.
- Immutable policy snapshots with revision digests, material inputs, quorum, channel,
  signature, required-role, human-only, and auto-approval requirements.
- Dispatch attempt records with stable idempotency, attempt ceilings, unknown outcomes,
  and read-only reconciliation evidence.
- Redacted lifecycle audit events with actor identity, event and ingestion time,
  retention metadata, sequence numbers, and a SHA-256 hash chain.
- A strict `email.send` payload schema and a reusable composition pattern for other
  dispatcher-owned action types.
- Positive and negative conformance vectors, cross-record semantic validation, and CI.
- An end-to-end n8n wait-and-resume reference covering validation, durable request
  admission, signed callback resolution, one-time consumption, dispatch, and audit.

### Changed

- `payload_hash` and `recorded_at` are required on every approval record.
- Approver modifications use an RFC 6902 subset restricted to `/payload` and require
  revalidation plus new effective hashes.
- Human, policy, approval, expiry, rejection, and settlement states have strict local
  invariants. Verified and compensated settlements require evidence; unresolved
  settlements cannot carry fields that imply verification.
- Schema IDs are pinned to the immutable `v1.0.0` release.

### Migration

Existing unversioned examples are not v1 records. Add the required version, identity,
hash, policy, expiry, idempotency, actor-authentication, and ingestion fields, then
validate the complete lifecycle with the release corpus before dispatching it.
