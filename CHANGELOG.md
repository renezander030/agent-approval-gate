# Changelog

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
