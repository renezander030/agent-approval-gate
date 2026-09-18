# Changelog

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
