# Contract reference

## Versioning

The release version and every schema's `schema_version` are `2.0.0`. Schema `$id`
values resolve through the immutable `v2.0.0` tag. A consumer may cache schemas by
`$id`; it must not replace a cached release schema with content from `main`.

- Patch releases may clarify descriptions and add compatible examples or tests.
- Minor releases may add optional fields or new enum values when consumers are
  documented to tolerate them.
- Major releases may add required fields, remove values, or change canonicalization.

Because these schemas use `additionalProperties: false`, adding a field is compatible
only after the consumer adopts the new schema version. Never silently project a new
document through an older schema by dropping fields.

## Canonical hashes

Use RFC 8785 JSON Canonicalization Scheme bytes and SHA-256. Encode digests as
`sha256:` plus 64 lowercase hexadecimal characters.

| Digest | Input |
|---|---|
| `payload_schema.digest` | Exact released schema file bytes |
| initial `action_hash` | Complete original `ProposedAction` document |
| effective `action_hash` | Complete proposal copy after approved JSON Patch operations |
| `payload_hash` | Effective `payload` object |
| `review_snapshot.content_hash` | Exact `content` object presented for decision |
| `authority_digest` | Ordered `subjects` array in the authority snapshot |
| `approval_record_hash` | Complete approval record referenced by a resolution receipt |
| `event_hash` | Complete audit event with `event_hash` omitted |
| `previous_event_hash` | Prior event's `event_hash` |
| `audit_snapshot.events_digest` | Complete ordered audit-event array |

Never hash a language-native object with its default serializer. Object-key order,
number rendering, and Unicode handling must be deterministic across languages.
`tests/canonicalization.json` supplies exact canonical byte sequences and hashes,
including UTF-16 property ordering and the interoperable integer ceiling. A conforming
implementation must pass the corpus, not merely produce stable output locally.

## Cross-record invariants

The envelope validator enforces the rules JSON Schema cannot express:

- proposal, validation, review, request, approval, resolution, authority, dispatch,
  and audit references name the same lifecycle;
- delegation call IDs are unique, parent links are contiguous, and the final hop
  matches the proposal's terminal agent and call;
- a request names a passed validation for its exact action hash;
- review content includes the complete effective arguments and its canonical content
  hash matches every approval that cites it;
- request policy input and request action hash match the original proposal;
- modifications produce the action and payload hashes recorded by approval;
- policy separation-of-duties, eligibility, exclusion, and distinct signing-key rules
  hold across every approver;
- each approval has a terminal resolution receipt whose approval-record hash verifies;
- dispatch names a complete, active, unexpired authority snapshot checked after the
  decision and before provider invocation;
- dispatch names approving records and the same effective action hash;
- dispatch preserves the original idempotency key and attempt ceiling;
- requested and decided times precede expiry;
- policy quorum, distinct actors, required roles, human-only, channel, and signature
  rules hold;
- proposal, request, policy, decision, consumption, dispatch, and audit timestamps are
  causally ordered;
- audit sequences are contiguous and every event hash verifies;
- the audit snapshot count, sequence bounds, event-set digest, and terminal hash match
  the exported event array.

Treat a semantic validation error as a hard refusal with a redacted audit reason.

## Delegation and identity

`agent.identity` is the stable authorization identity; display names are not identity.
Each delegation hop carries that identity, a `call_id`, optional `parent_call_id`, and
delegation time. Repeated names are permitted, but reused call IDs, broken parents,
time reversal, or a terminal hop that differs from the proposal are refused.

Persist the chain as contract data. Reconstructing it from a framework's current
in-memory agent object loses provenance after nested handoffs or serialization.

## Validation and review evidence

A request is admissible only when its `validation_id` selects a passed record for the
same proposal and action hash. Required checks make schema, payload, semantic,
policy-input, and authority-input validation explicit instead of inferring success
from the existence of a request.

The `ReviewSnapshot` is the decision surface. Its content carries action identity,
target, complete arguments, risk, expiry, and policy summary. Recompute its
`content_hash` and compare the action and payload hashes before accepting a callback.
Decorative channel text may vary, but it cannot replace or contradict this snapshot.

## Separation of duties

Evaluate `requirements.separation_of_duties` alongside quorum. When enabled, the
requester and proposing agent cannot approve their own action. Eligible and excluded
actor IDs are exact identity sets; excluded key IDs prevent a different actor label
from reusing a prohibited signing key. `distinct_signing_keys` applies across the
approvals that satisfy quorum.

## Modification profile

Version 2 uses RFC 6902 operations restricted to `/payload`. Allowed operations are `add`,
`remove`, `replace`, and `test`. `move` and `copy` are deliberately absent: review
interfaces should show explicit before/after values instead of making an approver
mentally follow pointer movement.

After applying modifications:

1. validate the complete proposal and action-specific payload again;
2. compute the effective action and payload hashes;
3. render exactly that effective action to the approver;
4. dispatch exactly those bytes after the same validation and hash checks.

## Resolution and dispatch authority

An approval decision and delivery of that decision are different state machines.
`ResolutionRecord` is terminal for the decision but permits bounded delivery retry to
the same `target_hash`; retrying delivery must not repeat approval or mint another
execution grant. A revised action always receives a new proposal and approval.

Immediately before provider invocation, produce an `AuthoritySnapshot` for the
approver, policy, workspace, and dispatcher. Every required subject must be present
and active, the digest must verify, and the snapshot must not be expired. `revoked` or
`unknown` fails closed as `dispatch.not_dispatched`.

## Complete audit exports

Hash linkage proves ordering only for the events presented. Pair an export with an
`AuditSnapshot` that commits to its entry count, first and last sequence, canonical
event-array digest, and terminal event hash. Retain a checkpoint outside the mutable
event store when rewrite detection must survive compromise of that store.

## Conformance corpus

`tests/conformance.json` contains positive examples and lifecycle mutations for
missing action binding, reused call identities, rejected validation, self-approval,
revoked authority, resolution tampering, incomplete audit exports, unknown provider
outcomes, broken audit chains, quorum, and attempt ceilings.

`tests/adversarial.json` separately covers bidi and control-character display input,
metadata injection, raw failure payloads, duplicated validation claims, altered review
arguments, and forged review hashes. `tests/canonicalization.json` is the
language-neutral byte-and-digest corpus. Together the files can drive validators in
any implementation language.
