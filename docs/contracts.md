# Contract reference

## Versioning

The release version and every schema's `schema_version` are `1.0.0`. Schema `$id`
values resolve through the immutable `v1.0.0` tag. A consumer may cache schemas by
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
| `event_hash` | Complete audit event with `event_hash` omitted |
| `previous_event_hash` | Prior event's `event_hash` |

Never hash a language-native object with its default serializer. Object-key order,
number rendering, and Unicode handling must be deterministic across languages.

## Cross-record invariants

The envelope validator enforces the rules JSON Schema cannot express:

- proposal, request, approval, dispatch, and audit references name the same lifecycle;
- request policy input and request action hash match the original proposal;
- modifications produce the action and payload hashes recorded by approval;
- dispatch names approving records and the same effective action hash;
- dispatch preserves the original idempotency key and attempt ceiling;
- requested and decided times precede expiry;
- policy quorum, distinct actors, required roles, human-only, channel, and signature
  rules hold;
- proposal, request, policy, decision, consumption, dispatch, and audit timestamps are
  causally ordered;
- audit sequences are contiguous and every event hash verifies.

Treat a semantic validation error as a hard refusal with a redacted audit reason.

## Modification profile

V1 uses RFC 6902 operations restricted to `/payload`. Allowed operations are `add`,
`remove`, `replace`, and `test`. `move` and `copy` are deliberately absent: review
interfaces should show explicit before/after values instead of making an approver
mentally follow pointer movement.

After applying modifications:

1. validate the complete proposal and action-specific payload again;
2. compute the effective action and payload hashes;
3. render exactly that effective action to the approver;
4. dispatch exactly those bytes after the same validation and hash checks.

## Conformance corpus

`tests/conformance.json` contains positive examples and negative mutations for missing
action binding, invalid auto approval, incomplete settlement, approval replay identity,
signature policy, unknown provider outcomes, broken audit chains, quorum, and attempt
ceilings. The same corpus can drive validators in other languages.
