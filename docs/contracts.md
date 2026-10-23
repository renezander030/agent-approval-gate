# Contract reference

## Versioning

The release version and every schema's `schema_version` are `3.3.0`. Schema `$id`
values resolve through the immutable `v3.3.0` tag. A consumer may cache schemas by
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
| `signature.signed_object_hash` | Complete `ApprovalRecord` with `signatures` omitted |
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

## Version 3 boundaries

Parse JSON before schema validation with duplicate-property detection at every depth.
Reject `NaN`, infinities, and overflowing numeric literals. Do not silently choose the
last duplicate property or normalize an ambiguous document before hashing it.

Use a deployment-owned local catalog of released payload schema bytes. The reference
validator ships `email.send`; `validate_envelope` and `payload_errors` also accept a
trusted schema-ID-to-file mapping for other action types. Custom schemas identify
their action with `x-action-type` and use an immutable `/v<version>/` ID. A payload
schema can have its own version independent of the envelope version. Do not fetch an
agent-selected schema URL. Verify the ID, version, action type, and raw-file digest,
then validate both the original payload and every effective edited payload.

Every approval requires the request's exact `policy_evaluation_id`, including human
decisions. A resolution ID has one terminal approval identity; delivery retries update
that receipt's delivery state rather than minting another terminal receipt.

Provider invocation requires a consumed request. Its terminal decision must be
recorded before consumption, and consumption must precede invocation. The consumed
revision must include both decision and consumption transitions after the revision
observed by the approver. Decision, consumption, and invocation must occur strictly
before request expiry; authority is usable only before its required `valid_until`.
The initial dispatch must include the consumed decision and a complete quorum whose
every cited approval binds the same effective action. Votes for different edits cannot
be combined into a quorum.

### Terminal refusals

An envelope covers an admitted request. Rejected, expired, cancelled, and failed
requests can have empty approval, resolution, authority, and dispatch arrays where
those steps never occurred. A rejected request still cites its rejecting decision;
every decision retains its durable resolution. Expiry cannot precede the deadline.

A `not_dispatched` record may have no approval IDs or authority snapshot and must
have `retry_allowed: false`. It cannot carry provider evidence. If no dispatch step
occurred, an expiry or cancellation event, or the recorded rejection, describes the
terminal path without a synthetic invocation. Pending requests are not complete
envelopes. A pre-admission rejection remains a validation record and audit stream,
without an admitted-request envelope.

### Dispatch history and recovery

Order dispatch records by recorded history. Each has a unique `dispatch_id`; the
request retains the first ID as its consumed execution identity. Later records name
the immediately preceding record with `previous_dispatch_id`. They preserve the
effective action hash, approval set, stable provider idempotency key, and attempt
ceiling. A new attempt increments `attempt` by exactly one and cannot begin before
the preceding result was recorded.

Only an authoritative `failed` result permitting retry, or a linked
`reconciled_not_applied` result permitting retry, allows another invocation. Unknown
outcomes require read-only reconciliation. Its record keeps the unknown attempt
number and lookup identity, and cites evidence checked after the unknown result.
Success, unresolved uncertainty, and an exhausted attempt ceiling never grant retry.
Every new invocation requires fresh, active authority; reconciliation does not grant
execution authority.

### Audit witnesses

A hash-valid stream must also describe the actual lifecycle. Every lifecycle record
needs a witness on its matching event type. All audit references resolve inside the
envelope, and supplied decision, action, attempt, policy, and result details agree
with the record. Decision actor and time agree with the approval; witness times agree
with the facts they record. Capturing the envelope cannot precede its contained
evidence. Rehashing a false event never makes it a valid witness.

## Version 3.1 additions

### Policy outcome

`ApprovalPolicySnapshot.outcome` records the evaluator's decision as exactly one of
`require_approval`, `auto_approve`, or `deny`. Map every other evaluator result,
including a non-boolean, missing, unknown, or errored result, to `deny` before writing
the snapshot. Never treat "no opinion" as permission.

- `auto_approve` requires `allow_auto_approval: true`, and every `auto_approved`
  decision requires an explicit `auto_approve` outcome.
- `deny` ends the request as `failed` with `terminal_reason: "policy_failed"`. It cannot
  carry an approving decision or reach provider invocation.

### Revocation before consumption

An approved request may become `revoked` until it is consumed. The transition is a
compare-and-set from `approved` to `revoked`; it must fail once consumption won.
The request names the withdrawn decision in `decision_record_id` and records
`revocation.revoked_at`, `revoked_by`, and a `reason_code`. Its revision includes both
the decision and the revocation transition. Revocation must precede request expiry, an
`approval.revoked` audit event must witness the same actor and time, and a revoked
request cannot invoke a provider. A dispatcher that observes the revocation records
`not_dispatched` with `reason: "approval_revoked"`. The approval record and its
resolution receipt stay unchanged; a new action needs a new proposal.

### Agent feedback

A refusal resolution (`rejected`, `expired`, or `cancelled`) may carry
`agent_feedback` with a closed `reason_code`, a redacted `message`, optional
`requested_changes` (JSON Pointers inside `/payload` with a note), and optional
`questions`. Requested changes or questions require
`disposition: "revise_and_resubmit"` and `retry_policy: "new_proposal"`. Feedback
informs the next proposal; it never reopens the decision or grants execution. When
the `resolution.emitted` event carries a `reason_code`, it must equal the feedback
reason.

### Reference action catalog and review targets

Every built-in `action_type` has a strict reference payload schema in
`schemas/actions/`. Each schema names its action in `x-action-type` and the payload
members the approver must see as the target in `x-review-target`. The validator
requires `ReviewSnapshot.content.target` to equal exactly those members of the
reviewed arguments, for built-in and trusted custom schemas alike. Deployments copy a
schema next to their dispatcher, adapt it, publish it under an immutable ID, and pass
it to the validator as a trusted local file.

### Cross-envelope identities

One envelope proves one lifecycle. A deployment's set of envelopes must also keep
proposal, request, dispatch, and audit-stream identities unique, admit at most one
approval request per tenant and `call_id`, and bind each tenant `idempotency_key` to a
single original action hash. Pass several envelopes to the validator to check the set.

## Version 3.2 additions

### Policy rules and an unavailable evaluator

`ApprovalPolicySnapshot.matched_rules` lists every rule that matched the action, each
with a `deny`, `require_approval`, or `auto_approve` effect. The outcome follows a
fixed precedence: `deny` when any rule denies, otherwise `require_approval` when any
rule asks, otherwise `auto_approve`. An empty list is `deny`; no matching rule is
never permission. Rule IDs are unique within one snapshot.

`evaluation_status: "evaluator_unavailable"` records an evaluator that errored, timed
out, or returned no verdict. Such a snapshot carries no matched rules and its outcome
is `deny`, unless `requirements.on_evaluator_unavailable` is
`require_human_approval`, which lets the outcome be `require_approval` so a human
decides. It is never `auto_approve`.

### Effect hints

`ProposedAction.effects` records `read_only`, `destructive`, `idempotent`, and
`open_world` hints, the same four MCP tool annotations carry. They are part of the
hashed action, and every review snapshot shows them unchanged. A hint that is not
declared takes the conservative value: not read-only, destructive, not idempotent,
open-world. An action cannot be both read-only and destructive.

`requirements.human_required_effects` names effects that need a human: `destructive`
and `open_world` fire on a true hint, `not_idempotent` and `not_read_only` on a false
one. When one fires, the outcome cannot be `auto_approve` and every approving
decision must come from a human.

### Standing grants

A standing grant is a human's decision that policy may approve a bounded class of
actions for a while. An `auto_approved` `ApprovalRecord` cites it in `standing_grant`
with the granting human, `granted_at`, `expires_at`, a scope (tenant, action types,
maximum risk), `max_uses`, and the `use_number` this approval consumes. The validator
requires that:

- the grant was in force when the decision was made;
- the scope covers the action's tenant, type, and risk;
- the use number does not exceed `max_uses`;
- the granting human is not the delegated agent, the requester, or an excluded actor.

`requirements.require_standing_grant` makes a grant mandatory for every auto
approval. A grant does not override `human_required_effects`. Across a set of
envelopes each use number is consumed once and a grant's terms never change.

### Target preconditions

`ProposedAction.target_precondition` names the state of the target the approver saw:
a `resource` and its expected `version`, `etag`, or `content_digest`. It is part of
the hashed action, and every review snapshot shows it unchanged. Before each provider
invocation the dispatcher checks it, as HTTP `If-Match` does, and records
`DispatchRecord.precondition_check` with `matched`, `changed`, or `unavailable`. Only
a `matched` check made before the invocation started may reach the provider. A
changed or unreadable target ends as `not_dispatched` with reason
`precondition_failed`; the consumed approval is spent and a new action needs a new
proposal. A dispatch never checks a precondition the action does not declare.

### Execution grants

`DispatchRecord.execution_grant` is what the dispatcher hands the provider or tool
with the invocation. Its `digest` is the RFC 8785/SHA-256 digest of this manifest,
with the values copied from the dispatch record and `approval_ids` sorted:

```json
{
  "action_hash": "sha256:...",
  "approval_ids": ["approval_..."],
  "attempt": 1,
  "authority_snapshot_id": "authority_...",
  "dispatch_id": "dispatch_...",
  "idempotency_key": "idem_...",
  "proposal_id": "prop_...",
  "request_id": "req_..."
}
```

It is issued after the authority check and before the invocation. A provider or tool
recomputes the digest from the identities it receives and refuses a call whose grant
does not match, so a replayed or forged call is distinguishable from the approved
one. Refusals and reconciliation records carry no grant.
`requirements.require_execution_grant` makes it mandatory for every invocation.

### Local actions and prompt channels

`shell.exec` and `file.write` are built-in action types with reference schemas. A
command is an argument vector run without a shell; its review target is the command,
its absolute working directory, and the execution environment. A file write names
its absolute path (without `..` segments), environment, and mode; `patch` carries a
unified diff, every other mode carries the replacement text.

`teams` and `cli` join the channel set. Like `mcp_elicitation`, a decision on either
names a present, authenticated human and answers a prompt the request delivered on
that channel.

See [framework-mapping.md](framework-mapping.md) for where these records come from in
common agent frameworks.

## Version 3.3 additions

### Relayed reviews in delegated work

A delegated call often reaches its human through the parent conversation. The
request records that path in `relay`: the ancestor calls that carried the review, nearest
first, each with its agent identity and `relayed_at`. The validator requires that:

- every relay hop is an ancestor of the proposing call in the proposal's delegation
  chain and names that hop's agent;
- the hops climb the chain one call at a time, inside the request window, in time order;
- no relaying agent decides the request: a relay forwards the review, and the decision
  binds the delegated call's exact action hash like any other;
- each hop has one `approval.relayed` audit event with the hop's agent as actor, its
  `call_id` in `detail.metadata`, and the relay time.

Approval text copied into a child conversation is not an approval. The child acts on
the resolution for its own request.

### Pending notices

An `ApprovalPendingNotice` is what the gate returns while a human decides, in place of
a tool result: the request and action it concerns, the request revision it observed,
the call it was returned to, the request deadline, the channels the review went to, and
how the caller learns the outcome (`await_resolution`, or `poll_request` no earlier than
`next_check_at`). A parent can receive one for a delegated call, so a waiting child is
visible up the chain instead of ending as a timeout.

A notice grants nothing. In an envelope, `pending_notices` must name this request's
identities and action hash, go to the proposing call or one of its ancestors, repeat the
request deadline exactly, be issued while the request was pending at a revision before it
left pending, and name only channels the request used. A standalone notice is checked
with `--record approval-pending-notice FILE`.

### Escalation without new authority

`requirements.escalation` names who is told when a request is still pending after
`after_seconds`. The request lists each notice in `escalations` with its time, the
notified actors, and the channel, and each has one `approval.escalated` audit event at
the same time on the same channel. An escalation must come no earlier than the policy's
delay, while the request is pending, and only to actors the policy names.

Escalation only notifies. It does not extend the request deadline, and a notified actor
decides only if separation of duties already makes them eligible.

## WebAuthn approval proof

`webauthn-es256` is an optional signature profile for authenticated web approvals.
Compute the RFC 8785 canonical bytes of the complete `ApprovalRecord` with the
`signatures` property omitted, hash them with SHA-256, and use the raw 32 digest bytes
as the WebAuthn challenge. Store the same digest as `signed_object_hash`.

The assertion retains the exact base64url-encoded `client_data_json`,
`authenticator_data`, DER ES256 signature, SPKI DER P-256 public key, credential ID,
RP ID, HTTPS origin, and current and previous counters. Verification must:

1. recompute `signed_object_hash` and the base64url challenge;
2. parse `clientDataJSON` without duplicate keys and require `webauthn.get`, the exact
   challenge, the expected origin, and no cross-origin context;
3. verify the RP ID hash, UP and UV flags, extension-free assertion profile, and
   counter;
4. verify the signature over `authenticatorData || SHA-256(clientDataJSON)`;
5. resolve `registration_evidence` and confirm that the credential public key, actor,
   RP ID, and prior counter match the independently retained registration.

The registration evidence digest is the RFC 8785/SHA-256 digest of this binding
manifest (with values copied from the approval):

```json
{
  "actor": "person@example.com",
  "credential_id": "base64url credential ID",
  "credential_public_key": "base64url SPKI DER public key",
  "previous_sign_count": 8,
  "rp_id": "example.com"
}
```

When the authenticator uses a signature counter, the referenced external evidence is
a registration-and-state checkpoint rather than a static registration document.

Steps 1–4 prove that the included key signed the exact approval artifact. Step 5 is
what makes the result independently attributable instead of merely self-consistent.
The repository validator performs steps 1–4 and validates the registration reference;
production verifiers must resolve and authenticate the referenced evidence.

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

Version 3 uses RFC 6902 operations restricted to `/payload`. Allowed operations are `add`,
`remove`, `replace`, and `test`. `move` and `copy` are deliberately absent: review
interfaces should show explicit before/after values instead of making an approver
mentally follow pointer movement.

Array indices are non-negative decimal tokens without leading zeroes. `add` may use
the array length or `-` to append; other operations require an existing index.
`replace`, `remove`, and `test` require an existing member. Reject malformed pointer
escapes and missing parent containers. `test` compares JSON values recursively:
numbers compare numerically, while booleans remain distinct from numbers. Apply the
whole patch to a copy; any failure refuses the approval without altering the proposal.

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

## Validating your own records

The reference validator checks this repository's corpus when run without arguments,
and your records when given files:

```bash
python scripts/validate_contracts.py --envelope out/envelope.json
python scripts/validate_contracts.py --envelope a.json --envelope b.json   # also checks the set
python scripts/validate_contracts.py --record approval-record out/approval.json
python scripts/validate_contracts.py --envelope out/envelope.json \
  --schema-file schemas/crm.update_record.schema.json                     # trusted custom schema
python scripts/validate_contracts.py --audit-events export.jsonl \
  --audit-snapshot snapshot.json [--anchor sha256:...]                     # offline audit export
```

Inputs are parsed with duplicate-property and non-finite-number refusal. `--json`
prints one result object. Exit status is `0` when every input passed, `1` when a
contract refused an input, and `2` when an input could not be read or parsed.

An audit export may be a contiguous range. A range that starts after sequence 1 must
name the preceding event hash, and `--anchor` checks it against the hash you retained
outside the event store. The snapshot's count, bounds, digest, and terminal hash must
match the exported range exactly.

The repository's `action.yml` runs the same checks in GitHub Actions:

```yaml
- uses: renezander030/agent-approval-gate@v3.3.0
  with:
    envelopes: |
      out/envelope.json
    records: |
      approval-record out/approval.json
    audit-events: out/audit.jsonl
    audit-snapshot: out/audit-snapshot.json
```

## Conformance corpus

`tests/conformance.json` contains positive examples and lifecycle mutations for
missing action binding, reused call identities, rejected validation, self-approval,
revoked authority, resolution tampering, incomplete audit exports, unknown provider
outcomes, broken audit chains, quorum, and attempt ceilings.

`tests/adversarial.json` separately covers bidi and control-character display input,
metadata injection, raw failure payloads, duplicated validation claims, altered review
arguments, forged review hashes, invalid WebAuthn binding, origin drift, counter
rollback, and signature tampering. `tests/canonicalization.json` is the
language-neutral byte-and-digest corpus. Together the files can drive validators in
any implementation language.

`tests/release-3.1.json` adds portable vectors for policy outcomes, revocation, agent
feedback, the MCP elicitation channel, and the reference action schemas.
`tests/release-3.2.json` covers rule precedence, effect hints, standing grants, target
preconditions, execution grants, and the local action schemas.
