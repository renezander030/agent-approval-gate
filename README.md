# agent-approval-gate

**AI agents should draft. Code should validate. Humans should approve. Systems should dispatch.**

A portable contract pattern for adding approval gates to AI automation workflows.
Use it when an agent wants to send a message, update a record, create a ticket, call
an API, or trigger another workflow.

This repo is opinion + versioned JSON Schemas + conformance examples. It is not a
framework. Drop the contracts into your own stack and keep the side-effect credential
away from the agent.

## The pattern

```text
AI Agent -> ProposedAction -> ValidationRecord -> ReviewSnapshot
                                                    |
                                                    v
                                ApprovalRequest -> ApprovalRecord
                                                    |
                                         ResolutionRecord
                                                    |
                                  dispatch-time authority check
                                                    |
                                                    v
                                      deterministic Dispatcher
                                                    |
                                                    v
                         DispatchRecord + complete audit snapshot
```

Nine boundaries make the gate real:

1. **ProposedAction** serializes the complete action. Its RFC 8785 digest binds the
   action type, call identity, arguments, tenant, expiry, risk, and idempotency key.
2. **Delegation provenance** preserves stable agent and nested call identities from
   the root invocation through the terminal action.
3. **ValidationRecord** attests that the exact action passed structural, payload,
   semantic, policy-input, and authority-input checks before notification.
4. **ReviewSnapshot** binds the complete arguments and other decision material shown
   to the approver to the action and payload hashes.
5. **ApprovalRequest** is durable, addressable state. A callback resolves one known,
   pending request and the approved request is consumed exactly once.
6. **ApprovalRecord** names the actor, enforces separation of duties, and binds the
   decision to the immutable policy revision and reviewed content.
7. **ResolutionRecord** durably returns the terminal decision without reopening an
   approval when delivery or agent resumption fails.
8. **Dispatcher** revalidates current authority immediately before invocation, uses
   the stable idempotency key, and preserves explicitly unknown outcomes.
9. **Audit stream** is append-only, redacted, and hash-linked; its export manifest
   proves the expected count, sequence bounds, event-set digest, and terminal hash.

If the agent still has the side-effect credential, the approval path remains optional
from the agent's point of view.

## Contracts in v2.0.0

| Contract | Purpose |
|---|---|
| [`proposed-action.schema.json`](schemas/proposed-action.schema.json) | Exact action draft, expiry, risk, payload schema, and idempotency identity |
| [`validation-record.schema.json`](schemas/validation-record.schema.json) | Immutable pre-notification validation result for an exact action |
| [`review-snapshot.schema.json`](schemas/review-snapshot.schema.json) | Exact decision material shown to the approver, bound by canonical hashes |
| [`approval-policy.schema.json`](schemas/approval-policy.schema.json) | Immutable policy revision, material inputs, quorum, and channel requirements |
| [`approval-request.schema.json`](schemas/approval-request.schema.json) | Durable pending identity, notifications, terminal state, and single-use consumption |
| [`approval-record.schema.json`](schemas/approval-record.schema.json) | Human or policy decision, action and payload hashes, signatures, and settlement evidence |
| [`resolution-record.schema.json`](schemas/resolution-record.schema.json) | Durable terminal receipt with independent delivery and acknowledgement state |
| [`authority-snapshot.schema.json`](schemas/authority-snapshot.schema.json) | Dispatch-time authority status for approver, policy, workspace, and dispatcher |
| [`dispatch-record.schema.json`](schemas/dispatch-record.schema.json) | Attempt ceiling, provider outcome, unknown-outcome handling, and reconciliation |
| [`audit-event.schema.json`](schemas/audit-event.schema.json) | Redacted lifecycle evidence with actor, event time, ingestion time, and hash chain |
| [`audit-snapshot.schema.json`](schemas/audit-snapshot.schema.json) | Completeness manifest for one exported audit-event set |
| [`approval-envelope.schema.json`](schemas/approval-envelope.schema.json) | Portable bundle plus cross-contract profile for a completed lifecycle |
| [`actions/email.send.schema.json`](schemas/actions/email.send.schema.json) | Strict reference for composing action-specific payload contracts |

Schema IDs are pinned to the `v2.0.0` release. Pin a released ID in production; do not
resolve schemas from the mutable default branch.

## Quick start

1. Validate the proposal and payload, record every required check in a passed
   `ValidationRecord`, and refuse admission on any failed or missing check.
2. Canonicalize the complete `ProposedAction` with RFC 8785 and store its SHA-256 as
   `action_hash` on the approval request.
3. Persist a `ReviewSnapshot` and request before notifying any channel. Resolve
   callbacks only by the pending request revision, tenant, nonce, action hash, and
   exact reviewed-content hash.
4. Recompute the effective action after any JSON Patch modifications. Enforce the
   policy's approver eligibility, exclusion, requester/agent separation, and signing
   key rules before writing an append-only `ApprovalRecord`.
5. Emit a durable `ResolutionRecord`; retry only its delivery when agent resumption
   fails. Never repeat the decision or create a fresh execution grant.
6. Atomically consume the approved request, revalidate current authority, then
   dispatch with the stable `idempotency_key`. An unknown provider outcome goes to
   reconciliation, not retry.
7. Append the lifecycle events and export them with an `AuditSnapshot`. Never put raw
   payloads, credentials, callback tokens, or provider secrets in failure or audit
   details.

The complete synthetic lifecycle is in
[`examples/approval-envelope.json`](examples/approval-envelope.json). The validator
checks IDs, hashes, quorum, expiry, sequence linkage, and attempt ceilings that JSON
Schema alone cannot compare across documents.

[`tests/canonicalization.json`](tests/canonicalization.json) is a language-neutral
RFC 8785 corpus with exact canonical UTF-8 bytes and SHA-256 results. Use it to prove
that implementations in different languages bind the same document to the same hash.
[`tests/adversarial.json`](tests/adversarial.json) exercises deceptive identities,
display controls, metadata injection, redaction boundaries, and review tampering.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python scripts/generate_examples.py
.venv/bin/python -m unittest discover -s tests -v
```

## n8n reference

[`examples/n8n-approval-workflow.json`](examples/n8n-approval-workflow.json) is an
importable wait-and-resume reference. Unlike a notification-only workflow, it calls a
real schema validator, persists validation and review evidence before notification,
accepts a signed callback, durably delivers the resolution, revalidates authority,
atomically consumes the approval, sends an idempotency key to the dispatcher, and
exports a complete audit snapshot on both success and refusal paths.

Configure these deployment-owned endpoints after import:

- `APPROVAL_VALIDATOR_URL` — validates the versioned schemas.
- `APPROVAL_GATE_URL` — stores requests and resolves/consumes callbacks atomically.
- `APPROVAL_AUDIT_URL` — appends and hash-links audit events.
- `APPROVAL_DISPATCH_URL` — deterministic side-effect endpoint.
- `APPROVAL_POLICY_ID` and `TG_APPROVER_CHAT_ID` — policy and approver routing.

The workflow deliberately does not embed a queue, database, validator, or dispatcher.
Those are trust-boundary components, not Code-node snippets. See
[`docs/n8n-reference.md`](docs/n8n-reference.md).

## What this repo is not

- Not a framework, SDK, CLI, daemon, hosted queue, or dispatcher.
- Not coupled to one LLM, orchestrator, approval channel, or protocol.
- Not a prompt-injection filter, rate limiter, budget engine, or ACL synchronization
  service.
- Not third-party-verifiable proof when the platform itself holds the signing key.

See [`docs/architecture.md`](docs/architecture.md) for the threat model and
[`docs/contracts.md`](docs/contracts.md) for canonicalization, lifecycle, and
compatibility rules.

## Related gates

- [skillgate](https://github.com/renezander030/skillgate) applies the deterministic-gate
  idea to the development finish line.

## Related work

- [Production AI Automation Notes #1: Agent Approval Gates](https://gist.github.com/renezander030/9069db775e494ffd2cdd5a09adf83add)
- [Claude Code with local LLMs](https://gist.github.com/renezander030/39249215616a095d74fe6c66b0348641)
- [Claude Code runtime rules](https://gist.github.com/renezander030/2898eb5f0100688f4197b5e493e156a2)
- [Context7 v2 enterprise GraphQL MCP pattern](https://gist.github.com/renezander030/83ad49aeffa5f8749325a2b19617823f)
- [fixclaw](https://github.com/renezander030/fixclaw)

MIT licensed. Maintained by [René Zander](https://github.com/renezander030).
