# Architecture

## The five contracts

This pattern only works if all five are present. Skipping any one of them turns the gate into theater.

### 1. ProposedAction — the agent never executes, only drafts

The agent emits a `ProposedAction` and stops. It does not call the email API, the CRM API, or n8n directly. Whatever side effect the agent wants to cause must be expressible as a serializable payload.

Two reasons this matters:

- **Schema enforcement.** A serialized contract can be validated; a function call cannot. Agents that call APIs directly drift their parameter shape across runs and you only notice when production breaks.
- **Bypass prevention.** If the agent has the API key, the approval step is optional from the agent's point of view. If only the dispatcher has the API key and the agent has no network reach to the side-effect surface, the approval step is *the* path.

### 2. Schema validation — at the boundary, not inside the dispatcher

`schemas/proposed-action.schema.json` is the contract. Validate the moment the proposal arrives at the queue, not later. The dispatcher should be allowed to assume the payload is well-formed.

Per-`action_type` sub-schemas (e.g. `email.send` requires `to`, `subject`, `body_text`) live next to the dispatcher implementation, because they evolve with the integration. The top-level schema is stable; the sub-schemas are not.

### 3. ApprovalRecord — the decision is its own document

Approvals are not a flag on the proposal. They are a separate, append-only record. This matters when:

- A proposal is approved, then auto-rejected because it expired before dispatch — both events need to be auditable.
- Multiple approvers are required (e.g. high-risk actions). Each approver writes their own record.
- A policy auto-approves under a rule. The record names the rule (`decided_by.kind = "policy"`, `identifier = "low-risk-internal-tenant"`), not a human.

**Bind the record to the payload, not just to the proposal.** `proposal_id` is an indirection, so a record that carries only the id says "someone approved proposal X" without saying what X contained at the time. If anything between approve and dispatch rewrites the payload under an unchanged id (a queue retry, a partial re-draft, a compromised worker), the record still looks valid and the signature still verifies. Close it with `payload_hash`: canonicalize the effective payload with RFC 8785, sha256 it, and store the digest on the record. "Effective" means after `modifications` are applied, because that is what the approver actually saw and what the dispatcher will actually run. When a signature is present, the hash goes inside the signed object, otherwise you have signed the decision and left the bytes loose.

**A rejection is a decision, not an outcome.** `decision: rejected` records what the approver wanted. It does not say the side effect failed to happen. A queue replay, a partial dispatch, or a retry racing the decision can land the effect anyway, and the record still reads as closed. So the settlement is a separate fact with its own author and its own timestamp: `verified_clean` when something checked the target system and the effect is not there, `compensated` when it did land and a named reversing action undid it, `unresolved` when nobody has looked yet.

`unresolved` is a legitimate state to write and an illegitimate state to leave. Alert on its age, not on its existence. And compensation never deletes: the original record and the compensating action both stay in the log, because the fact that something was attempted and reversed is itself evidence somebody will need. A cleaned-up decline is the same class of bug as a stale tag silently dropped — a record treated as bookkeeping when it was evidence. (This three-state split came from [@manahshah](https://dev.to/manahshah), who arrived at it from a different kind of action entirely.)

**Record when you decided and when you found out.** `decided_at` is event time; `recorded_at` is when the gate persisted the record. On asynchronous channels these diverge, sometimes by minutes on an email reply and by much more on a replayed webhook. Ordering on arrival time is how stale context overwrites a newer human decision. Keep both: reason with `decided_at`, audit with `recorded_at`. Only one of them and you can reconstruct either what was true or when you learned it, never both, and the second is what answers why the dispatcher acted when it did. (Raised by [@zenovay](https://dev.to/zenovay).)

### 4. Dispatcher — plain code, no model

The dispatcher reads `(ProposedAction, ApprovalRecord)`, re-validates both, and executes the side effect. It is intentionally boring code. No prompt, no model call, no chain-of-thought.

Before it executes, it runs one more check: recompute `payload_hash` over the payload it is about to send, and compare it to the hash on the `ApprovalRecord`. Mismatch is a hard refusal, logged as `not_dispatched` with reason `payload_hash_mismatch`. Never a warning, never a best-effort dispatch. This is the step that makes the approval bind to bytes instead of to a row id, and it costs one hash.

If you find yourself wanting the model to "decide how to dispatch," that is a sign the action_type enum is too coarse. Split it into more specific types instead of asking the model to branch.

### 5. Audit log — three rows minimum

For every proposal that leaves the agent, the log should grow by at least three append-only rows:

| event | timestamp | refs |
|---|---|---|
| `proposed` | when the agent drafted | proposal_id |
| `decided` | when the approver decided | proposal_id, approval channel, decided_by |
| `dispatched` | when the dispatcher executed | proposal_id, side-effect outcome (success/failure, external IDs) |

If the proposal is rejected or expires, the third row is `not_dispatched` with the reason. The log should be queryable by `proposal_id` so the full lifecycle is one fetch.

## Channel choice

Approval channels in rough order of trust → friction:

| Channel | Trust | Latency | Best for |
|---|---|---|---|
| Web UI (authenticated) | High | Low | Frequent approvers, mobile + desktop |
| Slack DM (with signed buttons) | High | Low | Existing Slack-first teams |
| Telegram bot | Medium | Very low | Solo operators, fast on mobile |
| Email | Low | High | One-off / out-of-band only |
| n8n form | Medium | Low | When the rest of the pipeline lives in n8n |

A signature on the `ApprovalRecord` is mandatory for high-risk actions on Telegram and email — both can be spoofed. For Slack with signed-buttons or an authenticated web UI, the channel itself provides the signature.

`payload_hash` is a separate question from the signature and applies on every channel, including the high-trust ones. The signature answers "was this decision authentic". The hash answers "was this the thing decided on". A trusted channel gives you the first for free and none of the second, because the mutation you are defending against happens after the approver clicks, on your side of the boundary.

## What this pattern explicitly does not do

- **It does not prevent prompt injection.** That is a different layer (input sanitization, system-prompt isolation). The gate stops a *successful* injection from causing real-world damage; it does not stop the injection from happening.
- **It does not replace rate limits or budget caps.** A pipeline that drafts 10,000 proposals/minute will overwhelm the approver. Cap drafts at the source.
- **It does not handle compensation.** If a dispatched action turns out to be wrong, the gate does not roll it back. Plan rollback per action_type. It does record compensation when you do it: `rejection_settlement.state = "compensated"` with the proposal_id of the reversing action, which itself goes through this gate.
- **It does not propagate the source's access level to the destination.** A proposal drafted from a restricted source and written into a broader-permission project inherits the destination's ACL, not the origin's. The gate shows the approver where the content came from, so a person can catch it, but nothing enforces that the target ticket keeps the originating restriction. That is the right design and it is not built here. If you sync between systems with different access boundaries, treat this as an open gap rather than a solved one. (Named by [@zenovay](https://dev.to/zenovay).)
- **It does not give you third-party-verifiable proof of approval.** The signature uses a per-tenant key that the platform holds, so the evidence and the executor sit inside the same trust boundary. That is enough to answer "did the agent do something nobody approved", which is the dispute that actually shows up. It is not enough if the approver themself is the contested party, because whoever holds the key could have written the record. Answering that needs a signature held by the person rather than the platform (passkey or similar), on a channel that can carry one, which rules out email and Telegram. `payload_hash` is orthogonal and worth having either way: it is what a per-person signature would have to cover anyway.
