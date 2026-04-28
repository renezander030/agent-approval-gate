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

### 4. Dispatcher — plain code, no model

The dispatcher reads `(ProposedAction, ApprovalRecord)`, re-validates both, and executes the side effect. It is intentionally boring code. No prompt, no model call, no chain-of-thought.

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

## What this pattern explicitly does not do

- **It does not prevent prompt injection.** That is a different layer (input sanitization, system-prompt isolation). The gate stops a *successful* injection from causing real-world damage; it does not stop the injection from happening.
- **It does not replace rate limits or budget caps.** A pipeline that drafts 10,000 proposals/minute will overwhelm the approver. Cap drafts at the source.
- **It does not handle compensation.** If a dispatched action turns out to be wrong, the gate does not roll it back. Plan rollback per action_type.
