# MCP elicitation profile

An MCP server that gates side effects can ask the person at the MCP client to decide
through `elicitation/create`. The `mcp_elicitation` channel records that decision in the
same `ApprovalRecord` as any other channel. The elicitation is a notification and answer
surface; the approval request, review snapshot, policy, and dispatcher stay on the
server side of the trust boundary.

## When the channel is available

Offer the channel only when the client declared form-mode elicitation in its
`initialize` capabilities. A URL-only declaration does not count. If the client cannot
elicit, do not notify through this channel: record the channel entry with
`delivery_status: "failed"` and use another allowed channel, or let the request end as
`failed` with `terminal_reason: "delivery_failed"`.

Never expose approve or reject as a tool the model can call with a decision argument.
The model may ask the server to collect a decision; only the elicitation answer from the
client decides.

## Request

1. Persist the `ApprovalRequest` and its `ReviewSnapshot` before sending the
   elicitation, exactly as for any other channel.
2. Render the snapshot `content` (action type, target, complete arguments, risk, expiry,
   and policy summary) into the elicitation `message`. Include the snapshot
   `content_hash` so the answer can be bound to what was shown.
3. Request a single boolean field in `requestedSchema`, for example
   `{"type": "object", "properties": {"approve": {"type": "boolean"}}, "required": ["approve"]}`.
   Do not ask the person to type the decision as free text.
4. Add a `channels` entry with `channel: "mcp_elicitation"`, the hash of the client
   session identity as `target_hash`, and `delivery_status: "delivered"` once the client
   accepted the request for display.

## Answer mapping

| Elicitation result | Approval record |
|---|---|
| `accept` with `approve: true` | `decision: "approved"`, human actor, `human_present: true` |
| `accept` with `approve: false` | `decision: "rejected"`, human actor, `human_present: true` |
| `decline` from the person | `decision: "rejected"`, human actor, `human_present: true` |
| `cancel` | no decision; the request stays `pending` until another answer or expiry |
| client declined without showing the form | no decision; mark the channel `failed` |

A client that answers `decline` without presenting the form to a person has not
rejected anything. Recording it as a human rejection would let a client configuration
decide on the person's behalf. The schema therefore requires an approved or rejected
`mcp_elicitation` record to name a human actor who was present and authenticated through
`authenticated_session`, `channel_identity`, or `signed_callback`.

## Validation

The reference validator refuses an `mcp_elicitation` decision when the request has no
delivered `mcp_elicitation` channel entry, and the envelope schema requires a signature
on an approved high-risk action decided through this channel, as it does for email and
Telegram. Prefer the `web` channel with the WebAuthn profile for high-risk actions that
need independently attributable proof.

The answer must still pass every ordinary check: the request revision, nonce, action
hash, review content hash, policy evaluation ID, quorum, and separation of duties.
