# n8n reference workflow

`examples/n8n-approval-workflow.json` demonstrates orchestration, not an in-Code-node
security boundary. Import it into n8n, assign Telegram credentials, and configure the
deployment-owned endpoints below.

## Required endpoints

### Validator

`POST $APPROVAL_VALIDATOR_URL/v3/validate`

Input: `{ "schema": "proposed-action.schema.json", "instance": { ... } }`

Output: `{ "valid": true, "instance": { ... }, "validation": { ... } }` or
`{ "valid": false, "validation": { ... }, "errors": [ ... ] }`. The validator
enforces Draft 2020-12, formats, the action-specific payload schema, size limits, and
the pinned release IDs. The returned validation object is a complete
`ValidationRecord`; the gate persists it before continuing or refusing.

### Gate

- `POST /v3/validations` durably records the validator's result for the exact action.
- `POST /v3/requests` persists policy and request state before notification.
- `POST /v3/review-snapshots` renders and persists the exact decision surface.
- `POST /v3/requests/{id}/resolve` verifies callback signature, nonce, tenant,
  action hash, review content hash, expiry, status, and expected revision in one
  transaction.
- `POST /v3/resolutions` stores and delivers the terminal decision receipt. Delivery
  retries reuse the same receipt and target hash.
- `POST /v3/requests/{id}/consume` changes one approved request to consumed and returns
  one short-lived dispatch grant. Duplicate consumption returns the original terminal
  identity or a conflict, never a new grant.
- `POST /v3/authority-snapshots` rechecks the approver, policy, workspace, and
  dispatcher immediately before provider invocation.

The raw callback nonce appears only in the signed review link. The durable request
stores its hash.

Version 3 endpoints emit `policy_evaluation_id` on every decision and `valid_until`
on authority snapshots. The dispatcher checks the consumed decision set and counts
quorum only over the exact effective action. Refusal endpoints may return no approving
records or authority snapshot; they never return a usable dispatch grant. Store each
retry or reconciliation with its `previous_dispatch_id`, retaining the initial consumed
dispatch identity. The workflow does not perform automatic provider retries.

### Audit sink

`POST $APPROVAL_AUDIT_URL/v3/events` accepts a redacted event intent. The sink assigns
sequence, previous hash, event hash, ingestion time, classification, and retention
under an append-only transaction. Do not let n8n clients choose sequence or hashes.

`POST $APPROVAL_AUDIT_URL/v3/snapshots` returns a complete export manifest after a
terminal event. Verify its event count, sequence bounds, event-set digest, and terminal
chain hash before archiving the run.

### Dispatcher

`POST $APPROVAL_DISPATCH_URL` requires both `Idempotency-Key` and a single-use
`X-Approval-Grant`. It revalidates and rehashes the effective action before using the
side-effect credential. It also requires the active authority snapshot ID returned by
the gate. Provider timeouts create `outcome_unknown`; reconciliation is read-only and a
blind retry is forbidden.

## Failure behavior

- Invalid proposal: persist the rejected validation, write `validation.rejected`, and
  do not create a request.
- Notification failure: mark the request failed and record the channel failure.
- Wait deadline: resolve to expired and write `dispatch.not_dispatched`.
- Bad, stale, duplicate, or cross-tenant callback: refuse and audit it.
- Review, hash, policy, separation-of-duties, or current-authority mismatch: refuse
  before dispatch.
- Resolution delivery failure: retry delivery of the same receipt only; do not repeat
  the decision or dispatch grant.
- Provider result lost: record unknown, reconcile, and do not retry automatically.
- Audit export mismatch: quarantine the export as incomplete.

The workflow's webhook responds immediately to proposal ingestion. The durable request,
not the original HTTP connection or an n8n execution's in-memory state, is the source
of truth for approval status.
