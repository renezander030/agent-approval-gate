# n8n reference workflow

`examples/n8n-approval-workflow.json` demonstrates orchestration, not an in-Code-node
security boundary. Import it into n8n, assign Telegram credentials, and configure the
deployment-owned endpoints below.

## Required endpoints

### Validator

`POST $APPROVAL_VALIDATOR_URL/v1/validate`

Input: `{ "schema": "proposed-action.schema.json", "instance": { ... } }`

Output: `{ "valid": true, "instance": { ... } }` or
`{ "valid": false, "errors": [ ... ] }`. The validator enforces Draft 2020-12,
formats, the action-specific payload schema, size limits, and the pinned release IDs.

### Gate

- `POST /v1/requests` persists policy and request state before notification.
- `POST /v1/requests/{id}/resolve` verifies callback signature, nonce, tenant,
  action hash, expiry, status, and expected revision in one transaction.
- `POST /v1/requests/{id}/consume` changes one approved request to consumed and returns
  one short-lived dispatch grant. Duplicate consumption returns the original terminal
  identity or a conflict, never a new grant.

The raw callback nonce appears only in the signed review link. The durable request
stores its hash.

### Audit sink

`POST $APPROVAL_AUDIT_URL/v1/events` accepts a redacted event intent. The sink assigns
sequence, previous hash, event hash, ingestion time, classification, and retention
under an append-only transaction. Do not let n8n clients choose sequence or hashes.

### Dispatcher

`POST $APPROVAL_DISPATCH_URL` requires both `Idempotency-Key` and a single-use
`X-Approval-Grant`. It revalidates and rehashes the effective action before using the
side-effect credential. Provider timeouts create `outcome_unknown`; reconciliation is
read-only and a blind retry is forbidden.

## Failure behavior

- Invalid proposal: write `validation.rejected`; do not create a request.
- Notification failure: mark the request failed and record the channel failure.
- Wait deadline: resolve to expired and write `dispatch.not_dispatched`.
- Bad, stale, duplicate, or cross-tenant callback: refuse and audit it.
- Hash or policy mismatch: refuse before dispatch.
- Provider result lost: record unknown, reconcile, and do not retry automatically.

The workflow's webhook responds immediately to proposal ingestion. The durable request,
not the original HTTP connection or an n8n execution's in-memory state, is the source
of truth for approval status.
