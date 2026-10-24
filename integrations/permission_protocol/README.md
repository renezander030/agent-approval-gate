# Permission Protocol reference adapter

A held action can be decided in [Permission Protocol](https://permissionprotocol.com)
instead of a channel the gate's own platform controls. The approver signs in the
issuer's app, and the gate records the issuer's signed receipt as the approval's
`pp-receipt-ed25519` signature. Anyone holding the issuer's published key can then
check the approval offline, without trusting the platform that ran the gate.

`adapter.py` is a reference, not an SDK. It needs only the standard library and
`rfc8785`.

## Flow

```text
ProposedAction held -> ApprovalRequest pending at revision N
        |
        v
execute_request(proposal, request_id, N, action_hash)
        |   constraints.idempotencyKey =
        |   agent-approval-gate:<request_id>:<N>:<action_hash>
        v
submit(...)               POST /api/v1/execute           (human signs in PP)
fetch_artifact(...)       GET  /api/v1/receipts/<id>/artifact
fetch_key_set(...)        GET  /.well-known/permission-protocol/keys.json   (retain a copy)
        |
        v
approval_record(artifact, key_set, ...) -> ApprovalRecord with pp-receipt-ed25519
        |
        v
scripts/validate_contracts.py --record approval-record <file>
```

The issuer signs `idemKey` and the full request (`requestJson`) into the receipt, which
is what lets the validator tie the receipt to this request, its pending revision and
the effective `action_hash`. The contract rules are in
[`docs/contracts.md`](../../docs/contracts.md#permission-protocol-receipts).

## What is tested and what is not

- Tested here: the receipt verifier against the issuer's published vectors (including
  a live production receipt and a tampered one, in `tests/permission-protocol/`), and
  `approval_record` end to end: the generated
  [`examples/permission-protocol-approval-record.json`](../../examples/permission-protocol-approval-record.json)
  is built through it and passes the record check and a complete lifecycle envelope.
- Not yet exercised against a live tenant: the HTTP calls in `submit` and
  `fetch_artifact`. Their paths follow the issuer's public documentation; the response
  shapes may need adjusting on the first live run with a workspace API key.
- Receipts in `jcs_v3` (specified by the issuer, not yet issued) commit `idemKey`
  inside a salted request commitment. Supporting them means opening that commitment
  with the owner's salt, which this profile does not do yet.
