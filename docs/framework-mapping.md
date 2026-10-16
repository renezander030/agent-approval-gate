# Mapping agent frameworks onto the contracts

Agent frameworks expose approval as a pause: a tool call is held, a person answers,
and the run resumes. The contracts describe what has to be true around that pause.
This guide shows where each record is produced when the pause comes from a
framework, so the framework keeps its runtime and the deployment keeps the evidence.

The names below follow each project's public documentation; check the version you
run. None of them is required: any runtime that can hold a call and resume it with a
decision fits the same pattern.

## The pause, in contract terms

| Moment in the framework | Contract record | What the deployment does |
|---|---|---|
| A tool call is about to run and needs approval | `ProposedAction` | Serialize the complete call, its `call_id`, `effects`, and `idempotency_key`; hash it |
| The framework's own argument and policy checks pass | `ValidationRecord` | Record each required check against the action hash |
| The policy decides whether to ask | `ApprovalPolicySnapshot` | Record `outcome`, the `matched_rules`, and `evaluation_status` |
| The approval prompt is shown | `ReviewSnapshot` + `ApprovalRequest` | Persist both before any channel is notified |
| The person answers and the run resumes | `ApprovalRecord` + `ResolutionRecord` | Resolve the pending request once; retry only delivery of the resolution |
| The tool function runs | `AuthoritySnapshot` + `DispatchRecord` | Consume the request, check authority and the `target_precondition`, then invoke with the `execution_grant` and idempotency key |
| The run finishes or is abandoned | Audit events + `AuditSnapshot` | Append and export the hash-linked stream |

Resuming is not approving again. When a framework replays a tool node after a
crash or a resume, the dispatcher sees a consumed request and an existing
`DispatchRecord` for the same idempotency key: it reconciles the earlier outcome
instead of invoking the provider a second time. Durable checkpoints keep the run's
state; the contract keeps the side effect to one.

## Framework notes

**LangGraph.** `interrupt()` inside a node is the pause and `Command(resume=...)`
carries the decision. Create the `ProposedAction` and `ApprovalRequest` before
calling `interrupt()`, pass the `request_id` in the interrupt value, and resume only
with an answer that names the same request and review content hash. Treat a resumed
node as possibly re-executed: dispatch through the idempotency key, never directly
from the node body.

**OpenAI Agents SDK.** A tool with `needs_approval` produces an interruption on the
run result, and `RunState.approve()` or `RunState.reject()` answers it. Map the
interruption's tool call to the `ProposedAction` `call_id`, record the decision as
an `ApprovalRecord` before resuming, and keep the `ResolutionRecord` as what the
agent receives. Host shell and file tools map to the `shell.exec` and `file.write`
reference schemas.

**Vercel AI SDK.** A tool with `needsApproval` emits an approval request part and
waits for an approval response. Use the tool call ID as `call_id`, render the
`ReviewSnapshot` content in the approval UI, and pass the dispatch's
`execution_grant` to the tool's execute function so it can tell which approval
authorized it.

**Google ADK.** A tool's confirmation request (`require_confirmation` or
`tool_context.request_confirmation()`) is the pause. One confirmation is one
`ApprovalRequest`; a repeated confirmation for the same call resolves the existing
request instead of creating another one, and a consumed request never runs the tool
again.

**pydantic-ai.** A tool that requires approval returns deferred tool requests, and
the run continues with deferred tool results that carry the approvals. Record the
external policy decision as the `ApprovalPolicySnapshot` with `matched_rules`, so
the deferred call is bound to the rule that asked for a human.

**Mastra.** A tool with `requireApproval` suspends the run, and approving or
declining the tool call resumes it. Resolve the pending request with a
compare-and-set on its revision, so two concurrent approvals of one tool call cannot
both consume it.

**MCP.** Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`) map to `ProposedAction.effects` (`read_only`, `destructive`,
`idempotent`, `open_world`). An annotation the server does not send takes the
conservative value, as in the MCP specification. Decisions collected through
elicitation use the [`mcp_elicitation` profile](mcp-elicitation.md).

**Coding-agent hooks.** A pre-tool-use hook that answers allow, deny, or ask is a
policy evaluation: record it as the policy snapshot, and record a terminal prompt
the person answers as an `ApprovalRecord` on the `cli` channel. A hook or
classifier that fails or gives no verdict is `evaluation_status:
evaluator_unavailable`; the policy decides whether that denies or asks a human.

## Policies across frameworks

Write one policy and evaluate it outside the framework:

- `matched_rules` with deny > require_approval > auto_approve precedence, so a deny
  always wins and no matching rule is never permission;
- `human_required_effects` to require a human for destructive or open-world actions,
  whatever the rules say;
- `on_evaluator_unavailable` to choose between denying and asking a human when the
  evaluator cannot answer;
- standing grants for a person to pre-approve a bounded class of actions, with an
  expiry and a use ceiling, instead of an unbounded "approve all".
