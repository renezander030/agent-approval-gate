# agent-approval-gate

**AI agents should draft. Code should validate. Humans should approve. Systems should dispatch.**

A minimal production pattern for adding approval gates to AI automation workflows. Use it when an agent wants to:

- send an email
- update a CRM record
- create a ticket
- modify a database row
- call an internal API
- trigger an n8n workflow

This repo is opinion + schemas + examples. It is not a framework. Drop the schemas into your own stack.

## The pattern

```
   ┌──────────────┐
   │   AI Agent   │   drafts a ProposedAction
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │   Schema     │   reject malformed drafts at the boundary
   │  Validation  │
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │   Approval   │   human (Telegram, Slack, email, web)
   │    Queue     │
   └──────┬───────┘
          │  ApprovalRecord
          ▼
   ┌──────────────┐
   │ Deterministic│   plain code dispatches the side effect
   │  Dispatcher  │
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │  Audit Log   │   what was proposed, by whom, approved by whom, dispatched when
   └──────────────┘
```

Five contracts:

1. **ProposedAction** — what the agent wants to do, fully serialized, no executable code.
2. **Schema validation** — every action type has a JSON Schema. Reject at the boundary.
3. **ApprovalRecord** — who approved, when, on what channel. Signed if the channel supports it.
4. **Dispatcher** — plain code (not the agent) executes the action. The agent never calls the side-effect API directly.
5. **Audit log** — append-only record linking proposal → approval → dispatch outcome.

If you skip any of the five, you don't have an approval gate — you have a model that can ship to production.

## Why this is different from "human-in-the-loop"

"Human-in-the-loop" usually means *the human reads what the model said and clicks OK*. That's not enough. Three failures show up the moment AI touches real customers:

- **Schema drift** — the agent emits a slightly different shape next week and your dispatcher silently does the wrong thing.
- **Dispatch coupling** — the agent itself calls the API, so an approval *step* exists but the model can also bypass it on the next run.
- **No audit** — you cannot answer "why did this email go out" three weeks later.

The five contracts above close all three.

## What's in this repo

```
agent-approval-gate/
├── README.md                                 — this file
├── schemas/
│   ├── proposed-action.schema.json           — the agent's draft
│   └── approval-record.schema.json           — the approval decision
├── examples/
│   ├── email-reply-approval.json             — example proposed action
│   └── n8n-approval-workflow.json            — importable n8n workflow
├── docs/
│   └── architecture.md                       — long-form rationale
└── LICENSE                                   — MIT
```

## Quick start

1. Read `docs/architecture.md` for the full pattern.
2. Adopt `schemas/proposed-action.schema.json` as the contract between your agent and your dispatcher. Reject drafts that don't validate.
3. Wire one approval channel (Telegram bot, Slack DM, n8n form, internal web UI). The example `examples/n8n-approval-workflow.json` shows the simplest version.
4. Append a log entry per proposal, per approval, per dispatch. Three rows minimum, not one.

## What this repo is NOT

- Not a framework. No SDK, no CLI, no daemon.
- Not coupled to one LLM, one orchestrator, or one approval channel.
- Not a turnkey solution for high-frequency dispatch. If your agent ships 10k actions/hour, this pattern is the *floor*, not the ceiling — bolt on rate limits, batching, and write-side tenancy.

## Related work

- [CLAUDE.md — 10 rules for Claude Code, edit-time and runtime](https://gist.github.com/renezander030/2898eb5f0100688f4197b5e493e156a2) — the runtime rules (#7 HITL, #8 schema validation) are the same discipline applied inside Claude Code.
- [Context7 v2 — enterprise GraphQL MCP pattern](https://gist.github.com/renezander030/83ad49aeffa5f8749325a2b19617823f) — what changes when an MCP server can write, not just read. Approval envelopes show up there too.
- [fixclaw](https://github.com/renezander030/fixclaw) — Go pipeline engine that enforces the runtime rules in production.

---

_This is part of **Production AI Automation Notes** — a series of repos and gists on shipping AI agents that touch real systems safely. Follow [@renezander030](https://github.com/renezander030) for the next entry._
