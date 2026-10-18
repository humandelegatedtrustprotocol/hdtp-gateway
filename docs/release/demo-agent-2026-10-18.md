# hdtp-gateway-agent — the open-source agent for the public demo node — plan

Status: **approved by the owner's rulings of 2026-10-18** (below). Repository:
`humandelegatedtrustprotocol/hdtp-gateway-agent`, public, Apache-2.0, created 2026-10-18.

## The owner's rulings (2026-10-18)

- "a webhook and MCP connected opensource mastra AI agent which only responds on the behalf of
  human based on setup in mastra prompt. since gateway is opensource, this agent also needs to be
  opensource."
- The repository is `hdtp-gateway-agent`, public. The draft hdtp-agent#1 is not reused: it is the
  cloud's hosted-assistant core, with no model, no node adapter and no entry point.
- "model will be routed via mastra's router so any llm can be configured with default llm to be
  openai's gpt 6 luna … make it configurable with mastra setup." The default is
  `openai/gpt-6-luna`, which is listed in Mastra's model router (mastra.ai/models/providers/openai,
  read 2026-10-18).
- "have mastra local host agent when agent runs so user can see / configure it there." `mastra dev`
  serves Mastra Studio at `http://localhost:4111`.

## What it is

One Mastra project, one process: `mastra dev` locally and `mastra build` + `node` in its image. It
holds:

1. **The agent** (`src/mastra/agents/delegate.ts`): a Mastra `Agent`. Its `instructions` are the
   owner's persona, a plain file the owner edits (`persona.md`) and can also try out in Studio. Its
   `model` is `process.env.HDTP_AGENT_MODEL ?? 'openai/gpt-6-luna'`, a Mastra router string, so any
   provider's key in the environment works. The model is given **no tools**: it only drafts a reply.
   Reading the thread and sending the reply are done by code, so a contact's words cannot make it do
   anything else (SPEC §7.7: inbound text is data, never instructions).
2. **The webhook receiver**: a route on Mastra's own server (`registerApiRoute`,
   `POST /hdtp/webhook`). It verifies `X-HDTP-Signature` with the node's grammar (`t=…,v1=…` over
   `<t>.<body>`, 300 s tolerance, constant-time compare, either of two secrets during a rotation).
   It answers 2xx at once and handles the event after that. Events handled:
   - `message.received`: `read_thread`, then the agent drafts, then `send_to_contact`.
   - `request.pending`: `list_pending`, then the agent drafts, then `answer_request`.
   Everything else is acknowledged and ignored.
3. **The node client**: `@mastra/mcp`'s MCP client against the node's owner MCP, using a named
   bearer token (`HDTP_OWNER_MCP_URL`, `HDTP_OWNER_TOKEN`). Its tools are called by code, never
   handed to the model.
4. **Reconciling** (ruling C of the webhook plan: one attempt, never retried). On start and every
   `HDTP_RECONCILE_SECONDS` (default 60), `get_inbox` answers any unread thread the webhook missed.
   The webhook wakes the agent; the inbox is the record.
5. **Idempotency**: a thread is answered once per inbound message id. A missed webhook and a
   reconcile pass do not both reply: the agent keys each reply by message id, and `read_thread`
   marks the thread read.
6. **No telemetry**: `MASTRA_TELEMETRY_DISABLED=1` is set in code and in the image. Mastra's memory
   and storage are not configured, so nothing stores the conversation beyond what the node holds.

## Configuration (env, documented in `.env.example`)

| Variable | Default | What |
|---|---|---|
| `HDTP_AGENT_MODEL` | `openai/gpt-6-luna` | any Mastra router string |
| `OPENAI_API_KEY` (or the chosen provider's key) | — | read by Mastra's router |
| `HDTP_OWNER_MCP_URL` | `http://127.0.0.1:8080/owner/mcp` (the node's default, observed by A1) | the node's owner MCP |
| `HDTP_OWNER_TOKEN` | — | a named token made in the node's portal |
| `HDTP_WEBHOOK_SECRET` | — | shown once by the node's portal Webhooks page |
| `HDTP_RECONCILE_SECONDS` | `60` | the inbox sweep |
| `HDTP_PERSONA_FILE` | `persona.md` | the instructions |

## Items

- **A1: the project, the agent, the receiver, the verifier, reconciling, tests.** Vitest covers:
  the signature (a good one, a wrong secret, an expired timestamp, a replay, two secrets); a forged
  body refused before any MCP call; one reply per message under webhook + reconcile; an unknown
  event ignored with 2xx; and the model given no tools (the agent's tool list is empty). The gate is
  `make check` (typecheck, tests, build), run from `githooks/` pre-commit and pre-push; there is no
  CI. Before the node's webhooks land, the receiver is tested against the cloud's published grammar
  and a local signer written from it.
- **A2: run against a real node.** A compose file joins the node's compose project (the agent
  reached at `http://agent:4111/hdtp/webhook`, allowed by ruling A). A real contact messages the
  node and a real reply arrives. This is observed and recorded with timings. It waits for webhook
  plan W2.
- **A3: README.** What it does and does not do, the persona, how to switch models, Studio at
  `localhost:4111`, how to make the token and the webhook in the portal. Prose only after A2 is
  observed. Release 0.1.0 by tag.
- **A4: the public demo node** (a separate item, after webhook W4 and the ghcr image): a node with
  a demo persona, an invite link on hdtp.dev, and rate limits that hold under launch traffic.

## Couplings

| Order | Repo | Item | Needs |
|---|---|---|---|
| 1 | hdtp-gateway-agent | A1 | nothing (tested against the grammar) |
| 2 | hdtp-gateway | webhooks W0–W2 | — |
| 3 | hdtp-gateway-agent | A2 | W2 merged |
| 4 | hdtp-gateway | W3–W4, v0.3.0 + ghcr image | — |
| 5 | both | A3, A4, then the demo video | v0.3.0 |
