# The agent sits between: replies to the other party, asks its owner when needed — plan


Status: **approved 2026-10-19 with A2UI** as the component standard (the owner's pick). The Z2 migration and any
Z4 dependency still need the owner at their prompts. Probe first (rule 4).
Owner's order (2026-10-19, answering how video 2 should end): "We need agent to prepare responses for
human. Like if the conversation needs human, agent will create options for human to choose with last
option as message so experience for human will be effective. A message can be sent to other party as
reply and a message for owner as ask. Agent sits in between so this ask is something should come when
needed and rest reply to other party".

## What exists (read 2026-10-19, node branch fix/pre-release-2026-10-19)

- The owner MCP has no way for an agent to ask its owner anything. Its tools are sends, reads,
  contacts, invites, and `list_pending` / `answer_request` (the agent answers a peer's request). The bus
  has `attention` ("a condition only the owner can clear"), but no tool raises one.
- The agent always sends a reply (agent#34). It cannot ask, and it cannot stay silent.

## Feasibility (Reality first, rule 4)

- **The existing standard:** the portal is the owner's surface. A message the owner sends from it is
  labelled human (SPEC §7.1). An ask belongs in the same thread, next to the messages it is about.
- **The simplest option:** the agent gives the owner **ready replies**. Choosing one sends it to the
  contact as the owner's own message, labelled human, through the portal's existing send path
  (rule 1). The last choice is "write my own". No answer has to travel back to the agent: it reads the
  owner's message in the thread, as it does today.
- **The cheap probe, before building:** with the model as it is, does a structured output
  (`reply` | `ask` | `none`) come back valid on the default model for the six-turn story? Measure it
  over 10 runs of the real persona prompts, with no node. Build after it passes.

## Placement

Both repositories. The node holds the ask, because the owner answers it in the portal and it must
survive an agent restart. The agent decides when to ask. HDTP's wire is untouched: asks never leave the
node.

## The owner's note on the plan (2026-10-19)

"use dynamic component library which responds in text which an llm can understand".

- An ask is no longer a fixed card. The agent composes it from a **catalog of components**, and the
  portal renders those natively.
- Whatever the owner does is turned into **plain text** that the agent reads, for example: `Ana chose:
  "Confirm Wed 15:00, 30 min, budget first"`, or `Ana wrote: "..."`.
- **The standard to follow (read 2026-10-19): Google's A2UI** (Agent-to-User Interface, Apache-2.0,
  a2ui.org, v0.9.1 current, v1.0 a release candidate).
  - The agent emits JSON messages: createSurface, updateComponents, updateDataModel.
  - It may request only the components in the client's trusted catalog (examples: Text, Button,
    DateTimeInput).
  - It is a protocol, not one app's component set. That fits HDTP: any agent can ask any node's
    portal.
  - The other option is Vercel's json-render (catalog defined in Zod, React renderer). It is a library
    tied to one app, not a protocol.
- **The node's catalog, the narrowest that serves the story:** Text, Button (the ready replies, one
  tap each; see Round 2 below), TextField (the "write my own", always last), DateTimeInput, and
  ChoicePicker for picking one of a list.
  - The portal renders them itself: a small renderer, with no new dependency unless the owner wants
    A2UI's own package (zone Z4).
  - The node validates every A2UI message against the catalog before storing it (rule 11), and refuses
    an unknown component or an oversize payload by code.
- **The answer:** the action and the data model at submit are turned into one text line by the node,
  in one place (rule 1). It is stored on the ask and given to the agent. A chosen ready reply is also
  sent to the contact as the owner's message, labelled human.

## Items

### N1. Node: owner asks (hdtp-gateway; migration = zone Z2, owner approves)

- A store table `owner_asks`: id, account, thread, for_msg_id, question, options (1–3 ready replies),
  status (open / answered / withdrawn / expired), answer, created_at, expires_at. Through sqlc only.
- Owner MCP tool `ask_owner(thread_id, for_message_id, question, options[])`:
  - It is idempotent on for_message_id.
  - Refusals: an unknown thread → not_found; bad option counts or sizes → invalid; an open ask
    already on the thread → conflict (rule 3).
- **Portal:** the thread shows the open ask as a card: the question, one button per ready reply, and a
  last "Write my own" box.
  - A button sends that text as the owner's message (labelled human) and marks the ask answered.
  - Any message the owner sends on that thread also answers it.
- **Expiry (rule 8):** an ask expires after 24 h, and the agent can withdraw it. An expired ask is
  shown as expired, never as open.
- **Bus and webhook:** an `ask` event, so the portal's open page updates (rule 5).
- **Audit (rule 7):** `ask.created`, `ask.answered`, `ask.expired`, one row each, in the service.
- **SPEC:** §8.4 gains the tool; §7.1 states that a chosen ready reply is the owner's message.

### A1. Agent: reply, ask or nothing (hdtp-gateway-agent; fixes agent#34)

- The model returns one of:
  - `reply` (text to the contact);
  - `ask` (a question for the owner, plus 1–3 ready replies);
  - `none` (nothing is needed: an acknowledgement or a sign-off).
- The output is checked by a schema. A malformed output is refused by code and retried, as an empty
  draft is today.
- The persona says when to ask, for example: a commitment, anything outside the owner's limits, the
  final yes.
- After an ask, the agent does not reply on that thread until the owner has acted (the ask is
  answered or expired). `none` counts as answered and is not retried.
- Tests:
  - a sign-off gives `none`, with no send and no retry;
  - a commitment gives `ask`, with no send to the contact;
  - the owner's chosen reply arrives, and the agent carries on.

### V2. Video 2, on N1 + A1

1. Ben (human) asks.
2. Ana's agent proposes.
3. Ben's agent counters.
4. Ana's agent settles. The final yes is Ana's, so her agent ASKS her, with ready replies.
5. Ana taps one, and it is sent as Ana.
6. Ben's agent confirms for Ben (within his limits).
7. Ana's agent: `none`. It ends.

## Couplings and merge order

| Order | Repo | Item | Needs |
|---|---|---|---|
| 1 | hdtp-gateway | #228 (pre-release) | review re-pass |
| 2 | hdtp-gateway | N1 | #228; the owner's Z2 approval for the migration |
| 3 | hdtp-gateway-agent | #23, #27 | #228 |
| 4 | hdtp-gateway-agent | A1 | N1 (the tool), the probe passed |
| 5 | video | V2 | N1 + A1 built (recorded from the branches) |

## Rules walked

- 1: the portal's existing send path.
- 3: the refusals above.
- 4: the owner MCP's existing bearer scope.
- 5: the ask event and its reader.
- 7: the audit rows.
- 8: the expiry.

## Extended for the use-case series (2026-10-19)

See docs/release/usecase-videos-2026-10-19.md.
- N1 adds: a TLDR line and key terms leading every ask (catalog: Text, KeyValue); a portal "Needs you"
  page listing open asks across threads; done-for-you TLDR **notices** (no buttons).
- A1 adds: the `notify` turn; autonomy per topic in the instructions (ask before committing, or
  commit within limits and notify).

## Aligned with A2UI v0.9.1's basic catalog (team-lead, 2026-10-19)

"we need to use A2UI in these demos" (the owner): the node speaks the specification, not look-alike
names. Read from google/A2UI `specification/v0_9_1` (the protocol document, `common_types.json`,
`catalogs/basic/catalog.json`).

- **The catalog** is the node's own, as A2UI provides for, named
  `https://hdtp.dev/a2ui/v0_9_1/catalogs/owner/catalog.json` in `createSurface.catalogId` (an
  identifier; nothing is served there). Its definitions are the tool schema's `$defs`. It holds six of
  the basic catalog's components under their names and property shapes, narrowed, and one of its
  own; a test validates every surface the node takes against A2UI's own v0.9.1 message schema
  (copied from google/A2UI) in a catalog of the basic components plus this KeyValue:

  | Component | From | The node's narrowing |
  |---|---|---|
  | `Column` | basic | the root only, listed first; `children` an array of ids (no template) |
  | `Text` | basic | `text` a literal string; the root's first child is the TLDR, listed second |
  | `ChoicePicker` | basic | `variant` `mutuallyExclusive`; 1–3 `options` `{label, value}`; `value` a `{path}` |
  | `TextField` | basic | `label` a literal; `value` a `{path}`; `variant` `shortText` or `longText` |
  | `DateTimeInput` | basic | `value` a `{path}`; `min`, `max`, `label` literals |
  | `Button` | basic | `child` a Text; `action.event` only, its `context` literals or `{path}`; a ready reply's event is `reply`, its context `{reply: "<text>"}` |
  | `KeyValue` | the node's | `items` `[{label, value}]`, 1–8: the key terms under the TLDR |

  No function calls, `checks`, `weight`, `accessibility` or `theme`: the portal implements none of
  them, so the schema does not offer them.
- **The data model:** every input binds its `value` to a path (an absolute JSON Pointer). A surface
  may carry a third message, `updateDataModel` for the same surface, with no `path` (the whole model)
  and an object `value`: the inputs' starting values. Bounded by the surface's 16 KiB and a depth of 4.
- **The answer** is the spec's client-to-server `action`: pressing a Button resolves its context (each
  `{path}` read from the card's data model) and the portal posts `{"version":"v0.9.1","action":{name,
  surfaceId, sourceComponentId, timestamp, context}}` as the `message` field of `POST
  /asks/{id}/answer`. The node checks it against the stored Button (its literals exactly; each bound
  value against the input bound to that path) and makes the one line, in one function:
  0. a ready reply's Button (event `reply`): its text is sent: `Ana chose: "…"`;
  1. a non-empty TextField value is sent to the contact as the owner's message: `Ana wrote: "…"`;
  2. else one chosen ChoicePicker value: its option's label is sent: `Ana chose: "…"`;
  3. else a DateTimeInput value: nothing is sent: `Ana picked: …`;
  4. else, a Button whose context binds nothing: nothing is sent: `Ana pressed: "<its label>"`;
  5. a Button whose bound values are all empty is refused (`bad_request`, nothing chosen or written).
- **What answers:** an ask holds at least one Button. An input alone answers nothing (A2UI sends on an
  action, never on a keystroke). A notice holds no Button and no input. The TextField, the "write my
  own", is the last input under the root (Buttons may follow it); each input binds its own path, and
  every `{path}` in a Button's context is one an input binds.
- **list_asks** gains `thread_id` (and `GET /api/asks` `thread`): the agent's "is an ask open on this
  thread" is `list_asks {thread_id, status: "open"}`.
- **What the owner does:** a ready reply is two taps now, the reply and then the Button that sends
  it, where the first card sent on the first tap: A2UI writes a selection to the data model and sends
  nothing until an action. One tap remains for a Button that reads nothing (`Ana pressed: "Approve"`),
  which sends nothing to the contact.

### Round 2 (2026-10-19, after the agent's probe)

- **One tap.** The two taps above are superseded: each ready reply is its own Button whose event is
  `reply` and whose context is the reply's text as a literal (`{"reply": "Confirm Wed 15:00"}`), so a
  tap posts that text, sends it to the contact as the owner's message and answers the ask in one
  step. "Write my own" stays a TextField and its Send Button. ChoicePicker stays in the catalog
  (mutually exclusive, picked and then sent); an agent's ready replies are Buttons.
- **The order in the schema.** The tool schema states what JSON Schema can: `prefixItems` puts the
  root Column first and a Text second, `contains`/`maxContains` bound the Columns (1), the
  ChoicePickers and TextFields of an ask (1 each) and its reply Buttons (3), and an ask contains a
  Button. That the second component is the root's first child, and the references between
  components, are checked by the node alone. `$schema` names draft 2020-12.
- **Newest first.** `list_asks` and `GET /api/asks` list newest first in every filter, so the limit of
  100 keeps the newest; the conversation reverses them to place the cards among its messages.
