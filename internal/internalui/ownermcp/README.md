# internal/internalui/ownermcp

The owner's MCP server (SPEC §8.4, §8.5): the tools and `hdtp://` resources with which an owner's
agent runs the node under a bearer token, doing what the portal does for a person. It is stateless:
nothing is pushed, and what changes is waited for with `wait_for_updates`.

`internal/cli/compose.go` builds a new server for each request with `NewServerWithExtra` and mounts
it at `/owner/mcp`, outside the portal's session and CSRF layers. In front of it sit a body cap
(`OwnerMCPMaxBodyBytes`, 1 MiB) and `requireOwnerToken`, which validates the bearer with
`auth.TokenService.Validate` on every request and answers 401 for a missing token ("a bearer token
is required") or an invalid one ("that token is not valid", the same for unknown, malformed and
revoked). The package itself does not authenticate: it receives the `auth.Identity` the request's
token validated as, and decides per account what that identity may touch.

It calls the store, `internal/contacts` (the contact lifecycle shared with the portal:
`contacts.Owner`), `internal/messaging` (threads, the event bus, the send seam),
`internal/integrations` (agent-answered requests), `internal/core/policy` (Cedar:
`AllowOwnerManage`), and `internal/internalui/auth` (`Identity`, `PasskeyInfo`, `ErrLastPasskey`).
Its dependencies that live in the node arrive as callbacks in `Deps` and `Extra`, wired in
`internal/cli/compose.go` and `internal/cli/ownerextra.go`.

## What it holds

- `NewServerWithExtra(d Deps, e Extra, ident auth.Identity) *mcp.Server`: composes the surface for
  one identity. Declares tools and resources, and neither list-change notifications nor
  subscriptions.
- `Deps`: the store and the node callbacks the core tools act through (`Send`, `Approved`,
  `Rejected`, `Removed`, `Invalidate`, `ServedPermissions`, `RefreshContact`, `Audit`, `PublicURL`,
  `Pending`, `Msg`, `Bus`, `Contacts`).
- `Extra`: the dependencies of the parity tools. Each field that is nil leaves its tool
  unregistered. `AddContactResult`, `IntegrationView` are the shapes `AddContact` and `Integrations`
  return.
- `AddParityTools`, `AddWatchTools`: register those two groups on a server; `NewServerWithExtra`
  is their only caller in this repository.
- Argument types `AccountArg`, `AnswerArgs`, `ReadThreadArgs`, `SendArgs`, `PermissionsArgs`,
  `TrustArgs`, `PetnameArgs`, `RefreshArgs`, `ContactArgs`, `AddressArgs`, `InviteIDArgs`,
  `InviteArgs`, `WaitArgs`, `DigestArgs`: the JSON-schema inputs of the tools.
- Resource URIs `URIInbox`, `URIRequests`, `URIPending`, `URIThreadPrefix`; `WaitMaxSec`;
  `ErrNoCard`.

## Tools

Every tool that names an account first checks `policy.AllowOwnerManage` against the identity's
scope (the accounts where the owner holds `admin`, narrowed to `Identity.AccountID` when the token
has one). Exceptions are listed under "What it refuses".

Registered always (`NewServerWithExtra`):

| Tool | Contract |
|---|---|
| `list_accounts` | The account ids this identity administers. |
| `get_inbox` | Threads of an account with `unread` and `last_at`. |
| `read_thread` | A thread's messages oldest first, each labelled with the contact's trust flag; marks the thread read through the newest message returned. |
| `send_to_contact` | Sends a message as sender `agent` (origin fixed to the owner MCP, never a parameter), through `Deps.Send` or, with none, records only. `thread_id` empty starts a thread; `topic` is for a new thread. |
| `list_contacts` | Contacts as `contactView` (named fields only); a waiting request carries `address_claim` when its address belongs, or lately belonged, to another contact. |
| `approve_contact`, `reject_contact`, `block_contact`, `unblock_contact`, `remove_contact` | The contact lifecycle through `contacts.Owner`, the portal's own. Each answers the `contacts.Decision` (status afterwards; whether the peer was told) and writes the portal's audit action (`contact_approve`, `contact_reject`, `contact_block`, `contact_unblock`, `contact_remove`) under `account:<id> contact:<fpr>`. `approve_contact` takes an optional `preset`. |
| `list_pending_addresses` | Contacts held at a new address for the owner's decision. |
| `approve_address`, `reject_address` | Decide such a contact by its root; audited as `contact_address_approve` / `contact_address_reject`. |
| `set_permissions` | Replaces a contact's whole grant, then drops the caller's composed server (`Invalidate`). |
| `rename_contact` | Sets the owner's local name for a contact; empty clears it. |
| `refresh_contact` | Registered only when `Deps.RefreshContact` is set. Re-fetches one contact's card; answers `outcome` and `why`. |
| `set_trust_flag` | `messages_only` or `may_instruct`; audited as `trust_update`. |
| `create_invite` | Mints an invite; answers `id`, `url` (the link, which holds the token) and `expires_at`. The token is shown only in that link. |
| `list_invites`, `revoke_invite` | Invites of one account (never the token); revoke scoped by the account. `revoke_invite` is audited as `invite_revoke`. |
| `list_pending`, `answer_request` | Open agent-answered requests (SPEC §6.8) and the answer that the node relays to the waiting caller. |

Registered by `AddParityTools`, each only when its `Extra` field is non-nil:

| Tool | Field | Contract |
|---|---|---|
| `export_card` | `Card` | The account's current card with the facts the owner reads it by. |
| `identity_certificate` | `Certificate` | Certificate state: root, chain, served leaf and dates, renewal due, pending CSR. |
| `list_passkeys`, `remove_passkey` | `Passkeys`, `RemovePasskey` | List passkeys; remove one by id. There is no register tool: a token cannot perform a WebAuthn ceremony (SPEC §8.6). |
| `call_contact` | `CallContact` | One call to a tool on an **active** contact's server, through the node's outbound path; the contact's own switchboard still applies. |
| `list_integrations` | `Integrations` | Connected upstreams and what each exposes; no credential, endpoint secret or raw schema. |
| `set_exposure` | `SetExposure` | Republishes which tools of an integration are exposed; an empty list withdraws it. |
| `add_contact` | `AddContact` | Reaches out: redeems an invite link, or requests contact with a card; lands `pending_out` or `active`. Exactly one of `invite_url` and `card`. |
| `audit_query` | `Audit` | The audit trail for the accounts the identity administers; `actor` filter; `limit` default 100, and any value over 1000 or not above 0 becomes 100. |

Registered by `AddWatchTools`:

| Tool | Contract |
|---|---|
| `wait_for_updates` | Blocks until something changes for the account and answers what moved since the caller's cursor. With `since` omitted it answers at once with a cursor and no backlog. `timeout_sec` is whole seconds from 1 to `WaitMaxSec` (25), which is also the default. The answer carries `threads`, `contact_requests`, `pending_requests`, `pending_addresses`, `calls`, `needs_attention`, `calls_truncated`, `cursor_expired` and `timed_out`. |
| `digest` | Per contact in a window (default the last 24 hours): messages in and out, unread, whether their word was last, plus the three queue counts. |

Resources: `hdtp://inbox` (unread count per administered account), `hdtp://requests` (contacts in
`pending_in` across them), `hdtp://pending` (open agent-answered requests across them), and the
template `hdtp://thread/{id}` (one thread and its messages, found among the administered accounts).

## What it refuses, and how

Three shapes of refusal exist; a caller must not treat them alike.

1. Tool error with a code (`IsError` true). `deny()` answers `{"code":"permission_denied"}` when
   the identity may not act on the named account (for an account it does not administer, and for
   one outside a narrowed token, alike). `refused(err)` answers `{"code","detail"}` for the
   lifecycle and permission tools: `unknown_contact` (`contacts.ErrUnknownContact`), `conflict`
   (`ErrWrongState`), `bad_request` (`ErrBadRequest`), `payment_required` (`ErrContactCap`),
   `internal` otherwise. Also: `create_invite` answers `unavailable` when the node has no public
   address ("set public_url") and mints nothing; `revoke_invite` answers `not_found` only for a
   missing or spent invite (a store failure is `internal`); `wait_for_updates` answers
   `bad_request` for a `timeout_sec` outside 1 to 25; `answer_request` answers the relay error's
   text.
2. A result that carries a code but is not marked an error (`IsError` false): `call_contact`
   (`bad_request` for an empty contact or tool; `unknown_contact` when the contact is not active;
   `unavailable` when the call failed), `remove_passkey` (`bad_request` for an empty id and for the
   last passkey), `set_exposure` (`bad_request`), `add_contact` (`bad_request`, including for both
   or neither of `invite_url` and `card`), and `answer_request` when dispatch is not enabled
   (`{"error":"agent-answered dispatch is not enabled"}`). The audit middleware records these as
   `ok`, because it reads only `IsError`.
3. A returned error (no code): store failures, `rename_contact` over the display-name limit
   (`contacts.MaxDisplayName`), `set_trust_flag` with a value other than the two (`bad_request:
   trust must be messages_only|may_instruct`), and `read_thread` or `send_to_contact` failing.

Account scope is not checked by `list_accounts` (it is the scope), `list_passkeys` and
`remove_passkey` (passkeys belong to the node, not an account): these three answer any identity
with a valid token, narrowed or not. `audit_query` checks scope per row instead: a row with no
account is shown only to an identity without a narrowing.

`set_permissions` refuses an unknown contact (`unknown_contact`) and any permission the account
does not offer (`contacts.Offered`: the core permissions, those the account's surface serves, and
those the contact already holds) with `bad_request`, rather than dropping it and answering ok.

## Invariants

- Every `tools/call` is audited, reads and refusals included, when `Extra.Log` is set: one
  `owner_mcp_call` row with resource `tool:<name>` and outcome `ok`, `refused` (`IsError`) or
  `error` (a returned error). Held by `TestEveryOwnerMCPCallIsAudited`.
- A token narrowed to one account cannot see or act on another's. Held by
  `TestTokenAccountScopingEnforced`, `TestAuditQueryNeverLeavesTheIdentitysAccounts`,
  `TestScopedTokenCannotReadNodeLevelAuditRows`.
- `set_exposure` hands the account and the integration id to `Extra.SetExposure` and reports its
  refusal as `bad_request`; the check that the integration belongs to the account is the
  callback's (`internal/cli/ownerextra.go`). `TestSetExposureCannotReachAnotherAccountsIntegration`
  holds the tool's side of this against a stub callback that refuses.
- The sender label is fixed by the surface: `send_to_contact` stores `agent`. Held by
  `TestSendToContactStoresAgentLabel`.
- An approval reaches the caller's live composed server (`Invalidate`). Held by
  `TestOwnerMCPApprovalReconcilesTheCallersServer`.
- The surface declares no list-change or subscription capability. Held by
  `TestTheOwnerSurfaceOffersNoSubscriptionsAndAMessageIsReadable`.
- `read_thread` marks read only through what it returned. Held by
  `TestReadThreadMarksTheThreadReadThroughWhatItReturned`.
- A cursor older than the change log, or past its newest change, is said to be expired. Held by
  `TestACursorOlderThanTheLogIsSaidToBe`, `TestACursorPastTheLogIsSaidToBe`; a change made by
  another process wakes a wait: `TestAWaitWakesForAChangeAnotherProcessMade`; the number of rows
  a wake reads does not grow with the contact list: `TestAWakeReadsTheSameRowsAt1And300And2000Contacts`.
- The change feed labels a thread whose contact row is gone `messages_only`. Held by
  `TestFeedFailsSafeOnAMissingContactRow`.
- Answers project named fields, not store rows. Held by `TestListContactsAnswersNamedFieldsOnly`.
- A full contact list is `payment_required`. Held by `TestAFullContactListIsPaymentRequiredToTheOwnerMCP`.
- The portal and the owner MCP stay one authority in two shapes: the tool names the spec lists,
  each with a portal affordance or a stated reason it has none. Held, in `internal/internalui`, by
  `TestEveryAgentCapabilityHasAPortalAffordance`,
  `TestEveryContactAndInviteDecisionAPersonMakesAnAgentCanMake` and
  `TestSpecNamesEveryOwnerToolOnce`.

## Held by

`server_test.go` (tools, scoping, labels, the wait and the feed), `parity_test.go` (audit,
integrations, exposure, certificate), `lifecycle_test.go` (the contact lifecycle,
`set_permissions`, invites), `address_test.go`, `claim_test.go`, `pending_test.go`,
`review_test.go`, `revoke_failure_test.go`, `contactcap_test.go`, `wait_test.go`, `wake_test.go`.

## What it does not do

- It does not authenticate. A request with no valid bearer never reaches it; `requireOwnerToken`
  in `internal/cli` is the only gate, and the bearer is checked on every request, so revocation
  takes effect on the next one.
- It does not push. There are no notifications and no subscriptions; `wait_for_updates` is a poll
  with a bound of `WaitMaxSec` seconds, and the bus only tells it to look. The store's change log
  says what moved.
- It does not register passkeys, and cannot (SPEC §8.6).
- It does not decide what to do about a message. `wait_for_updates` and `digest` report and label;
  the labels carry the owner's trust flag, and message bodies are untrusted peer content, which is
  why the feed omits them (read them with `read_thread`).
- It does not return `ErrNoCard`: nothing in this repository returns or tests it.
- It does not give a tool its own path to the wire. `call_contact` and `send_to_contact` use the
  node's outbound functions handed in through `Extra` and `Deps`.
