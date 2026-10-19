# Changelog

Notable changes to hdtp-gateway. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project will use
[semantic versioning](https://semver.org/spec/v2.0.0.html) from its first release.

The first release is 0.1.0. The per-change record before it — every task, every defect,
how each was proved — is in [`PLAN.md`](PLAN.md), which is more detailed than a
changelog can be and is not summarized into a fictional release history.

## [Unreleased]

### Changed

- The pre-push hook needs the sibling checkouts its guards read: batondeck (the cloud's
  conformance battery and fixtures), hdtp-identity and hdtp-spec. It sets
  `HDTP_REQUIRE_SIBLINGS=1`, and a guard whose checkout is not found fails where it skipped; under a
  bare `go test` it still skips, which shows only under `-v`, and a bare `make check` lists, one
  line each, every comparison a missing checkout leaves unmade (`dependents`). Each checkout is found by
  `HDTP_BATONDECK_DIR`, `HDTP_IDENTITY_DIR` or `HDTP_SPEC_DIR`, else beside this checkout, else
  beside the main checkout of a worktree (`scripts/sibling.sh`, `testid.SiblingDir`). A push
  without one is refused before the gate runs, naming each checkout missing; a contributor without
  access to one (batondeck is private) sets `HDTP_ALLOW_MISSING_SIBLINGS=1`, and the hook prints
  first, one line each, the comparisons that will not run, then runs the gate without them.

### Fixed

- A ticked box on the portal's Settings page saved as false, so **Accept LAN connections** could
  not be turned on there (#221): the box posts `1`, and the save stored `true` only for a posted
  `true`. Every boolean knob is now read by one rule, `core.SettingTrue` (`true` or `1`), from the
  environment, the store and the portal alike.
- After a crash or a `docker restart` of the node, the compose portal answered nothing until its
  forwarder was restarted by hand (#204): a restart Compose does not make kept the forwarder in the
  node's old network. The forwarder now shares the node's processes as well (`pid:
  "service:hdtp-gateway"`, with `cap_drop: [ALL]`), so it stops with the node and its restart policy
  brings it back; the portal answered 0.5 s after either.
- `GET /api/invites` sent the stored invite rows, each invite's token hash included (#210). It
  now sends the fields the Invites page reads and no others.

### Removed

- The live-only portal scripts under `web/tools/` (`portal-live.mjs`, `portal-oauth-live.mjs`,
  `portal-oauth-probe.mjs`, `portal-invite-flow.mjs`, `preset-live.mjs`, `trust-live.mjs`, their
  helpers `portal-login.mjs` and `mcp.mjs`, and `agent-loop.mjs`), and with them the portal's
  `puppeteer-core` dependency. No gate, target or document ran them; the harness and
  `make screenshots` drive a real Chrome against a node.

## [0.2.0] — 2026-10-16

### Added

- The `edge` tunnel adapter, for a sidecar that terminates TLS and that the node does not run
  itself (ngrok's agent in the `ngrok` compose profile, a quick tunnel, any terminating proxy): the
  node starts nothing, runs in edge mode, and trusts no forwarded header, so its per-source limits
  see the sidecar's address. The portal lists it with the other adapters (#171).
- The limits sidecar as a release asset: `make dist` builds `hdtp-limitd_<version>_<os>_<arch>`
  for the four platforms beside the node's binaries, from the vendored crates (Linux in the
  Dockerfile's `rust:1.92-alpine` image, statically linked; macOS natively with the same Rust's
  darwin targets), and `SHA256SUMS` covers both. A release is two binaries per platform, the node
  and its sidecar, or one Docker image built from the checkout.
- `hdtp-gateway ingress unpair -subdomain <s>` forgets one pairing in the running ingress, over its
  admin socket, and closes the node's open data-plane sessions for it: the name routes nowhere until
  it is paired again, and its data-plane secret no longer logs in.
  The ingress audits it `ingress_unpair subdomain:<s>`. Nothing could remove a pairing before.

### Changed

- hdtp-identity 0.8.4, from 0.8.3; the node implements HDTP 1.0.1. An import whose threads.csv
  header equals the longer header only once its fields are joined (a NUL where one of its commas
  was) is refused naming both headers, as every other wrong header already was; it named the
  longer one. An envelope, header or plaintext with a member whose name holds a comma is refused
  with the same code as before, the library's reason now naming the wrong set of members. 0.8.4's `decide` no longer returns a `seen` effect for a call from a held address whose
  `thread_id` is of neither form; the node never applied that effect there (`seen` is left to the
  replay record, which that path does not reach), so its answers do not change. A caller at the
  pending tier was already refused `pending_approval` for a tool it cannot see or that does not
  exist, as 1.0.1 requires.
- `/healthz` answers a stopped limits sidecar with one fixed sentence, `not serving: the limits
  sidecar is not answering, so every sealed call is refused unavailable`. It carried the probe's
  error, the socket's path and the dial's error text, to a caller that needs no session (#127);
  `doctor`, the `serve` banner and `healthcheck --limits` still name the socket and why.
- The ingress's `POST /pair` answers every refusal with a JSON body holding the code alone
  (`{"code":"conflict"}`), served as `application/json`. A subdomain paired to another node is
  `409 conflict`; a pairing the registry could not record (the file registry's write failed) is
  `503 unavailable`, where it was a 409 whose body carried the error's text inside a JSON string
  and was not valid JSON when that text held a quote (a subdomain's name always did).
- A plaintext `tools/call` with no identity — no chain that validated, no envelope — is answered
  `identity_required` whatever the tool and whatever the seal policy, and audited as the gate's one
  `identity_gate` row, as SPEC.md §5.8 says and BatonDeck answers (#170). A tool outside the guest
  view was answered `blocked_or_unknown`, and under `seal: optional` a guest tool was served.
- A sealed call is charged before the pin's moves its open decided are applied — a newer leaf, a
  new address and the former one, an address parked for the owner and the owner's event — so a
  call the budget refuses changes none of them, as BatonDeck refuses it (#186). They were applied
  inside the open, before the budget was asked. A replay answered from its record now applies none
  of them either.
- A sealed call refused for its `thread_id` checks the tool's permission first: a contact the tool is
  not granted to is told `permission_denied`, audited as that denial, as over a client certificate
  and as BatonDeck answers (#139). It was told `bad_request`.
- A public tool reads each argument by its exact name, as the `thread_id` check and BatonDeck read
  them (#138). `Thread_ID` or `THREAD_ID` is ignored; it was matched to `thread_id` without regard
  to case after the check had passed, so a call joined a thread the check never saw, or was
  refused `bad_request` by messaging, which a sealed retry of the same envelope then replayed.

### Removed

- The `ngrok-https` tunnel adapter. It wrapped the decrypted HTTP ngrok handed it in the node's own
  TLS, so it served nothing (#167). A node whose settings or environment still name it refuses to
  start with `tunnel "ngrok-https" is not a registered adapter`; choose `edge` with the `ngrok`
  compose profile instead. A node whose portal saved it stops before the portal serves, so the
  portal cannot change it: set `HDTP_TUNNEL=edge` in the environment, which wins over the stored
  selection, and the node starts.
- `HDTP_MODE` and the config file's `mode` key: the deployment mode is derived from the tunnel
  adapter and was never meant to be declared (SPEC.md §10.1). A node whose environment sets
  `HDTP_MODE`, to any value, refuses to start (`invalid_enum_value: HDTP_MODE is not read: the mode
  is derived from the tunnel adapter; set HDTP_TUNNEL=edge (or the portal's tunnel setting)`), and a
  config file with a `mode` key is refused (`unknown field "mode"`). For a node that set
  `HDTP_MODE=edge` beside a sidecar, set `HDTP_TUNNEL=edge` (or choose `edge` in the portal)
  instead (#171). The refusals `edge_mode_forces_seal_required` and
  `edge_mode_forces_client_cert_off` went with it: nothing can put a node in edge mode without
  forcing both knobs.
- The portal's `GET /api/inbox`, `GET /api/thread` and `POST /thread/send`, which nothing in the
  portal called (the conversation view reads `GET /api/conversations`, marks read with
  `POST /messages/read` and sends with `POST /messages/send`). `GET /api/thread` sent the stored
  message rows as they are, and `POST /thread/send` sent into a thread whose id the caller chose.
  They answer 404 (the two reads) and 405 (the send); `POST /thread/delete` and `GET /events` stay.
- `POST /owners/tokens/create`'s fallback for a request with no owner, which minted the token for
  the node's first owner. The session gate refuses such a request first, so no composed portal
  reached it; the route now answers it 401 `identity_required` and mints nothing.
### Fixed

- The owner MCP's `read_thread` answers a thread the identity does not hold `not_found`, as
  `delete_thread` does and as the cloud's conversation read answers 404; it answered an empty list.
  A thread that could not be read is `internal`.
- The owner MCP's `hdtp://inbox`, `hdtp://requests` and `hdtp://pending` resources fail with
  "internal: …" when an identity's list or unread count cannot be read, where they skipped that
  identity (or counted its unread as 0) and answered the rest; `hdtp://thread/<id>` fails the same
  way when the thread cannot be read, and with "not_found: …" for a thread no identity of the scope
  holds, where both were "ownermcp: no such thread".
- The owner MCP's `wait_for_updates`, `digest`, `list_integrations` and `get_inbox` answer
  `internal` when a count, a list, a thread or the contact behind a call they read cannot be read.
  They read each failure as nothing — no integration needing attention, no request or address
  waiting, a thread's unread 0, a thread's messages skipped, a contact's call skipped as if the
  contact were removed, nothing exposed — so a wait could park, or move its cursor past a call it
  never reported, and a digest say all was quiet.
- `wait_for_updates` ends a wait on what happened since the cursor: a new contact request or
  agent-answered request, a contact newly held at a new address, an integration newly needing
  re-authorization, beside moved threads and contacts' calls. It ended every wait at once while any
  of those queues held anything, so an agent calling it in a loop, as its description says, spun
  for as long as the queue stood. The counts are reported on every answer as before. [0.1.1]'s
  entry ("answers when a contact is parked at a new address … or an integration needs
  re-authorizing") did not say that it answered so on every wait while either stood.
- An integration whose token stays dead no longer ends every `wait_for_updates`: each health cycle
  that redials it (every 60 s by default, while no connection stands), each failed reconnect and
  each refused call that found it in `auth_error` again fired the change feed's attention event
  and wrote another `integration_auth` audit row, so a wait parked over it answered within a cycle.
  Only the move into `auth_error` fires the event and writes the row now, after the status is
  written; the entry above's "newly needing re-authorization" was not true of the node until this
  change.
- Every argument refusal of the owner MCP is a coded tool error audited `refused`: `remove_passkey`
  ("id is required"; the last passkey), `set_exposure` ("integration_id is required"),
  `add_contact` ("give exactly one of invite_url or card", where it said "not both" for neither
  too) and `answer_request` with dispatch off (`unavailable`) answered results not marked as
  errors, audited `ok`; `rename_contact` over the name limit and `set_trust_flag` with a bad value
  answered a bare error with no code. [0.1.5]'s entry said `add_contact` and `set_exposure` answer
  their failures as `IsError` results audited `refused`; that was true of the failures of their
  work, not of these argument refusals.
- The portal's `POST /integrations/{id}/reconfirm` answers an integration with nothing published,
  or with no catalogue snapshot, 409 with the node's sentence ("integrations: nothing published to
  reconfirm"), as its README says; it answered 404, the answer for an integration not on the
  account.
- A catalogue refresh whose integration does not answer its tool list is `unavailable` with the
  node's sentence ("integrations: <name> did not answer its tool list"; 502 on the portal's
  `POST /integrations/{id}/refresh`); it was a failure of the node (500).
- The portal's routes that name an integration answer a read of it that failed 500 with the fixed
  phrase, where they answered 404, the answer for an integration not on the account. The
  portal's README said removing another account's integration was 403; it is 404, as for any
  integration the account does not hold.
- A portal action refused `too_large` answers 413, as `POST /thread/delete` does for a `thread_id`
  over 64 bytes; `pageStatus` answered it 400, so a file over the identity's storage quota on
  `POST /messages/send_media` was 400.
- The portal's Identity page, the Settings page's pairing selector and storage rows, and the
  owners page's token scopes list the identities the signed-in owner administers, as the switcher
  does; they listed every identity on the node, so one with no membership showed there and every
  action on it answered 404. When the identities or the memberships cannot be read, the three pages
  answer 500, where Settings and owners showed no identities.
- The owners page answers 500 when its passkeys or tokens cannot be read, and the Settings page
  when its stored values, adapter credentials, pairings or presets cannot be read, to a GET or a
  HEAD; each read was dropped, so a failed one rendered as nothing registered, stored or paired. A
  post to either page, which answers with that state, answers such a read failing after it with
  its own status and notice, `new_token` for a token create, and `page_error` `"store"` in place
  of the lists, so a token's one appearance and a trust-on-first-use pairing's ingress key are not
  lost; the portal shows the notice, and the token, with the page as it was, except that the
  Settings page's preset grid applies a preset save or delete the node confirmed. Selecting an
  ingress tunnel when the pairings cannot be read answers the store's failure, 500 (with
  `page_error` `"store"` when the page cannot be read after it either), saves nothing and audits
  `settings_save` `error`; the failed read was taken as no pairing, a 200 telling the owner to
  pair first.
- A Settings save stores every knob the form submits or none. Each knob was checked and saved in
  turn, and the portal posts `public_url` (saved first) beside the tunnel, so a refusal of a later
  knob (a value the validator refused, an ingress tunnel not paired, the pairings that could not
  be read) left the earlier ones saved, with the refusal the only audit row; the entry above's
  "saves nothing" was not true of that form. Every knob is now checked before any is written, and
  they are written in one transaction, so a failed write stores none either. A knob stored and not
  applied to the running node (its apply failed after the commit) no longer stops the others: each
  is applied and announced to the node's other processes, and the portal answers "Saved <knobs>;
  could not apply <knob>: <sentence>.", audited `settings_save` `ok` and `settings_apply` `error`.
  The first failure ended the save there: the knobs after it were stored and never applied or
  announced, so no other process took them either, and the portal answered "could not save …",
  audited `error`, of knobs it had stored.
- The portal's `GET /api/card` answers a card whose signature could not be made 500
  `card_unavailable` (404 `no_card` when the identity is not there to sign it); the failure was
  dropped and the card answered 200 with an empty `sig`.
- The portal's `POST /contacts/{fpr}/remove` removes nothing when the contact cannot be read, and
  answers the failure (`err`, one `contact_remove` `error` row). The read, made for the notice, was
  dropped: the contact was removed on it, and a peer that could not be told was reported "Removed."
- The portal's exposure picker (`GET /api/integrations/{id}/exposure`, `POST
  /integrations/{id}/exposure`) answers a catalogue or an exposure set that could not be read, or a
  catalogue whose stored tool list does not parse, 500 and publishes nothing. A failed exposure read
  was dropped, so the picker showed nothing exposed; a failed or unparseable catalogue was 409, the
  answer for an integration with no snapshot, which stays 409.
- `THIRD_PARTY_NOTICES` covers every platform a release ships. It was made from one `go list
  -deps` for the host (macOS), so it lacked the eight modules only the Linux binaries link
  (`github.com/vishvananda/netlink`, `vishvananda/netns`, `mdlayher/netlink`, `mdlayher/socket`,
  `jsimonetti/rtnetlink`, `safchain/ethtool`, `prometheus/procfs`, `godbus/dbus/v5`), and listed
  `github.com/tailscale/certstore`, which only a cgo build on macOS links and no release binary
  does. It is now the union of one run per entry of the Makefile's `PLATFORMS` with
  `CGO_ENABLED=0`, as `make dist` builds, and `make notices-check` refuses a file made for another
  list (#140). The files attached to v0.1.5 and earlier releases were incomplete in the same way;
  they are left as published.
- `doctor`'s `FAIL probe` line gives the dialer's, resolver's or TLS stack's reason after the
  node's own phrase again (`unreachable: the endpoint did not answer the probe: …`); since #126 it
  gave the phrase alone. The portal's probe still shows the phrase only (#129).
- A restart no longer signs the owner out of the portal after a public URL was saved in Settings
  or allocated by the tunnel adapter. The cookie names carry the node's tag, which was computed
  after the store's settings and the adapter had set the public URL, so a URL saved in the portal
  renamed the cookies at the next start and the session was not found; the tag is now taken from
  the configuration file and the environment alone. A node whose public URL came from the portal
  or its adapter gets new cookie names once, at its first start on this release, and its owner
  signs in once more. `compose.yaml`'s portal forwarder now has `restart: true` under its
  `depends_on`, so Compose restarts it whenever Compose restarts the node, where after
  `docker compose restart hdtp-gateway` it answered nothing until restarted by hand (#169).
- The `cloudflare` tunnel adapter with `tunnel.cloudflare.sidecar=true` starts without a tunnel
  token: the token is the connector's, and the compose sidecar holds its own. The node refused to
  start without one, so a node following the quickstart restarted in a loop (#168). Spawning
  `cloudflared` as a child still needs it.
- The ingress's file registry writes a pairing to disk before it routes it. It changed the book in
  memory first, so a pairing whose write failed was routed until the next start forgot it.
- A pairing from the portal stores its ten rows (the adapter's eight, the tunnel selection and the
  public URL) in one transaction. They were written one at a time, so a re-pair that failed part-way
  left the new ingress's rows beside the previous pairing's, still selected.
- A pairing from the portal whose public URL the running node could not take (its apply failed
  after the ten rows were stored) answers "Paired as <name> over <adapter>; could not apply
  public_url: <sentence>. Restart the node to serve there." with `error` set and 200, audited
  `ingress_pair` `paired` beside `settings_apply keys:public_url` `error`. It answered "pairing
  refused" with the rows stored, the adapter selected and the one-time token spent, and wrote no
  `ingress_pair` row.
- A storage save from the portal (`POST /settings/storage`) stores its three rows (the quota, the
  retention window and the request expiry) in one transaction. They were written one at a time,
  so a write that failed part-way left the earlier rows saved under a "could not save" answer.
- An import that cannot read whether a contact is held fails and writes nothing. A failed read was
  taken for "not held": the file's contact was imported over whatever the store held, and a
  removed thread's root was labelled not a contact here.
- Deleting a conversation wakes a portal showing it (one `message` event naming the thread), where
  it published nothing. `wait_for_updates` does not report a deletion, as before.
- Deleting a conversation while another media body of the account does not parse says that its
  files were left, and why; the comments beside it promised the orphan sweep would collect them,
  which it cannot while that body stays.
- Every retention pass that deletes messages, threads or files writes one `retention_sweep` row
  naming what went (`ok`, `blobs_skipped_unreadable_media`, or `error` when a later step failed).
  While a media body that does not parse held the files back, a pass deleted the messages and,
  after the first, wrote no row; and an unreadable body reported in one account silenced the same
  body in another. The orphan sweep's row names its counts in the same shape.
- A retention pass that cannot list the accounts prints `retention: accounts: <error>`. It ended
  there without a word, so no account was swept and nothing said so.
- The contacts limit (`limit.contacts`) saved in the portal is applied at the next start. The boot
  read skipped every dotted key, so the node started on the default while the page showed the
  saved value as pending.
- The ingress's data plane knows a node paired on two subdomains by the secret it presents. It
  looked the node up by fingerprint alone and compared the secret of whichever pairing it met
  first, so such a node was refused with its own credential most of the time (349 of 400 lookups
  measured).
- A peer that refuses the MCP handshake itself with an HDTP §12 code in the JSON-RPC error's
  `data` — BatonDeck's edge, once a source's budget is spent — is read as that peer refusing the
  call, with its `retry_after`: a send is "recorded, not delivered: rate_limited" and keeps the
  wait (#135). It was the error text `calling "initialize": rate_limited`, a peer that could not
  be reached, and the wait was lost. A sealed call refused there no longer records that the peer
  has seen this identity's chain.
- `add_contact` with a card tells a failure of this node before the request leaves — its card or
  its client could not be read — as `internal`, audited `error` (#131). It was told as a peer that
  could not be reached (`unavailable`) and audited `unreachable`.
- `add_contact` with the invite link of somebody who asked this identity by card (`pending_in`),
  when their side redeems it, makes the row ours, pinned to what the offer proved, and moves it on
  with their answer (`active` or `pending_out`), as BatonDeck does (#183). Their invite was spent and
  the owner was then told `bad_request` ("already a contact or already pending"). Measured against a
  real node that still holds its request (`pending_out` there): it answers the redemption
  `pending_approval` before anything is spent, and the owner is told `bad_request` ("the peer
  refused the redemption: pending_approval"), unchanged; the redemption reaches this branch once
  their request has expired or been withdrawn. By card, a request for somebody already
  held `pending_out` is answered from the row and dials nobody, and one for somebody held
  `pending_in` is refused `conflict` ("they have asked you already: approve their request"),
  audited `pending_in`, as BatonDeck refuses it; the first was dialled and could end in that
  `bad_request`.
- The portal's ingress pairing refuses an account the node does not hold as `not_found`, and a
  node not serving yet or unpairing the selected tunnel as `conflict`, where all three were
  `bad_request`. A pairing the ingress refused is told by the ingress's code (a spent token, a
  subdomain paired to another node as `conflict`, a malformed subdomain, a node certificate it did
  not accept, an ingress that could not record it as `unavailable`), a pin the ingress did not
  match and an ingress not reached (`unavailable`) as themselves, where every one was
  `bad_request` "the ingress did not pair this node". Unpairing an adapter whose stored selection
  could not be read is a failure of the node and deletes nothing, where the failed read was taken
  for "not selected" and the pairing the next start would boot with was deleted. `POST /settings/pair` and `POST /settings/unpair` answer a refusal with the status
  its code reads (404, 409, 400, 502 for an ingress not reached, or 500 for a failure of the node) beside the page's state (or
  `page_error`, when the page cannot be read), where every refusal was a 200 with `error` set (a pairing form missing a field still is).
- A portal pairing that names no account pairs the node's sole account only when the signed-in
  owner administers it, as `accountMiddleware` resolves it for the request; on a node with one
  account that the owner does not administer it is refused `not_found` ("unknown account") and
  audited `ingress_pair` `not_found` under the pairing URL. It paired the sole account for any
  signed-in owner. On a node with several accounts it is still `bad_request` ("this node has
  several identities — choose which one to pair"), and on one with none `bad_request` ("create an
  account before pairing"); neither is audited. A pairing naming an account the owner does not
  administer, held by the node or not, is 404 before it reaches the pairing, at account
  resolution, audited `portal_request` `refused`.
- `add_contact` tells this identity's own outbound budget refusing the call as `rate_limited`, with
  the wait ("this identity has sent as many calls as its budget allows for now; try again in N s"),
  on both of its paths, and audits it `rate_limited`. It was told as a peer that could not be
  reached (`unavailable`) and audited `unreachable`, where SPEC.md says a call the outbound budget
  refuses returns `rate_limited` to the owner. A peer's own `rate_limited` refusal is `rate_limited` too ("…; try again later"),
  where it was `bad_request`.
- `add_contact` with an invite link that does not answer writes a `contact_initiate` row naming
  what failed (`why:`, as an undelivered message's row does), where it wrote none; the refusal is
  unchanged. Neither that row, the error behind the refusal, nor the row of an offer that does
  not verify carries the link: the link is a bearer token, and the audit names its origin
  (`link:`). The error carried the whole link, and the offer's row did.
- `add_contact` with the invite link of somebody this identity already holds `active` answers
  `active` from the row and calls nobody, as the cloud answers from its row (where it says
  `accepted`). It called the inviter, whose
  node refuses an active contact's `redeem_invite` (`permission_denied`, the contact tier), and the
  owner was told `bad_request`.
- `add_contact` with an invite link pasted with a space before it or a newline after it fetches
  the link it split, trimmed. The split trimmed it and the fetch was given it raw, so the request
  could not be built and the owner was told `internal` (#181).
- A call out that never left because this node's own budget refused it, or because the limits
  sidecar did not answer, is told and audited as that by a send (text and media), by `add_contact`
  (both paths: redeeming an invite link and asking by card) and by the notice to an asker (#179),
  and by `refresh_contact` and `call_contact` on the owner MCP and the portal (#182), which used to read
  it as an unreachable peer and an unavailable call: a refresh or a call this node's budget refused is
  `rate_limited` with the wait (429 on the portal), audited `rate_limited`, and one with the sidecar
  down `unavailable` saying so, audited `limits_unavailable`. A send is "recorded, not delivered: rate_limited" or
  "…: limits_unavailable", where it was "…: unreachable". `add_contact` with the sidecar down is `unavailable` "this node's limits
  sidecar is not answering, so nothing is sent", audited `limits_unavailable`, where it said the
  peer could not be reached and audited `unreachable`. The notice to an asker (`contact_accepted`,
  `contact_rejected`) is audited `rate_limited` or `limits_unavailable`, where it was audited
  `unreachable`; what the owner is told was already the budget's or the sidecar's words. A peer's
  `rate_limited` refusal of a send keeps its `retry_after`, in whole seconds, in the undelivered
  row's `why:`; the retry sweep's timing does not read it.
- `add_contact` with the invite link of somebody this identity holds `pending_out` (it asked them
  by card and they have not answered) moves that row on: `active` when they accept the redemption,
  unchanged when it is pending. It inserted a second row, which the store refused, so the owner
  was told `bad_request` "already a contact or already pending" after their node had spent the
  invite and, when it auto-accepts, made this identity `active` there (#178). With the link of
  somebody this identity has blocked it answers `bad_request` "you have blocked that identity;
  unblock them first" and calls nobody, as the cloud does; it called them and spent their invite.
- `make fuzz` gives each target a number of executions (`-fuzztime Nx`, minimization
  `-fuzzminimizetime 100x`) where it gave 30 s (minimization 5 s). A time budget that ran out
  while the engine was minimizing a new input failed the pre-push gate with `context deadline
  exceeded` and no failing input (#180); a count sets no deadline. Each count is 30 s at the
  lowest of five measured rates: `FuzzVCardParse` 700,000, `FuzzSealedEnvelope` 400,000,
  `FuzzInviteOffer` 250,000, `FuzzRedact` 2,000,000. Ten runs passed, in 136 to 160 s each.

### Docs

- SPEC.md and `docs/conformance.md` say the node implements HDTP 1.0.1, and SECURITY.md's
  Dependencies and Interoperability rows name hdtp-identity 0.8.4.
- `docs/deploy.md`'s upgrade of a VM runs what the first boot runs, the vendor step for the limits
  sidecar's crates included, which it left out; `make deploy-check` holds the lines to
  `deploy/cloud-init.yaml`'s (#141).
- `docs/operations.md` lists a Cloudflare quick tunnel (no account) with the `edge` adapter, and
  says localtunnel is not supported, with what was measured (#172, #173). The two-users demo no
  longer names a scenario count its battery has outgrown, and the quickstart says what the pairing
  run of 2026-10-13 measured where it said the pairing was not run (#172).

## [0.1.5] — 2026-10-12

### Changed

- No error text the node did not write reaches a caller of the owner MCP or a page of the portal,
  except `/healthz`, whose 503 names the limits sidecar's socket and the dial's error. A failure
  the node coded keeps the node's sentence; a store's not-found is `not_found` and any
  other failure `internal`, each with a fixed detail (`internal/refusal`). This changes answers:
  - Every owner MCP tool that returned a store failure as a bare error, whose text the SDK sent,
    answers `{"code","detail"}`. Resource reads whose scope or a thread's messages could not be
    read fail with "<code>: <detail>", where they returned the store's error.
  - `add_contact` and `set_exposure` answer their failures as `IsError` results, where they were
    results not marked as errors carrying `bad_request` and the error's text. Their
    `owner_mcp_call` row says `refused`, not `ok`.
  - `add_contact` over the contact cap answers `payment_required`, where it answered
    `bad_request`; a store failure answers `internal`. A peer or an invite link it could not
    reach is `unavailable` ("the peer could not be reached to redeem the invite", "the request
    did not reach the peer", "could not reach the invite link"); these were `bad_request` with the
    error's text ("the peer refused the redemption: …", "the request did not land: …", "could
    not reach the invite link: …"). A peer's refusal of a redemption or a request stays
    `bad_request`, naming its §12 code, or `refused`.
  - `set_exposure` on another account's integration answers `not_found` (was `bad_request`); on an
    integration with no catalog snapshot, `conflict`; a publish it refuses, `bad_request` with the
    node's reason; a store failure, `internal`.
  - `send_to_contact` answers a contact the account does not hold `not_found` and one that is not
    active `conflict`. A message recorded and not delivered is answered with the recorded result
    (`Status` `pending`) beside `unavailable` and "recorded, not delivered: <why>", where `<why>`
    is the peer's §12 code, `refused`, `endpoint_refused` or `unreachable`; the portal's three
    sends show the same sentence.
  - `answer_request` answers an unknown request `not_found` and a closed one `conflict`; a store
    failure is `internal`, where it was reported as an unknown request. Each was the error's text
    alone.
  - `refresh_contact` answers a refresh that could not be attempted `not_found`, `conflict` or
    `internal`, where it returned the error's text.
  - `export_card` for an identity awaiting its wallet answers `not_found` with the node's
    sentence, as the portal's card route answers 404 `no_card`, where it returned the error's
    text.
  - The portal's forms and routes that showed `err.Error()` (sending, adding a contact, the
    contact lifecycle, requests, identities, tokens, settings, pairing, integrations, media, the
    web wallet) show the node's sentence or a fixed phrase.
- The owner MCP's `call_contact` answers a contact the account does not hold `not_found` and one
  that is not active `conflict`, where both were `unknown_contact`; and `envelope_invalid` for an
  answer that did not verify — after its one `get_card`, or on the retry after it — and for a
  `certificate_renewed` whose chain could not be followed, where those were `unavailable`. Every
  failure is an `IsError` result now, so its `owner_mcp_call` row says `refused`, not `ok`: a call
  missing its contact or tool answers `bad_request` alone, every other failure its code and a
  fixed detail, where a detail, when there was one, was the error's text. The portal's
  contact call and tool-list routes answer `{"error":<code>}` by the same reading — 404
  `not_found`, 409 `conflict`, 502 `envelope_invalid`, 502 `unavailable` — where every failure was
  a 502 carrying the error's text.
- A call to a contact writes one `call_contact` audit row, `node.CallContact`'s, including for a
  contact not held (`not_found`) or not active (`conflict`). Each door wrote its own beside it, `ok`
  or `failed`, so a call that reached `node.CallContact` had two rows; for a contact not held or not
  active, which `node.CallContact` did not record, the owner MCP's door wrote `unknown_contact` and
  the portal's `failed`. The store suite now asserts `ErrNotFound` for a deleted contact on both
  engines.
- The owner MCP's lifecycle and permission tools answer a contact the account does not hold
  `not_found`, where they answered `unknown_contact`. A lifecycle action on a contact whose row
  could not be read answers `internal`, on the owner MCP and in the portal, where any failure to
  read the row was reported as an unknown contact (`unknown_contact`; 404 from the portal's
  request routes).
- A peer's refusal code is repeated only when it is one of HDTP §12's codes; any other string is
  `refused`, in add_contact's answer, in a send's "recorded, not delivered: <why>", in its audit
  row and in the move campaign's. A peer chose the string and could put words in front of the owner.
- A card, an invite's chain and a refreshed contact are refused in the node's words: "the card's
  certificate does not parse", "the card's certificate is not one this node accepts", "the invite's
  chain is refused by rule <n>", "the chain it answered with fails rule <n>". These carried the
  identity core's reason or a parser's text. A web wallet's chain refused at install says the rule
  and not the core's reason, on the page and from `account install-leaf`.
- The reachability probe's detail, on the settings page and from `doctor`, is the node's: the rule a
  served chain fails, without the identity core's reason; fixed phrases for an endpoint that does
  not answer or a certificate that does not verify; another instance without the id it echoed.
- Portal statuses follow the code of the failure (`pageStatus`): a media fetch of a private address
  is 403 (was 422) and one whose link did not answer 502; a contact refresh that could not be
  attempted is 404, 409 or 500 (was 404); an integration refresh of one not connected 409, a store
  failure 500 (was 409).
- Pairing whose account list cannot be read answers `internal`, where it said "create an account
  before pairing". Creating an identity under a slug another holds answers `conflict` ("the slug
  ... is another identity's"), where the page showed the store's refusal.

### Fixed

- 0.1.4's entry says `call_contact` answers a malformed answer `envelope_invalid` "as BatonDeck's
  does". BatonDeck's call route answered it `unavailable` at the time; that sentence claimed more
  than was measured.

## [0.1.4] — 2026-10-12

### Changed

- **Upgrading deletes data.** A conversation stored under a `thread_id` of neither form of HDTP §7
  (below) is deleted by the first `serve`, `migrate`, `export` or `import` after the upgrade, and
  again by each of them until one run finishes: the thread, its messages, the files only it names,
  its read marker and its change rows, with nothing kept in its place (migration 0005). Each identity
  that lost one gets a `thread_id_wipe` audit row with the counts and no id; `export` and `import`
  print on stderr a file the wipe could not collect. The new binary's `export` runs the wipe before it
  writes, so a copy of such a conversation is taken with the old binary, before upgrading
  (`docs/operations.md`); an import of that file leaves those threads and their messages out and
  shows their ids in its review.
- A `thread_id` has two forms, 1 to 64 ASCII letters and digits or a lower-case UUID, and the node
  takes no other (HDTP §7, SEP-0006). At `send_message`, `send_media` and `book_slot` a contact's
  `thread_id` over 64 bytes is refused `too_large`, and any other of neither form, the empty string
  included, `bad_request`, where the node took any string of up to 1024 bytes and read the empty one
  as none. The refusal records nothing of the call: no message, no thread, and the `msg_id` is not
  seen. Inside a sealed envelope it is sealed back as a tool error, charged and audited as the
  contact's call, and a renewal or a new address the envelope carried is learned. The portal and the
  owner MCP refuse an id of neither form that the owner names, to send into, read or delete a thread.
- hdtp-identity 0.8.3, from 0.8.0. A sealed call whose envelope is not exactly `protected`, `enc`,
  `ct` and `sig`, each a string, is refused `envelope_invalid` before the open by the library's
  reader (HDTP §13.1, SEP-0005): a fifth member or a member name in another case was read past, and
  a `sig` absent or null was read as the empty string and decided at the open (`chain_required` in
  the small form); now each is refused before the open, and not charged as an opened refusal. A
  member written twice is read at its last occurrence alone: an earlier occurrence that is not a
  string (`"sig":5` before the real `sig`), which the decode refused `envelope_invalid`, no longer
  refuses the envelope. A `sig` present and not base64url in its one spelling is refused
  `envelope_invalid` before the open in the small form too, where it was answered `chain_required`,
  and spends the guest total alone, not the source's guest budget; an empty `sig` is still
  `chain_required` in the small form. A peer's sealed answer of other members fails as it is decoded,
  `envelope_invalid`, where it was read past or, with no `sig`, taken for an unverifiable answer and
  followed by a `get_card`; the owner MCP's `call_contact` answers it `envelope_invalid`, as
  BatonDeck's does, where it answered `unavailable`.
- An export no longer refuses, or leaves anything out, for a contact's text that reads as a private
  key: a thread id, a `msg_id` or a `reply_to` in that shape is written as `r` and 62 hex digits, the
  same at every reference, as is every id already of that form, and a topic or a contact's display
  name in it is written empty (SPEC §3.10, hdtp-identity 0.8.1 and 0.8.2). 0.1.3 refused such an
  export whole.
- Portal: Delete conversation is the last section of the contact panel, a "Conversation" heading and
  one button, where it was a trash icon in the conversation's header; it asks first, as before, and
  runs the same operation. A removed contact's conversation now opens the panel too, showing who they
  were and the button. A refused delete is said in the panel beside the button; one that went
  through clears the selection and goes back to the conversation list.

### Fixed

- A conversation whose thread id is `.` or `..` (a contact chose the id) could not be opened, sent
  into or deleted from the portal: the id was a path segment, which the browser's URL parser removes
  before the request leaves and Go's mux answers with a redirect. The routes that take a thread id
  now read it from `thread_id` in the query or the form: `GET /api/thread`, `POST /thread/send` and
  `POST /thread/delete` replace `GET /api/threads/{id}`, `POST /threads/{id}/send` and
  `POST /threads/{id}/delete`. `POST /thread/send` redirects to `/messages`.
- Portal, on a phone: with the rail collapsed (kept from a desktop) and a long account name or host,
  the account button's text ran out of the hidden drawer across the foot of every page, over the
  Inbox's Send and the panel's Delete, and took their presses. The name box is laid out as a column
  again at 900px and below.
- The claim, in migration 0004's comment and the [0.1.3] entry, that a thread holding a message was a
  contact's because "only a contact writes one" holds for what a host records itself, not for an
  import, which writes its file's threads and messages whatever this host holds of their root. The
  released migration is left as it shipped; `store.Thread.KeptWasContact`, SPEC §3.10 and
  `internal/core/store/README.md` state it truly. `kept_was_contact.json` and the comments that cite
  it no longer say BatonDeck "is to run" the list "once it lands": it runs it, from a byte copy held to
  the node's file.
- SPEC §12.3 said the image is "published multi-arch" and §12.5 that releases (binaries and images)
  are built with goreleaser. No image is published and goreleaser is not used: a release is
  `make dist` and `make sbom` on a maintainer's machine (`RELEASING.md`), publishing binaries for
  four platforms, `SHA256SUMS`, the SBOM and `THIRD_PARTY_NOTICES`, and the image is built locally
  from the `Dockerfile`. The SPEC, `docs/deploy.md` and a comment now say so, and name the `-full`
  image by its `Dockerfile.full` rather than as a tag.
- `compose.yaml` told a `-full` user to chown `/data` to 1000:1000; `Dockerfile.full` runs as
  65532:65532, the slim image's uid, which the comment now says.

## [0.1.3] — 2026-10-11

### Added

- Every tool the node serves states the four MCP hints (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`) as JSON booleans, each even where it equals the protocol's
  default: the fourteen HDTP tools, `sealed_call` included, on the plaintext `tools/list` and on the
  one answered inside a sealed envelope alike; the thirty-four owner MCP tools; and every exposed
  integration tool. Open world is true only where a call can leave this host (a calendar or status
  recipe, an integration, the sealed wrapper). BatonDeck serves the same values for the same HDTP
  tool names, and its copy (`gateway/test/fixtures/go-protocol-tools.json`) is held to this node's
  wire by `TestTheCloudsCopyOfTheProtocolHintsIsCurrent`.
- An export carries a former contact's conversation, and an import takes it in (HDTP §9.2,
  SEP-0004): each root that was ever a contact and is not (no row, or a request not yet decided)
  travels: each of its threads as a removed thread in `threads.csv`, carrying per name the newest
  its threads kept that is not empty, with its messages and files. Its root is never written as a contact and never
  called; into an identity that
  holds the root, the thread is that contact's. Migration 0004 keeps on each thread whether its root
  was ever a contact, as its row is deleted (`ever_active` or active; once kept it stays), and marks
  every thread written before it that holds a message, since only a contact's conversation can. What
  an export still leaves out — a conversation with a root this host has no record of as a contact,
  its request waiting or gone — is named by thread id and reason; a thread whose row went before 0004
  and that has no message left is one, a gap the migration cannot close. An import strips a display
  name a contact chose, and a removed thread's, as a card's FN is (HDTP §3), and the conversation
  list and the owner MCP strip it as they render it. Requires hdtp-identity 0.8.0.
- The owner can delete one conversation, here only: the portal's Delete on a conversation (which
  asks first) and the owner MCP's `delete_thread` run one operation. The thread, its messages
  (one still being retried is not sent) and the files no other message names go; the contact and
  its other threads stay, and nothing is sent to them (SPEC §7.9).
- `SECURITY.md` records the node's current hardening status: one row for each of fourteen areas
  (tests, fuzzing, static analysis, release integrity, authorization, secrets at rest and others),
  each naming the file, target or test it was measured from.
  `TestTheHardeningStatusTableMatchesTheTree` holds the rows to the tree: the analysers' pins, the
  pre-push hook's steps, the fuzz targets, the `policy.Allow` call sites, the release-build checks,
  and the live scenarios as a floor (more than 25, in the fabric, PR and nightly tiers).

### Changed

- An exposed integration tool is served with the upstream's hints, normalised (SPEC §6.9): a hint
  the upstream did not state as a boolean is MCP's default (read-only false, destructive true,
  idempotent false, open world true), `openWorldHint` is true whatever the upstream said, since every
  call leaves this host for the upstream, and an agent-answered exposure states the worst case
  whatever the upstream's tool said of itself. It was served with no annotations at all, although the
  snapshot had stored them, so a caller's host assumed every default.
- **Upgrading:** a link the owner fetches is now fetched for one message and its file recorded on
  that message, so the conversation opens it, an export carries it and a deletion collects it. The
  hourly pass now also takes files no message names, whatever the retention window (once older than
  an hour). A node upgraded from 0.1.2 or earlier holds files it fetched before, which no message
  names and whose records cannot say which message would: those are KEPT, and counted in the
  quota, because they are the owner's and the link behind one may be dead. Migration 0003 records
  when the node began to judge files, and the sweep judges only records written since. Nothing names
  such a file, so deleting its conversation does not find it either: it stays until the identity
  leaves the node (`account leave`).
- A removed contact's conversation stays in the inbox, under the name it had (the owner's petname,
  else theirs) and ` · removed`, readable and with no composer; it used to vanish from the list
  with the contact. A conversation whose contact is now a request or blocked stays listed too,
  read-only, under that row's name. Migration 0002 keeps the names on the contact's threads as its
  row is deleted, by any path, and never replaces a kept name with an empty one; `get_inbox`
  answers them as `removed_contact` (SPEC §9.1).
- `get_inbox` answers each thread's `contact_status`: its contact row's status, or `removed` when
  no row names the thread's fingerprint, in the words BatonDeck's thread rows use (SPEC §9.1).
- An avatar's colour is picked by the identity it stands for, not by its name: the first 30 bits of
  the root fingerprint choose one of ten fills (`--av-1` to `--av-10` in `brand.css`), so a rename
  keeps the colour and two contacts with one name almost always differ. A removed contact's
  conversation keeps its root's colour; the node's own identities are keyed by account id, since an
  account's fingerprint is its current leaf. A key that is not a fingerprint is hashed as text.
- The README states that the node comes with no warranty and no liability, in plain words under
  Sections 7 and 8 of the Apache License 2.0, which govern. `SUPPORT.md` no longer says nothing has
  been released.
- Contributing: no `Signed-off-by` line is asked for (no DCO, no CLA; the licence's section 5
  covers a contribution). The `commit-msg` hook refuses a message carrying a path under `/Users` or
  `/home`, and `TestNoTrackedFileLeaksALocalPath` reads the tracked text files for one. The name
  guard (`scripts/check-names.mjs`, `scripts/hdtp-names.txt`) is removed.
- `make deploy-check` holds the Azure sample parameters, the two deploy scripts' usage lines and
  `docs/deploy.md` to the AWS template's default release, as well as the four template defaults.
- The harness asks the local cloud's runner what a run links in and checks each in the checkout
  before it promises a scenario that needs the local cloud; a runner that cannot answer is refused,
  with node's error line.

### Security

- `make dist` refuses to build unless `git status --porcelain` is empty, untracked files included,
  and HEAD is the commit tag `v$(VERSION)` names; after building it refuses unless every binary's
  build info records `vcs.modified=false` and that commit. `make sbom` holds to the same tree check,
  and `make release-check`, in `make check`, shows each refusal against fixture repositories. 0.1.3
  is the first release built under these checks; the binaries of 0.1.0 to 0.1.2 are stamped
  `vcs.modified=true` (`RELEASING.md` records what was measured).

### Fixed

- The sealed answer to `get_card` carries the node's chain whatever the node has recorded the
  contact as having seen (HDTP §13.2: `get_card` "always answers with the chain"). It followed the
  record, so a contact that could not verify an answer and asked `get_card`, as §13.2 says to, got
  the fingerprint of the leaf it could not verify, and stayed stuck until that leaf retired. The
  answer is recorded as the chain sent, like any chain-form answer.
- An answer from a peer whose card says `X-HDTP-SEAL: required` that verifies under no leaf held for
  it is followed by one `get_card`, sealed to the pinned leaf, and when the chain it answers with is
  newer than the pin, by a re-pin and one retry under the same `msg_id`. The call failed at once,
  with the pin standing until an answer carried the chain or the pinned key retired. A `get_card`
  that does not verify, or is refused (`certificate_renewed` when the pinned key retired in
  between, which the next call follows), ends the call with an error naming both failures; no
  second `get_card` is asked. A peer that takes plaintext is still asked in plaintext.

## [0.1.2] — 2026-10-09

### Added

- Deploy templates for one VM with TLS on a hostname (`docs/deploy.md`): a shared first boot
  (`deploy/cloud-init.yaml`: Docker, the node and its sidecar built from a release tag, Caddy in
  front), a CloudFormation template for AWS, an ARM template with a Deploy to Azure button, a Cloud
  Shell walkthrough for Google Cloud and a Droplet script for DigitalOcean. `make deploy-check`, in
  `make check`, holds the templates to each other and to the node (`scripts/deploy-check.mjs`).
  None has been run on its provider yet; the document's status table says so, per provider.

### Security

- Built with Go 1.26.9 (13 standard-library advisories fixed since 1.26.6; v0.1.1's binaries were
  built with 1.26.6). `go.mod` names it in a `toolchain` line, the Dockerfiles pin
  `golang:1.26.9-alpine` by digest, and the image test holds the two to each other.

### Fixed

- The portal's integration routes refuse an integration of another account with `404`, the answer
  an id that names no row gets. `POST /integrations/{id}/remove` refused it `403`; the other eight
  (`oauth-client`, `credential`, `connect`, `authorize`, `refresh`, `exposure` read and write,
  `reconfirm`) compared nothing, so an owner who administers one account could connect,
  re-credential, refresh, read and set the exposure of another account's integration by naming
  its id.
- The limits sidecar's container has a healthcheck of its own: `hdtp-gateway healthcheck --limits`
  asks the sidecar for its rules over the socket the node asks it on. It inherited the image's,
  which asks the node's portal, so `docker compose ps` listed `limitd` unhealthy for as long as it
  ran; `compose.yaml` and `deploy/envoy/compose.yaml` run the new one.
- `doctor` reads `public_url` the way the node does: the environment, else the configuration file,
  else what the portal's Settings saved. It read the first two alone, so on a node whose address
  was set in the portal it printed `warn probe skipped: public_url not configured` and never
  dialled it.
- The owner MCP's `set_exposure` answers an integration of another account as it answers an id
  that names no row: the same `bad_request` detail, and no `permission_denied` audit row of its
  own. It read the integration's catalog before comparing accounts, so the catalog read's error
  told a foreign id from a missing one — an existence oracle the portal's `404` does not have.
  Both doors now ask the store for the integration by account and id (`GetAccountIntegration`),
  which answers `ErrNotFound` for either.
- The portal refuses a `POST` whose form fails to parse with `400` "bad form" (audited `bad_form`)
  before any route, and the CSRF check refuses one too. `ParseForm` keeps the pairs that parsed,
  and the account check read the body only when it parsed cleanly, so `account=<another's>&x=%zz`
  (or a bad escape in the query) reached the handler unchecked and acted on that account.
- The portal's `GET /events` carries only the events of accounts the signed-in owner administers.
  With several accounts and none named it subscribed to every account's, so an owner read the
  live stream of accounts administered by another owner.
- The owner MCP's `answer_request` answers another account's request id as it answers an id that
  names nothing (`unknown pending request`). It read the request by id and compared accounts after,
  so a token narrowed to one account told which request ids existed on another. The store reads and
  answers a pending request by account and id (`GetAccountPendingRequest`, `AnswerPendingRequest`).
- An answer from a contact whose card requires sealing that cannot be verified under any leaf held
  for it fails at once, with an error that says the pin stands until an answer from the contact
  carries the chain. The node tried its remedy first, a plaintext `get_card`, which refuses itself
  against such a contact before sending, and the error named that refusal (`and get_card:
  seal_required`). Against a contact that takes plaintext the remedy stands: one plaintext
  `get_card`, its chain followed to the pinned root, then one retry.

### Changed

- `web/tools/portal-qa.mjs` is removed: nothing ran it, and the harness and `make screenshots`
  cover what it drove.
- `make gosec` excludes `.claude`, the checkout's worktrees, which gosec's own filesystem walk
  entered and the Go tool's `./...` never did.
- `make analyze` runs its tools under the Go `go.mod` names (`GOTOOLCHAIN=<toolchain>+auto`), so a
  machine with an older Go, or `GOTOOLCHAIN=local` set, downloads it instead of failing. A Go older
  than 1.21 has no toolchain switching and is not helped.

## [0.1.1] — 2026-10-09

### Fixed

- The portal's session gate is an allow-list. A `GET` of a registered route outside `/api/` fell
  through to its handler with no session: `GET /media/{hash}?account=<id>` answered the stored
  bytes and `GET /events?account=<id>` opened the account's event stream to anyone who could reach
  the portal. Without a session the portal now serves the sign-in and setup ceremonies,
  `/api/session`, the wallet's return page, `/oauth/callback`, the static shell and the SPA's views;
  every other `GET` is sent to sign in, and a fetch under `/api/` or a mutation is refused `401`.
- `POST /messages/send_media` acts on the account the query names, which account resolution checks
  against the owner's memberships. It took the account from the multipart body first, which
  resolution never reads, so a signed-in owner could send media as an account they do not
  administer; the same id in the query was refused `404`.
- `list_passkeys` and `remove_passkey` on the owner MCP refuse a token narrowed to one account
  with `permission_denied`, as every account-scoped tool does; any valid token could list and
  remove the owner's passkeys. `remove_passkey` of an id that names no passkey answers
  `not_found`, where it returned the raw error.
- `wait_for_updates` answers when a contact is parked at a new address (`pending_addresses`) or an
  integration needs re-authorizing (`needs_attention`); the node woke the wait for both and the
  wait parked again until its timeout.
- An ingress pairing writes `subdomain`, the marker that makes the adapter selectable, as the last
  of its rows. `ingress_fpr` was written after it, so a failure on that write left a selectable
  adapter with no ingress pin; `unpair` now deletes `ingress_fpr` with the other rows.
- `GET /oauth/callback`, served without a session, completes a flow only for a `state` the node
  minted: it no longer takes an integration id from the query, no longer creates a connector
  entry per id it is given (unbounded from an unauthenticated request), no longer writes a
  result with a foreign state into an owner's pending flow, and audits the callback under the
  integration's own account rather than an `account` named in the query.
- `SPEC.md` §8.3 names the requests the portal serves without a session as the gate's
  allow-list has them (`/api/session`, the wallet's return page, `/oauth/callback` and the SPA's
  views among them); it said only the ceremonies, the shell and the health probe were served.
- `SPEC.md` §5.4 and §12 said a pending-tier caller invoking a tool beyond its own is refused
  `permission_denied`. The node answers `pending_approval` (`refusalCode`,
  `TestThePendingTierIsRefusedPendingApproval`), as HDTP 1.0 amended by SEP-0003 requires; the
  two lines say so.

### Removed

- `DashboardDeps.Setup` and `DashboardDeps.SignedIn`, set by the composition and read by nothing,
  and `ownermcp.ErrNoCard`, returned by nothing.

## [0.1.0] — 2026-10-08

This release covers the surfaces described in [`SPEC.md`](SPEC.md):

### Added

- **Node role** — the personal HDTP server: contacts, invites, a per-contact
  permission switchboard, messaging with threads, media with quotas, availability and
  calendar booking, all as MCP tools over mTLS with sealed envelopes.
- **Ingress role** — an own-domain front door for one or more nodes, in passthrough
  (SNI-routed, end-to-end) or terminate (ACME certificate, re-originated) mode.
- **Portal** — the owner's private web surface: setup wizard, passkey login, contacts
  and requests, inbox, integrations, settings, identity and key rotation.
- **Owner MCP** — the same authority for the owner's own agent, behind named,
  revocable bearer tokens on every bind.
- **Integrations** — upstream MCP servers over streamable-HTTP, SSE or supervised
  stdio, exposing only the tools the owner picks, versioned and audited, with recipes
  mapping them onto HDTP capabilities.
- **Reachability** — direct, Tailscale, frp, ngrok, Cloudflare, or the ingress role,
  with a `doctor` that derives the deployment mode and probes the endpoint.
- **Storage** — SQLite by default, PostgreSQL when wanted, with backup and restore;
  `check store` and the `serve` banner read every card and certificate the store holds
  by the identity core's rule and name each that does not read, and name each contact
  in a state neither a pin nor a request has.
- **Audit** — an append-only hash-chained trail over every public call and every
  configuration change. The rows naming an identity that left the node move to an
  archive file of its own after `audit_archive_after` (90 days by default), and verify
  with the rest of the chain (SPEC §3.11).
- **`THIRD_PARTY_NOTICES`** — the licence text of the Go modules the binary links, the
  crates the limits sidecar builds and the npm packages the portal bundles, written by
  `make notices` and held to `go.sum`, `Cargo.lock` and `package-lock.json` by
  `make notices-check`, which `make check` runs; a release ships the file.

### Changed

- The identity module, `github.com/humandelegatedtrustprotocol/hdtp-identity/go`, comes
  through the public Go module proxy and checksum database: hdtp-identity is public since
  2026-10-08, so `GOPRIVATE`, the SSH `insteadOf`, `make identity-proxy` and the
  `identityproxy` image-build context are gone, and a clone builds, vets and gates with no
  credential.
- The docs say where the identity repository is, where they said it was not public: the
  README quickstart, CONTRIBUTING, RELEASING, the pre-push hook, `docs/testing.md`,
  `docs/crypto-review-brief.md`, `docs/harness-design.md` and `docs/operations.md`.
- `compose.yaml` pins `alpine/socat` and `cloudflare/cloudflared` by digest (each `:latest`
  as resolved on 2026-10-08), the tag kept beside the digest for the reader.
