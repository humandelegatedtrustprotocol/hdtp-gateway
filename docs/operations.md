# Operating an hdtp-gateway node

This is the operator's page: what runs where, how the node is reached, how it is
backed up, and what to do when something is lost. Design rationale lives in
[`SPEC.md`](../SPEC.md); this page only tells you what to run.

## Layout

| Path (in `data_dir`, `/data` in the container) | What |
|---|---|
| `hdtp.db` | the SQLite store: accounts, contacts, messages, integrations, audit chain |
| `blobs/` | content-addressed media |
| `keyring.key` | the keyring master key (0600). **Every account's private key is sealed under it.** |
| `hdtp.lock` | held while `serve` runs; offline commands refuse to run while it is held |
| `admin.sock` | the admin socket the CLI talks to while the node is running |

Configuration: env `HDTP_*` > `config.json` > defaults (`hdtp-gateway doctor` prints the
resolved result). The deployment **mode is derived** from the tunnel adapter, never
declared (SPEC §10.1).

## Reachability

| You have | Use | Mode |
|---|---|---|
| a public port / static IP / VPS | `tunnel: direct` (default) | direct |
| a Tailscale account | `tunnel: tailscale` — tsnet Funnel, free, ports 443/8443/10000 | direct |
| an `frps` you run on any VPS | `tunnel: frp` — raw SNI/tcp passthrough | direct |
| a paid ngrok plan | `tunnel: ngrok` — `tls://` endpoint | direct |
| a Cloudflare account | `cloudflare` edge adapter (P4-05) — Cloudflare terminates TLS | edge |
| a domain of your own | run a second hdtp-gateway in the **ingress role** on a VPS (below) | direct (passthrough) or edge (terminate) |
| nothing inbound at all | one of the tunnels above, or a provider hosting the identity under a leaf you issue (HDTP §9). There is no relay role: it went on 2026-09-18, because a store-and-forward gateway sees every sender, recipient and timestamp | — |

Direct mode keeps mTLS end to end: callers' client certificates reach the node. Edge
mode cannot — a third party terminates TLS — so the node **forces** `seal=required`
and `client_cert=off`, and callers are identified by their sealed-envelope
signatures. `hdtp-gateway doctor` reports the derived mode and probes your
advertised endpoint; a `wrong_cert` verdict means something between the caller and
the node is terminating TLS that should not be.

Every carrier still sees metadata (who talks to whom, sizes, timing). Where that is
itself sensitive, use `direct` on infrastructure you control (SPEC §13).

### Ingress role (own domain)

On the VPS run the ingress; on the node pair with a one-time token:

1. ingress: `hdtp-gateway ingress serve --domain example.com` (P5-05 wires the command;
   the library is `internal/ingress`) and mint a token from its portal.
2. node: portal → *Settings → Ingress* — paste the token, pick the subdomain and mode:
   - **passthrough** — the ingress routes on SNI and forwards raw TLS; your node's own
     certificate is what callers see (direct mode).
   - **terminate** — the ingress holds an ACME certificate, terminates the public TLS
     session, and re-originates a mutually-pinned mTLS leg to your node (edge mode for
     your node). Both keys are pinned at pairing; nothing else can deliver traffic.
3. The node connects **outbound** (embedded frp client) — no inbound port at home.

## Call budgets

Every call counts against a budget of the account it is addressed to, sized by
how many contacts that account may hold (HDTP §12). The budgets are not the
node's to decide: the **limits sidecar**, `hdtp-limitd`, holds their numbers and
their counters and decides each call with hdtp-identity's `hdtp-limits` crate,
the decision the hosted cloud makes (SPEC §5.7). The node asks it over a unix
socket, `limits_socket` (`HDTP_LIMITS_SOCKET`, default `<data_dir>/limits.sock`),
on one connection it keeps open; nothing but the charge — the account, the
caller's root and tier, its address, the contact cap — crosses it.

Its numbers are its configuration file, the rules document of hdtp-identity's
contract, shipped as `deploy/limitd/limits.json` (in the image at
`/etc/hdtp-limitd/limits.json`):

| Member | Budget | Keyed by |
|---|---|---|
| `contact_calls_per_second`, `contact_burst` | a contact | account, contact root |
| `identity_capacity_per_second` | every contact together: `limit.contacts` × the contact rate, burst one second of it, at most this | account |
| `guest_calls_per_hour` | a guest (a proven root that is not a contact) | account, root, address |
| `guest_source_calls_per_hour` | an address alone (nothing proven) | account, address |
| `stranger_calls_out_per_hour` | calls OUT to strangers (`request_contact`, `redeem_invite`, the answers to a request) | account |
| `integration_calls_per_hour` | one integration's tools, per contact | account, integration, contact |
| `pending_in_cap` | requests waiting on the owner that strangers may write | account |
| `guest_total_calls_per_hour` | every caller the open does not prove a contact, together (below) | account |

**`guest_total_calls_per_hour` is checked before the envelope is opened** (the owner's decision of
2026-09-29). Nothing unopened says who sent a sealed call, so the node asks the sidecar first,
before it reads a key: while the account's total holds a call, every sealed call goes on to be
opened; once it holds none, only a call from a known address does — one that carried an active or
pending_out contact's call to the account in the last hour, which the sidecar remembers — and
everything else is refused `rate_limited`, in the clear, with the total's `retry_after`. Asking
spends nothing. The total is spent after the open by every call that is opened and does not prove
an active or pending_out contact: a guest, a blocked or superseded root, a root whose only row is
the request it left, a small form naming a leaf nobody pinned, and an `envelope_invalid` or
`certificate_renewed` the open found. A proven contact never spends it; a plaintext call opens
nothing and never spends it.

The known cost: during a flood, a contact calling from an address it has not used in the last hour
is refused before the open, as a stranger is, with `retry_after`, until the total refills. The known
addresses live in the sidecar's memory beside the counters, an hour each and a bounded number an
account (the oldest going first: `KNOWN_SOURCE_TTL_MS` and `KNOWN_SOURCES_CAP`,
cmd/hdtp-limitd/src/lib.rs), so a sidecar restart forgets them too.

A known address is an address: every caller arriving from it shares its standing. Behind a carrier
that delivers every caller from one address of its own — `frp`, `ngrok` and `tailscale` from the
node's host, a terminate-mode ingress from its own, none of which names the client's address — one
contact's call makes that one address known, and the check before the open lets every stranger
through to be opened (and refused after it). The check does its work where each caller arrives with
an address of its own: behind Envoy (below), or the `cloudflare` adapter. (`TestAStrangerFloodDrainsTheTotalThenIsRefusedBeforeTheOpenAndAKnownContactGetsThrough`
shows a stranger at the contact's known address opened and refused.)

Calls out to a contact spend that contact's rate and the account's aggregate, in
buckets of their own. A refusal is a `rate_limited` tool error carrying
`retry_after` — the whole seconds until the bucket holds a call again — and an
audited `rate_limited` row naming the bucket, not a dropped connection, so the
caller's agent can read it and back off. A call out that is refused never leaves
the node. A request past `pending_in_cap` is answered `unavailable`: no wait
empties a list only the owner can.

**The shipped `identity_capacity_per_second` is measured, and it is below what 500 contacts ask
for.** One node on an Apple M2 Max served sealed `send_message` from 500 contacts at up to 280
calls a second in every run, and broke between 300 and 450 a second from run to run
(`TestMeasureAccountCapacity`, internal/node; the method and the numbers are in its file), and
the shipped figure is the lowest knee with a margin. The figure is the node's, and every identity
on the node shares it.

**Changing a number** is editing the file and restarting the sidecar, which reads it once and
refuses one it cannot enforce (a rate of zero, a burst under one call, a contact bucket that takes
longer than the hour an idle row is kept to refill), saying which member and why. The node needs no
restart: `get_card` asks the sidecar for the numbers it advertises on every call.

**When the sidecar is down, the node refuses.** Every sealed call, call out, request and
integration call is answered `unavailable` until it answers again, which the node notices by
itself. `/healthz` answers 503 and names the socket, so the container's healthcheck fails;
`hdtp-gateway doctor` prints `FAIL limits` with the reason, and the `serve` banner says `limits:
NOT ANSWERING`. Start the sidecar (`hdtp-limitd -config <file>`; the compose file runs it) and
the node serves again with no restart.

The counters live in the sidecar's memory, one set for every node process on the host. A restart
of the sidecar refills every bucket, which is the trade-off for not writing to a database on every
call — the budget is there to blunt abuse, not to meter usage, and an attacker who can restart
your sidecar has already won. Memory is bounded: a bucket idle for an hour is full whatever it
budgets, so it is dropped (checked once a minute), and a caller cycling addresses or fingerprints
cannot grow the table past who called in the last hour.

The one budget setting that is the node's is how many contacts each identity may hold, which sizes
the aggregate:

| Setting | Environment | Default | Meaning |
|---|---|---|---|
| `limit.contacts` | `HDTP_LIMIT_CONTACTS` | 500 | contacts each identity may hold — active contacts plus the requests it sent — and the size of its call budget |

It is an ordinary knob: the portal's Settings page edits it under Security, the
config file carries it as `limit_contacts`, and the environment pins it above
both (SPEC §12.2), in which case the page shows it locked and says why. It is
read per use, so a change takes effect with no restart. Empty, zero or
unparseable restores 500 rather than removing the cap. The cap is enforced
wherever a contact is added — approving a request, unblocking a contact,
accepting somebody's invite, sending a request, a peer redeeming an auto-accept
invite, approving a contact at a new address, and an import — and nothing already
held is removed when it is lowered.

## Connection bounds

The public listener holds at most 1,024 connections open (SPEC §5.7); one more is closed before
its TLS handshake, and the audit trail gets one `listener_full` row a minute while that continues,
with how many there were. Requests have 10 s for their headers, 60 s in all, 75 s for the answer,
and an idle connection is kept 120 s. Rate limits per address or for the whole node are not the
node's: put them where the traffic arrives — the edge, or a proxy in front of the node, such as
the one below.

## Behind Envoy

`deploy/envoy/` is the node behind a proxy of its own, the first of the two layers of its rate
limits (the second is the sidecar above): `docker compose -f deploy/envoy/compose.yaml up -d` runs
Envoy, the node and the limits sidecar, and only Envoy publishes a port. Before it: `make
limitd-vendor` (the image build), a certificate for the node's public name at
`deploy/envoy/tls/cert.pem` and `key.pem`, and `HDTP_PUBLIC_URL`, that name, in the environment.

What Envoy does (`deploy/envoy/envoy.yaml`, whose numbers are its own and nowhere else):

- terminates the caller's TLS with that certificate, which is what a caller now sees — WebPKI for
  the node's name, as behind a terminating edge — and asks for the caller's certificate chain,
  accepting any, since there is no authority above the person;
- limits each source address per path — the MCP endpoints, the invite landing, everything else,
  each with a bucket of that address's own — and answers 429 past it, before the node sees the
  request; and holds the listener's connection cap and timeouts;
- forwards the caller's chain in `X-Forwarded-Client-Cert` and the address its socket saw in
  `X-HDTP-Client-Address`, replacing whatever the caller sent in either.

The node reads those two headers only from Envoy's address, `proxy_address`
(`HDTP_PROXY_ADDRESS`, an IP; the compose file gives Envoy a fixed one on its network and the node
that one). From anywhere else they are a caller's own claim and prove nothing, and with no
`proxy_address` they are never read. The node still opens every envelope: Envoy sees the MCP
requests, never what a sealed one carries. `internal/integrationtest/envoy_test.go` holds the two
files to what the node relies on, on every commit, and the harness's S23 runs them with the image
and floods them, with a control.

## The store, when it is large

Nothing here needs setting. It is written down so that what the node does to its database is
not a surprise, and so that the one knob that exists is findable.

- **SQLite** (the default) is opened in WAL mode with `synchronous=FULL`, write transactions that
  take their lock at `BEGIN`, and a pool of four connections. Each was measured against a store of
  a million messages and the reasons are beside the code (`internal/core/store/sqlite.go`).
  `synchronous=FULL` is the one that costs speed on purpose: a commit here is a message a peer was
  told was delivered, and it is not given up to a power cut for a faster write.
- **Postgres** (`store_engine: postgres`) uses pgx's pool with its default size, the larger of
  four and the number of CPUs. The DSN is where it changes: append `pool_max_conns=16` (and
  `pool_min_conns`, `pool_max_conn_lifetime`) to `postgres_dsn`.
- **Every hour** the node removes what has outlived its own window, whatever retention an account
  has set: idempotency records of sealed calls, which a node would otherwise keep one of for every
  call it ever took, owner sessions nobody came back to, and change-log rows older than a week. With a retention window set it also
  removes the messages, threads and media past it.
- **Every statement the store can run is checked at build time** to have an index on any table
  that grows (`TestEveryQueryHasAPlan`, both engines). To see the numbers on your own hardware:

```
HDTP_SCALE_DB=/tmp/hdtp-scale.db go test ./internal/core/store/ -run '^$' -bench '^BenchmarkScale' -benchtime 20x
```

  The first run seeds the file — 10,000 contacts, a million messages, a million audit rows — and
  takes about a minute. `make scale` runs these benchmarks over a scratch file, and times an import
  of 40,000 threads against one of 10,000 (`HDTP_EXPORT_SCALE`), three rounds interleaved, failing
  if the best of three takes more than 6 times as long for 4 times the threads, in reading or in
  writing (linear is 4); the pre-push hook runs `make scale` last, after every other step.

## More than one process

Several `serve` processes can share one store, each with its own `internal_bind` and `public_bind`
behind whatever balances between them (SPEC §11.1):

- **SQLite:** on one host, all with the same `data_dir`. Not across hosts, and not on a network
  filesystem: SQLite's locking does not hold there. One limit of this profile: `Scrub`, the
  checkpoint that clears the write-ahead log after a leaf key is destroyed, cannot finish while
  another process is reading the file. It says so — a warning on an install or a signing request,
  an error on a retirement or a leave — and the next scrub that finishes clears the log; until
  then the destroyed key's bytes may remain in it. Postgres has no scrub at all (SPEC §3.9).
- **Postgres:** on any hosts, each with a `data_dir` of its own and the same `postgres_dsn`. Give
  every host the same master key in `HDTP_MASTER_KEY` (a host that generates a `keyring.key` of
  its own cannot open a key another sealed), and point `blob_dir` (`HDTP_BLOB_DIR`) at storage
  every host mounts, or media stored through one host is missing on the others.

The first `serve` on an idle data dir migrates; the others check that the schema is the one they
were built for and refuse to start if it is not. To migrate, stop every process on the data dir
(on Postgres, every process) and start the new binary. `migrate`, `export`, `import` and the
`audit` commands refuse to run while any `serve` holds the data dir. One process serves the admin
socket and `serve` prints `admin: ... is served by another hdtp-gateway process` on the others;
the setup URL a first run prints works on the portal of the process that printed it. The outbound
retries and the hourly retention pass run on one process at a time: the one holding the work's
lease in the store, renewed every 10 s; a holder that stops lets it go at once, and one that
crashes is replaced within 30 s.

The call budgets are shared by every process on a host: they are the limits sidecar's, and every
process names the same `limits_socket`. A unix socket does not cross hosts, so on Postgres each
host runs a sidecar of its own, and each host grants the whole budget.

What each process still keeps to itself, and so what is not yet shared between them:

- integrations: every process connects each one itself, so a stdio integration runs a child per
  process. An OAuth token is one for them all: the store holds it, and an expired one is refreshed
  by the one process holding that integration's refresh lease while the others wait for it.

## Export and import

```
hdtp-gateway export --config config.json --slug alina --out alina.zip
hdtp-gateway import alina.zip --config config.json --slug alina          # review: writes nothing
hdtp-gateway import alina.zip --config config.json --slug alina --yes    # writes it
```

Both are **offline** commands: stop the node first (they refuse while `hdtp.lock` is held).

**An export is one identity's contacts, chats and files, and nothing else** (SPEC §3.10, HDTP
§9.2): one unencrypted zip of `manifest.json`, `contacts.csv`, `threads.csv`, `messages.jsonl` and
`media/<sha256>`, the same format the cloud and the `hdtp` CLI read and write. `export` says, before
it writes, that the file is not encrypted: anyone who gets it can read the contact list and every
conversation and file, though it holds no key and cannot be used to speak as anyone. The file is
created `0600` and never replaces an existing one. A stranger's request that was never accepted,
and its conversation, stay behind.

What is **not** in it, because it is the host's and not the person's: every key, saved settings,
integration credentials, owners, passkeys, sessions, tokens, invites, the audit chain, the ledger
of leaves, and a contact's preset, trust flag and card. There is no flag that adds any of them.

`import` checks the WHOLE file before it writes anything, and refuses it whole at the first fault,
naming the member, row or line. Without `--yes` it shows what it would write and stops. Into a slug
that is not here it creates the identity keyless — its root and nothing more; into the slug the
file belongs to it merges, keeping every pin this host already holds. The rows go in under one
transaction, the files after it. An undelivered outbound message arrives as `failed`: delivering
it was the old host's job, under the old host's leaf.

Every import ends the same way: a request for a new leaf, which the import mints itself — `move`
for an identity that arrived, `renew` for one that was here — and prints with how to complete it
(the portal's `/identity/<slug>/wallet` for the web wallet, or the request itself for the CLI
wallet). Installing the leaf sends every imported contact this host's handshake (`account announce`
reports it). With no `public_url` set there is no address to ask for, and it names `account csr`
instead.

This is not a backup of the node, and the node has none: what a host accumulates beyond contacts
and chats is rebuilt, not restored. After a lost machine: `import`, the setup wizard for a passkey,
reconnect integrations, one certificate per identity.

## Recovery

| Lost | Consequence | Do |
|---|---|---|
| the node, with an export per identity | identities are not served until re-certified; settings, integrations, passkeys and the audit history are not in an export | `import` each, `serve`, the setup wizard; then one `account csr` / `install-leaf` per identity. Contacts keep their pins |
| `keyring.key` only | sealed leaf keys, saved settings and integration credentials are unreadable. **No identity is lost** — the root is in the wallet. If nothing on the node opens under the master key it was given, `serve` refuses to start and says why; if anything does, it starts and prints `NOT SERVED` for each account that does not | put the key back if it was kept anywhere, and nothing is lost. If it is gone for good: `export -slug` each identity, then `import` each into a fresh data directory — an export never needed the master key, because it never held anything sealed under it. For a single `NOT SERVED` account on a running node, a renewal alone does it: the install retires the key it cannot open and says so |
| a leaf simply ran out (nobody renewed it) | the account stops being served within the hour and its key is destroyed; contacts keep their pins, and `doctor` warns before it happens | `account csr --slug me -purpose renew`, the wallet signs, `account install-leaf` |
| a card or certificate on file that the identity core no longer reads (its reading got stricter with a release of the identity library: the identity core 0.4.2 refuses a character outside base64url in a card's certificate that 0.4.1 skipped, and what intake accepted then is still on file) | the core refuses it where it reads it, and the node says so only then: a contact whose card does not read cannot be written to (`node.PeerOf` reads the card first and refuses — a refresh of that contact included), and a call from a contact whose pinned leaf does not parse, in either form, is this node's unreadable state (`identity_state_unreadable` on the trail, `envelope_invalid` to the caller). The `serve` banner's `store:` line and `hdtp-gateway check store` read every such field first and name each that does not read — table, row, field, reason — and change nothing; `check store` exits 1 on one, and runs beside a serving node | for a contact's card: this node cannot ask for one; the contact's own next `update_contact` writes one that reads, or remove the contact and re-add it from a new card of theirs. For a pin's leaf: remove the contact and re-add it, since nothing it sends can be decided against that pin. Run `hdtp-gateway check store` before and after a binary that bumps the identity library |
| a contact in a state neither a pin nor a request has (the schema admits only `active`, `pending_in`, `pending_out` and `blocked` — both engines — so such a row is a hand-edited store's or a later binary's) | the node hands the identity core no pin for it, where the core would refuse the state as unreadable: a call from its holder is decided as a stranger's — the small form `chain_required`, the chain form a guest's — and no effect reaches the row. The `serve` banner's `store:` line counts such rows and a `NO PIN` line names each by account, root and status; `hdtp-gateway check store` prints the same and exits 1 | remove the contact (`remove_contact` ends a relationship in any state) and re-add it from a new card of theirs |
| one account's leaf key (compromised) | the thief speaks as that host until the leaf expires or is outranked | `hdtp-gateway account csr --slug me -purpose renew`, have the wallet sign it, `account install-leaf`: the newer leaf outranks the stolen one with every contact it reaches (HDTP §14.3) |
| nothing: the person moved an identity to another host | this node goes on serving it, with its key, until told | `hdtp-gateway account leave -slug me -yes` once the new host has told the contacts (without `-yes` it shows what it would erase): every record and leaf key of the identity erased, its address free at once (SPEC.md §3.11) |
| the wallet's root | the identity itself; this node cannot help | the wallet's own recovery, if it has one (HDTP §9, §14.5) |
| the audit chain shows a break | someone altered history | `audit verify` names the first bad row; treat the store as untrusted from there |

No telemetry leaves the node, ever; the audit chain is yours alone.
