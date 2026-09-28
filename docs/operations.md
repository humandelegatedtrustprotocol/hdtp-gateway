# Operating a pact-gateway node

This is the operator's page: what runs where, how the node is reached, how it is
backed up, and what to do when something is lost. Design rationale lives in
[`SPEC.md`](../SPEC.md); this page only tells you what to run.

## Layout

| Path (in `data_dir`, `/data` in the container) | What |
|---|---|
| `pact.db` | the SQLite store: accounts, contacts, messages, integrations, audit chain |
| `blobs/` | content-addressed media |
| `keyring.key` | the keyring master key (0600). **Every account's private key is sealed under it.** |
| `pact.lock` | held while `serve` runs; offline commands refuse to run while it is held |
| `admin.sock` | the admin socket the CLI talks to while the node is running |

Configuration: env `PACT_*` > `config.json` > defaults (`pact-gateway doctor` prints the
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
| a domain of your own | run a second pact-gateway in the **ingress role** on a VPS (below) | direct (passthrough) or edge (terminate) |
| nothing inbound at all | one of the tunnels above, or a provider hosting the identity under a leaf you issue (PACT §9). There is no relay role: it went with PACT 1.x on 2026-09-18, because a store-and-forward gateway sees every sender, recipient and timestamp | — |

Direct mode keeps mTLS end to end: callers' client certificates reach the node. Edge
mode cannot — a third party terminates TLS — so the node **forces** `seal=required`
and `client_cert=off`, and callers are identified by their sealed-envelope
signatures. `pact-gateway doctor` reports the derived mode and probes your
advertised endpoint; a `wrong_cert` verdict means something between the caller and
the node is terminating TLS that should not be.

Every carrier still sees metadata (who talks to whom, sizes, timing). Where that is
itself sensitive, use `direct` on infrastructure you control (SPEC §13).

### Ingress role (own domain)

On the VPS run the ingress; on the node pair with a one-time token:

1. ingress: `pact-gateway ingress serve --domain example.com` (P5-05 wires the command;
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
how many contacts that account may hold (PACT §12): if it may hold 500, all 500
may call it at once, one call a second each, and none is refused. Each budget is
a token bucket — a rate and a burst:

| Budget | Rate | Burst | Keyed by |
|---|---|---|---|
| a contact | 1 call/second | 10 | account, contact root |
| every contact together | `limit.contacts` × 1/second, at most 200/second | one second of it | account |
| a guest (a proven root that is not a contact) | 10 calls/hour | 10 | account, root, address |
| an address alone (nothing proven) | 60 calls/hour | 60 | account, address |
| calls OUT to strangers (`request_contact`, `redeem_invite`, the answers to a request) | 20 calls/hour | 20 | account |

Calls out to a contact spend that contact's rate and the account's aggregate, in
buckets of their own. A refusal is a `rate_limited` tool error carrying
`retry_after` — the whole seconds until the bucket holds a call again — and an
audited `rate_limited` row, not a dropped connection, so the caller's agent can
read it and back off. A call out that is refused never leaves the node.

**The 200 is measured, and it is below what 500 contacts ask for.** One node on an Apple M2 Max
served sealed `send_message` from 500 contacts at up to 280 calls a second in every run, and broke
between 300 and 450 a second from run to run (`TestMeasureAccountCapacity`, internal/node; the
numbers and the method are beside `NodeCapacityPerSecond` in internal/public/limits.go). So an
identity allowed 500 contacts is advertised and held at 200 calls a second, not 500: all 500 may
call at once only at two-fifths of a call a second each. The figure is the node's, and every
identity on the node shares it.

The one setting is how many contacts each identity may hold:

| Setting | Environment | Default | Meaning |
|---|---|---|---|
| `limit.contacts` | `PACT_LIMIT_CONTACTS` | 500 | contacts each identity may hold — active contacts plus the requests it sent — and the size of its call budget |

It is an ordinary knob: the portal's Settings page edits it under Security, the
config file carries it as `limit_contacts`, and the environment pins it above
both (SPEC §12.2), in which case the page shows it locked and says why. It is
read per use, so a change takes effect with no restart. Empty, zero or
unparseable restores 500 rather than removing the cap. The cap is enforced
wherever a contact is added — approving a request, unblocking a contact,
accepting somebody's invite, sending a request, a peer redeeming an auto-accept
invite, approving a contact at a new address, and an import — and nothing already
held is removed when it is lowered.

The buckets live in memory. A restart refills every one, which is the trade-off
for not writing to the database on every call — the budget is there to blunt
abuse, not to meter usage, and an attacker who can restart your node has already
won. Memory is bounded: a bucket that has refilled is exactly what a missing one
starts as, so it is dropped (checked once a minute), and a caller cycling
addresses or fingerprints cannot grow the table past who called lately.

## Connection bounds

The public listener holds at most 1,024 connections open (SPEC §5.7); one more is closed before
its TLS handshake, and the audit trail gets one `listener_full` row a minute while that continues,
with how many there were. Requests have 10 s for their headers, 60 s in all, 75 s for the answer,
and an idle connection is kept 120 s. Rate limits per address or for the whole node are not the
node's: put them where the traffic arrives — the edge, or a proxy in front of the node.

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
PACT_SCALE_DB=/tmp/pact-scale.db go test ./internal/core/store/ -run '^$' -bench '^BenchmarkScale' -benchtime 20x
```

  The first run seeds the file — 10,000 contacts, a million messages, a million audit rows — and
  takes about a minute. `make scale` runs these benchmarks over a scratch file, and times an import
  of 40,000 threads against one of 10,000 (`PACT_EXPORT_SCALE`), three rounds interleaved, failing
  if the best of three takes more than 6 times as long for 4 times the threads, in reading or in
  writing (linear is 4); the pre-push hook runs `make scale` last, after every other step.

## More than one process

Several `serve` processes can share one store, each with its own `internal_bind` and `public_bind`
behind whatever balances between them (SPEC §11.1):

- **SQLite:** on one host, all with the same `data_dir`. Not across hosts, and not on a network
  filesystem: SQLite's locking does not hold there.
- **Postgres:** on any hosts, each with a `data_dir` of its own and the same `postgres_dsn`. Give
  every host the same master key in `PACT_MASTER_KEY` (a host that generates a `keyring.key` of
  its own cannot open a key another sealed), and point `blob_dir` (`PACT_BLOB_DIR`) at storage
  every host mounts, or media stored through one host is missing on the others.

The first `serve` on an idle data dir migrates; the others check that the schema is the one they
were built for and refuse to start if it is not. To migrate, stop every process on the data dir
(on Postgres, every process) and start the new binary. `migrate`, `export`, `import` and the
`audit` commands refuse to run while any `serve` holds the data dir. One process serves the admin
socket and `serve` prints `admin: ... is served by another pact-gateway process` on the others;
the setup URL a first run prints works on the portal of the process that printed it. The outbound
retries and the hourly retention pass run on one process at a time: the one holding the work's
lease in the store, renewed every 10 s; a holder that stops lets it go at once, and one that
crashes is replaced within 30 s.

What each process still keeps to itself, and so what is not yet shared between them:

- the §12 rate buckets (each process grants the whole budget);
- integrations: every process connects each one itself (a stdio integration runs a child per
  process), and an OAuth token refreshed by one process may be refused to another that refreshes
  the same token, which marks the integration for re-authorizing;
- on SQLite, `Scrub` (the checkpoint that clears the write-ahead log after a leaf key is destroyed)
  cannot finish while another process is reading; it says so — a warning on an install or a
  signing request, an error on a retirement or a leave — and the next one that finishes clears
  the log.

## Export and import

```
pact-gateway export --config config.json --slug alina --out alina.zip
pact-gateway import alina.zip --config config.json --slug alina          # review: writes nothing
pact-gateway import alina.zip --config config.json --slug alina --yes    # writes it
```

Both are **offline** commands: stop the node first (they refuse while `pact.lock` is held).

**An export is one identity's contacts, chats and files, and nothing else** (SPEC §3.10, PACT
§9.2): one unencrypted zip of `manifest.json`, `contacts.csv`, `threads.csv`, `messages.jsonl` and
`media/<sha256>`, the same format the cloud and the `pact` CLI read and write. `export` says, before
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
| one account's leaf key (compromised) | the thief speaks as that host until the leaf expires or is outranked | `pact-gateway account csr --slug me -purpose renew`, have the wallet sign it, `account install-leaf`: the newer leaf outranks the stolen one with every contact it reaches (PACT §14.3) |
| nothing: the person moved an identity to another host | this node goes on serving it, with its key, until told | `pact-gateway account leave -slug me -yes` once the new host has told the contacts (without `-yes` it shows what it would erase): every record and leaf key of the identity erased, its address reserved until its last leaf expires (SPEC.md §3.11) |
| the wallet's root | the identity itself; this node cannot help | the wallet's own recovery, if it has one (PACT §9, §14.5) |
| the audit chain shows a break | someone altered history | `audit verify` names the first bad row; treat the store as untrusted from there |

No telemetry leaves the node, ever; the audit chain is yours alone.
