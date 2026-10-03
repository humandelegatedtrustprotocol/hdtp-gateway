# hdtp-gateway — Product Specification

**Version 0.2.2-draft · 2026-10-03 · implements HDTP 1.0.0** — HDTP 1.0 is the protocol's first version under this name, and every "HDTP §N" below cites it. Its call budgets are here: token buckets, the account's sized by the contacts it may hold, decided by the limits sidecar (§5.7) and advertised as `get_card`'s `limits` (`TestGetCardAdvertisesTheLimitsInForce` holds the figures to the sidecar's rules and the names to the wire; `TestGuestRateLimitIsEnforcedOnTheRealListener` spends the source budget an unproven caller pays on the real listener). Its notice is `export`'s: before the file is written it says the file is not encrypted, that anyone who gets it can read the contact list and all the conversations and files, and that it holds no keys (this node writes full exports and no book). The portal asks a web wallet for a leaf with a form and takes its answer from the fragment of its own address (§3.12), and one identity's contacts, conversations and files leave and arrive as the unencrypted zip (§3.10). The export writer this node links nulls, drops, truncates or leaves out and lists what a reader would refuse, and each message left out is reported (§3.10); BatonDeck's import ceilings, like this node's own, never refuse an export — they warn; and an import ends with the request for the next leaf, minted here. The manifest lists only the text members, the key-material rule reaches the manifest's strings and the media, and every instant in an export is RFC 3339 in UTC: those are held by that library. The span of a leaf is the person's to choose beneath §14.2's ceiling, and §14.3's MUST NOT is held by `TestAnUnansweredConfirmationChangesNoPin`. The identity library this node links (`github.com/pact-cloud/pact-identity/go`, required by version) holds the certificate rules: an ECDSA signature on a certificate is the low-S twin or the certificate is refused, at card intake as in a chain; a validity field that is not a date is refused rather than normalised; and an extension value of another type, or a `basicConstraints` that reads two ways, is refused rather than read. HDTP asks for no proactive re-confirmation and this node does none: a newer leaf arrives on use (§13.2, §14.4)

hdtp-gateway is a self-hosted personal node for the HDTP protocol: your agent's public,
permission-gated MCP server to the people you approve, your private control panel and
owner-MCP surface, and the bridge that exposes selected tools from your own MCP
integrations to your contacts. One Go binary; SQLite by default; no telemetry.

The HDTP protocol specification (`hdtp-spec/SPEC.md`) is normative for everything
wire-visible. This document is normative for the hdtp-gateway implementation.

---

## 1. Overview and roles

### 1.1 What hdtp-gateway is

hdtp-gateway is a self-hosted personal HDTP node: one static Go binary that gives a person a permanent agent presence on the network. It implements HDTP 1.0 — the protocol spec remains normative for all wire behaviour and is cited throughout as "HDTP §N". There is one generation: the person's self-signed root is the identity, the host holds a leaf the person issued it, and a card is `X-PACT-VERSION:2` plus that leaf. The protocol's first generation was removed entirely on 2026-09-18; nothing here speaks it. A single node is three things at once:

- **An MCP server to the outside.** Contacts and strangers reach the node's public surface (§5) as an MCP server over HTTPS. What a caller sees and may call is decided by caller identity (§3), tier, and the owner's per-contact permission switchboard (HDTP §8) — never by anything the caller asserts.
- **An MCP client to the inside.** The owner's own integrations — calendar, mail, anything speaking MCP — are upstreams the node connects to as an MCP client (§6). Contacts never reach an upstream directly: every exposed capability passes through versioned catalog snapshots and exposure sets, and is served in one of three modes — passthrough, mapped, or agent-answered (§6).
- **An internal surface for the owner.** A browser portal and an owner MCP server (§8) are how the owner, and the owner's own agent, read the inbox, manage contacts, invites, and permissions, and administer the node.

### 1.2 Two roles, one binary

The same binary plays three roles, selected by configuration (§12):

| Role | What it does | Detail |
|---|---|---|
| **node** | The default and the subject of most of this spec: a person's agent server — public surface, integrations, portal, owner MCP. | §2–§9 |
| **ingress role** | An own-domain front door: routes each subdomain either as **passthrough** (SNI routing, end-to-end mTLS preserved) or **terminate** (public ACME TLS at the front, converted to a fresh, mutually pinned mTLS hop to the node). Nodes pair with an ingress via a one-time token. | §10 |

The two roles compose rather than exclude each other: one binary, one configuration, and which role it is playing follows from what is configured.

### 1.3 Audience, license, telemetry

**v1 is built for strangers from day one.** The public surface is not a friends-only experiment: unknown callers are expected and served deliberately — the guest tier is minimal (HDTP §6.1), invites carry expiry, use counts, and server-side revocation (§9), HDTP §12 rate limits are enforced at the boundary, and refused connections are audited (§11).

**License and posture.** Apache-2.0 from day one. The repository starts private and is flipped public by the owner; CONTRIBUTING.md and a SECURITY.md with a private disclosure route ship from the first commit so the flip needs no cleanup.

**No telemetry.** The binary reports nothing to anyone, and the documentation states this explicitly. Its only outbound connections are the ones the owner configured: peer nodes, upstream integrations, and tunnel carriers (§10).

---

## 2. Architecture

### 2.1 One binary

hdtp-gateway ships as a single static Go binary (`CGO_ENABLED=0`) containing every role and every surface. Upstream integrations are consumed HTTP-first; stdio-only MCP servers run as supervised child processes of the node. The container image is a slim distroless build, with a `-full` tag adding the node and uv runtimes that stdio children commonly need (§12).

```mermaid
flowchart LR
    CA["Contact / guest agents"]
    OB["Owner's browser"]
    OA["Owner's agent"]
    CL["CLI"]
    UP["Owner's integrations<br/>calendar, mail, ..."]
    subgraph GW["hdtp-gateway node - one binary"]
        PUB["Public surface :8443<br/>mTLS MCP + invite landing"]
        REG["Registry + policy.Allow<br/>per-caller MCP servers, LRU"]
        CORE["Messaging, contacts, invites,<br/>integrations, events"]
        INT["Internal surface :8080<br/>portal + owner MCP"]
        ADM["Admin unix socket"]
        ST["Store + audit chain<br/>SQLite / Postgres"]
        UPC["MCP client pool<br/>HTTP-first, stdio children"]
    end
    CA -->|"mTLS / sealed_call"| PUB
    PUB --> REG
    REG --> CORE
    OB --> INT
    OA -->|"bearer token"| INT
    INT --> CORE
    CL --> ADM
    ADM --> CORE
    CORE --> ST
    CORE --> UPC
    UPC --> UP
```

Internally the binary is organized into twelve packages; the names below are normative. The twelve subsystems, each grounded in an approved decision:

| # | Package (indicative) | Responsibility | Detail |
|---|---|---|---|
| 1 | `store` | `Store` interface, sqlc + goose migrations, SQLite (modernc, default) and Postgres (pgx) engines | §11 |
| 2 | `audit` | Append-only hash-chain audit log, JSONL archive with durable re-anchor, the archive of a departed identity's trail, `audit verify`/`audit archive`/`audit repair`/`audit erase-archive` | §11, §3.11 |
| 3 | `identity` | Owners, accounts, memberships, WebAuthn passkeys, bearer tokens, keyring-encrypted secrets | §3 |
| 4 | `authz` | Cedar (cedar-go): static shipped policies, dynamic entities; the single call site `policy.Allow` | §3 |
| 5 | `envelope` | HPKE seal/open, detached signatures, the two suites, the open order | §4 |
| 6 | `public` | Public mTLS listener, caller identity derivation, tiers, per-caller MCP servers (§2.4) | §5 |
| 7 | `contact` | Contact lifecycle, invite issuance/redemption, card builder, vCard parse/emit | §9 |
| 8 | `message` | Threads, messages, blob store, internal event bus | §7 |
| 9 | `integration` | MCP client pool, upstream OAuth, catalog snapshots, exposure sets, three serving modes | §6 |
| 10 | `internal` | Portal (server-side rendered, zero external assets) and the owner MCP server | §8 |
| 11 | `reach` | Tunnel adapters and the ingress role | §10 |
| 12 | `cli` | CLI over the admin socket, config loading (environment > file > store > defaults, §12.2), doctor, migrate | §12 |

### 2.2 Three entry points

| Surface | Default bind | Authentication | Serves |
|---|---|---|---|
| Public | `:8443`, TLS | Caller identity per §3.5: the root of a chain that validated, presented on the transport (per the `client_cert` knob) or carried in a sealed envelope | The per-caller MCP endpoint (§5); invite landing pages `https://<host>/i/<token>` (§9) |
| Internal | `127.0.0.1:8080` | Portal: an owner session on **every** bind, loopback included (§8.3); CSRF protection stays on regardless. Any non-loopback bind MUST refuse to start unless passkey authentication and TLS are configured (§3). Owner MCP: named, revocable bearer tokens, also on every bind (§8.4) | Portal (browser) and owner MCP (§8) |
| Admin | Unix socket | Filesystem permissions | CLI (§12); offline DB operations only with the node stopped |

The default binds (`:8443`, `127.0.0.1:8080`), the path scheme of §5.2 (`/a/<account>/mcp`, the single-account `/mcp` alias), and the per-account endpoint slug of §3.2 are spec-chosen defaults, not plan-fixed decisions — of the URL surface only the invite path `/i/<token>` is plan-sourced; they stand unless the owner objects at review. Binds are configuration, not constants (§12); the portal and owner MCP can be kept local, tunneled, or split per the owner's deployment matrix (§10). One consequence of the surface split is worth stating here: when the owner sends outbound to a contact, the `sender` label of HDTP §6.2 is **derived from the surface** — portal → `human`, owner MCP → `agent` — and is never accepted as a caller-supplied parameter (§7).

### 2.3 The public call path

Every inbound call on the public surface travels one path:

1. **Accept.** TLS handshake on the public listener. A client certificate is requested according to the `client_cert` knob (`required` | `preferred` | `off` — §3): `preferred` is the direct-mode default; edge mode forces `off` because no client certificate survives a terminating edge (§10). Unknown certificates are accepted at the TLS layer — tiering happens above it (HDTP §2).
2. **LAN check.** The LAN connections flag governs whether the public listener accepts connections that bypass the configured carrier from private-range addresses; it defaults to off in edge mode, and every refusal is audited (§10, §11).
3. **Identity.** The caller is the **root** of a chain that validated (HDTP §2, §14.2) — presented as the TLS client certificate, or carried inside a sealed envelope. A lone certificate is not a chain and names no root, so it establishes nothing. When both proofs are present their leaf keys MUST match, else `envelope_invalid`. Fingerprints are `"sha256:" + base64url(SHA-256(SPKI))`. A call carrying no usable proof where one is required fails with `identity_required` (§5.3).
4. **Seal.** The `seal` knob (`none` | `optional` | `required`, advertised on the card as `X-PACT-SEAL`) is enforced. With `seal: required` — the default, and forced in edge mode — unsealed substantive calls are rejected with `seal_required`; a `sealed_call` passes the open order of HDTP §13.3 (decode → version and suite → resolve `kid` to a leaf key this endpoint holds → HPKE-open → verify the signature under the chain's leaf, or under the leaf the small form names → tier → time window → `msg_id` idempotency → dispatch).
5. **Tier.** The identity is looked up in the account's contact list and lands in exactly one tier: guest, pending, contact, or blocked — and blocked callers are silently served the guest tier, indistinguishable from strangers (HDTP §6.1, §9).
6. **Serve.** The caller's per-caller MCP server (§2.4) answers `tools/list` and receives `tools/call`.
7. **Dispatch.** Every call re-passes `policy.Allow` at call time, enforces HDTP §12 limits at the boundary, honors `msg_id` idempotency, and appends an audit event — bodies referenced, not copied (§11).

### 2.4 Per-caller MCP servers

The node never exposes one static MCP server. Every tool it can serve — guest and pending tools, the contact-tier core of HDTP §6.2, `sealed_call`, and every integration-derived tool — lives in a **registry as data**, and the node composes a dedicated MCP server per caller:

- **Keyed by (account, caller fingerprint).** Built on first use and LRU-cached.
- **Composed through `policy.Allow`.** Composition asks the single Cedar call site (§3) which registry entries this caller may see; the composition result *is* what `tools/list` returns. There is no second, parallel filtering path to drift out of sync.
- **Rebuilt on change.** Flipping a switch on a contact's switchboard drops the cached server, so the caller's next request is composed from the new grant. The transport is stateless (§5.5): there is no open session to notify, and a server announces no `listChanged`; a client re-lists. Upstream catalog changes propagate the same way once the owner re-confirms the affected exposures (§6).
- **Re-checked at call time.** The cache is a listing optimization, never an authorization cache: every `tools/call` passes `policy.Allow` again, so revocation is effective on the very next call even against a stale cached server.
- **No sessions.** Every request carries its own caller and is composed for it alone; nothing a request presents — an `Mcp-Session-Id` included — stands in for identity (§5.5).
- **Guests share one server.** All unknown callers of an account share a single guest server exposing exactly the guest tier of HDTP §6.1 (`redeem_invite`, `request_contact`) plus the `sealed_call` wrapper (§4); nothing about it is caller-specific, so there is nothing to build per caller.

### 2.5 Deployment modes (summary)

Reachability is the tunnel adapters' only job: an adapter never changes protocol behavior by itself. Each adapter declares whether it terminates TLS at a third-party edge (`TerminatesAtEdge`), and the node derives the deployment mode — and the knob values that mode forces — from that declaration, so the owner cannot configure a contradiction. Full adapter list, the ingress role, and the owner's matrix are in §10.

| Mode | TLS path | Forced / default knobs | Who reads what |
|---|---|---|---|
| **direct mode** | End-to-end mTLS terminating at the node (port forward, Tailscale Funnel, frp, ngrok TLS) | `seal: required` by default; `client_cert: preferred` by default | The carrier moves ciphertext; no third party reads content |
| **edge mode** | Public TLS terminates at a third-party edge (Cloudflare Tunnel; ngrok HTTPS) which re-originates to the node | `seal` forced `required`; `client_cert` forced `off`; LAN connections flag defaults off | The edge sees all metadata and would see any unsealed content — which is why seal is forced; sealed content stays unreadable to it (§4, §13) |

The honest residue, carried in full in §13: sealing uses HPKE Base mode to a long-lived leaf key, so there is **no forward secrecy** — a later compromise of that key decrypts traffic recorded while it was current, bounded by the leaf's 398-day ceiling and by renewal with a fresh key; an edge always sees **metadata** even when content is sealed; and the sealing keypair is the **same keypair as mTLS** (an accepted key-reuse caveat, with the envelope's `kid` as the seam for a future separate encryption key).


---

## 3. Identity, owners, accounts, authorization

hdtp-gateway keeps three notions strictly apart. An **owner** is a human who administers the node, authenticated with passkeys on the internal surface (§8). An **account** is an HDTP identity the node serves — a keypair, a card, an endpoint. A **caller** is a remote identity established per request on the public surface (§5) under the unified identity rule of §3.5. Every decision about what any of them may do funnels through a single Cedar authorization point (§3.6).

### 3.1 Owners and passkeys

Owners live in the `owners` table, their login material in `credentials` (§11). Owner authentication is WebAuthn passkeys:

- An owner MAY register multiple passkeys, each carrying a human-readable tag ("macbook", "spare yubikey"). Passkeys are listed and removed from the portal, the owner MCP, and the CLI (`passkey list|remove`, §12).
- Registering a **new** passkey is portal-initiated only — a WebAuthn ceremony needs a browser authenticator; the CLI participates by minting the one-time setup URL that leads to the portal ceremony (`passkey reset-wizard`, §12). It MUST NOT be possible over the owner-MCP bearer-token surface (§3.4) — a leaked token must not be able to mint a durable login credential.
- The portal requires an owner session on **every** bind, loopback included (§8.3); a non-loopback bind MUST additionally refuse to start unless passkey auth and TLS are configured (§8). A passkey is therefore not optional: once one exists it is the only way in.

First run and lockout recovery share one mechanism, the setup wizard (§12), gated by the zero-passkey rule: whenever the node has **zero** registered passkeys — first boot, or after the last passkey was removed — the portal auto-shows the wizard. The wizard is reachable only from loopback or with a one-time setup token (loopback-or-token gated); first run prints the portal URL and setup token to the logs (§12), and `passkey reset-wizard` (CLI, over the admin unix socket, §12) mints a fresh one-time setup URL for an owner locked out of every passkey. Setup tokens carry at least 128 bits of entropy and expire after 24 hours. An ordinary one is invalidated the moment any passkey is registered (§12.4); a **recovery** token minted by `passkey reset-wizard` is the deliberate exception, and re-opens the wizard while passkeys still exist — without it, losing a single passkey would be unrecoverable, since no bind serves the portal unauthenticated. A recovery token MUST be presented explicitly: reaching loopback alone never re-opens the wizard once a passkey exists, or any local process could register itself as an owner. Registering through it adds a passkey and removes none. It is **not** burned on first use: a WebAuthn ceremony is two requests, so consuming the token on the first would guarantee the second failed. Until setup completes it is a bearer credential for the wizard — anyone holding it can reach the ceremony — which is why it is invalidated by the first registered passkey and why the operator copy tells the owner to treat it as a password. Host shell access is therefore the recovery root of trust; there is deliberately no online recovery path.

The `credentials` schema is type-discriminated and pre-shaped for later login adapters: each row carries a kind plus an adapter-specific payload, so OAuth adapters (Google/Apple/WorkOS) and email/password can land later as new kinds without reshaping the table. v1 implements passkeys only. Portal logins create rows in `sessions` (§11).

### 3.2 Accounts

An account is one HDTP identity served by this node; a node serves one or many. The `accounts` table (§11) carries:

| Field | Meaning |
|---|---|
| leaf keypair | ECDSA P-256 default, Ed25519 permitted (HDTP §14.1); private key encrypted under the keyring (§3.7). The ROOT is not here: it is in the person's wallet (HDTP §9) |
| root fingerprint | `"sha256:" + base64url(SHA-256(SPKI))` of the root's key — the identity, and what contacts pin (HDTP §2, §14.3) |
| vCard fields | FN, TEL, EMAIL, … rendered by the card builder (§9); the `X-PACT-*` properties are derived by the node, never hand-edited |
| endpoint slug | path component addressing this account on the public listener. The endpoint is the node's public base URL plus the slug, and it is named inside the leaf's `subjectAltName` — nowhere else on the card (HDTP §14.2 rule 5) |
| seal policy | `none\|optional\|required`, published as card property `X-PACT-SEAL` (HDTP §13.4); default `required`, and edge mode forces `required` (§10) |
| status | whether the node currently serves this account; a disabled account keeps its data and contacts but its endpoint answers `unavailable` (HDTP §12) |

**Key reuse, stated plainly.** The leaf keypair is simultaneously (a) the TLS client key, presenting the chain on outbound calls, (b) the TLS server key, presenting the same chain, and (c) the HPKE recipient key and detached-signature key for sealed envelopes — Ed25519 leaves are converted to X25519 for PACT-SEAL-X25519. Compromise of one private key therefore breaks transport identity **and** envelope confidentiality at once, for that leaf. What it does not break is the identity: the root is elsewhere, a leaf lives at most 398 days, and a renewal with a fresh key outranks the stolen one with every contact it reaches (HDTP §14.3, §14.5). This is a deliberate, accepted caveat (§13); the envelope's `kid` is the seam that lets a later version introduce a separate encryption key without a format change (HDTP §13.5).

### 3.3 Membership and node administration

`memberships` (§11) relates owners to accounts many-to-many, with a role attribute on each row: several owners can share one account (a family assistant), and one owner can hold several accounts (personal and business personas). The role attribute is data handed to Cedar as an entity attribute (§3.6); the shipped static policies decide what each role may do. v1 defines exactly one membership role: `admin` — full control of the account. Finer-grained roles are post-v1; the role column is pre-shaped for them the same way `credentials` is pre-shaped for later login kinds (§3.1).

`node_admin` is node-scoped — a flag on the owner, not a membership role. Node-wide configuration — tunnel settings and the LAN connections flag, ingress pairing, storage, and the owner roster itself (§8) — requires `node_admin`; account-scoped actions require membership in that account.

### 3.4 Bearer tokens for the owner MCP

The owner MCP surface (§8) authenticates with **named, revocable bearer tokens**: created from the portal settings page or the `token` CLI (§12), each labeled, each bound to exactly one owner. A token acts as that owner and is subject to the same Cedar decisions (§3.6); revocation takes effect immediately. A token is required on **every** bind, loopback included — for the same reason the portal demands a session on every bind (§8.3): granting full owner authority to anything that can open a loopback socket would hand it to every other process on the host, and, where a container shares the network namespace, to every process in it. The CLI needs no token because it speaks over the admin unix socket, whose permissions are the host's. Tokens MUST NOT be accepted on the public HDTP surface, which carries no OAuth or token auth of any kind (HDTP §6) — public callers are identified only by §3.5. Tokens cannot register passkeys (§3.1).

### 3.5 Caller identity on the public surface

Under HDTP 1.0 the identity is the **root**, and the only thing that names a root is a
chain that validated (§14.2). There are two carriers and no third:

> The caller is the root of a chain presented as the TLS client certificate, **or** the
> root of the chain carried inside a sealed envelope. When both are present, their leaf
> keys MUST match; a mismatch MUST be refused `envelope_invalid` and audited (§11).

**A lone certificate establishes nothing.** The retired generation read the fingerprint
of whatever single certificate arrived as the caller, because there the identity WAS a
key. A self-signed certificate names no root and anyone mints one in a second, so the
node records no identity for it at all. Three things depended on that and were wrong
while it stood: `client_cert: required` — the posture HDTP §13.4 permits, about who may
knock at all — was satisfied by any certificate; the guest rate budget bucketed on a
fingerprint the caller chose per request; and the "both proofs must match" rule compared
a proven leaf against an unproven key.

Which carrier is available follows from the deployment knobs (§10): seal is
`none|optional|required`, client_cert is `required|preferred|off`. Direct mode defaults
to seal `required`, client_cert `preferred`; edge mode forces client_cert `off` and seal
`required`, so identity there is always the envelope. A guest's sealed call carries its
card inside the payload, and the chain inside that payload is what the card's
certificate must byte-equal (HDTP §13.2).

- A call that establishes no identity at all where one is needed MUST be refused
  `identity_required`.
- An unsealed substantive call to an account whose seal policy is `required` MUST be
  refused `seal_required`.
- An envelope that fails any step of HDTP §13.3's open order MUST be refused
  `envelope_invalid`. A small-form envelope the receiver cannot verify against a leaf it
  holds is answered `chain_required` instead — one answer for unknown, blocked, expired
  and mis-signed alike, so the answer tells a stranger nothing.
- Once an envelope has opened, a refusal MUST be **sealed** back like any other result
  (HDTP §13.2). A plaintext refusal past the open tells the carrier what state the
  recipient holds this sender in, and in edge mode the carrier is there by construction.

The resolved root is looked up in the account's contact list and maps to a tier — guest,
pending, contact, blocked — per HDTP §6.1, and the pin checks of §14.3 and §5.3 run
first: a leaf older than the pinned one proves nothing, and a leaf naming a different
endpoint is a request to move, not a call. Blocking is silent guest demotion: a blocked
caller is indistinguishable from a stranger. There are no MCP sessions to resume: every
request is resolved on its own (§5.5).

```mermaid
flowchart TD
    IN["Tool call on an account endpoint"] --> RES["Resolve identity:<br/>chain as client certificate / chain in the envelope"]
    RES -- "a lone certificate, or a chain that fails §14.2" --> AN["no identity: anonymous guest"]
    RES -- "both present, leaf keys differ" --> RF["envelope_invalid + audit"]
    RES -- "neither, where one is needed" --> IR["identity_required"]
    RES -- "a validated chain" --> PIN{"pin checks<br/>(§14.3, §5.3)"}
    PIN -- "older leaf, or blocked" --> AN
    PIN -- "a different endpoint under ask" --> PA["pending_approval"]
    PIN -- "the pinned root at the pinned address" --> LK{"root in<br/>the contact list?"}
    AN --> LK
    LK -- "no" --> GT["guest tier"]
    LK -- "pending_out" --> PT["pending tier"]
    LK -- "active" --> CT["contact tier"]
    GT --> CE["Cedar policy.Allow<br/>(single call site)"]
    PT --> CE
    CT --> CE
    CE -- "permit" --> DP["dispatch"]
    CE -- "deny" --> PD["permission_denied"]
```

### 3.6 Authorization: one Cedar decision point

Authorization is Cedar via **cedar-go**, on the model *static policies, dynamic entities*: the policy set ships inside the binary and is versioned with it; owners never author or edit Cedar in v1. What owners control is data — the per-contact permission switchboard (§5, §9) writes grants (`message.text`, `calendar.book`, `integration.<slug>`, … per HDTP §8) into the store, and those grants surface to Cedar as entity attributes, not as policy text.

`policy.Allow` is the **single** authorization call site: the public dispatch path, the owner-MCP dispatch path, and portal mutations all funnel through it, so there is no second ad-hoc permission check to drift out of sync. Entities are built per request from store state: the principal (caller fingerprint and tier, or owner with role and `node_admin` — in v1 the only membership role is `admin`, §3.3, so the shipped policies distinguish only membership and the `node_admin` flag), the account, and the grant set.

- The shipped policy set carries an explicit **forbid on blocked** callers; Cedar's forbid-overrides-permit semantics make the demotion of §3.5 non-bypassable regardless of any lingering grants.
- Authorization is re-checked **at call time** on every `tools/call`, not only when a caller's tool list is composed — flipping a switch revokes instantly (HDTP §8). The cached per-caller server (§5) is rebuilt on switchboard change; in the window before rebuild, the call-time check already denies.
- Denials return `permission_denied` (HDTP §12) and are audited (§11), as are refused LAN connection attempts (§10).

### 3.7 Keyring and secret storage

All secrets at rest are encrypted under a keyring **master key**, supplied — in the configuration precedence order of §12.2 — via environment variable, a key file, or the OS keyring where one is available. A key file with permissions broader than `0600` MUST cause the node to refuse to start. Containers (distroless, §12.3) have no OS keyring: there the key arrives via the environment or a key file on the `/data` volume. The keyring encrypts, inside the store (§11): account leaf private keys, owner-token secrets, integration credentials such as OAuth refresh tokens (§6), and tunnel credentials (§10). A copy of the database alone is therefore not enough to impersonate an account. The corollary is stated honestly: losing the master key loses every encrypted key with it — for leaf keys that is the loss of §3.9, applied to every account at once — an inconvenience, not the loss of the identities, because the roots are in wallets.

### 3.8 Server certificates by deployment mode

What certificate the node presents depends on the deployment mode (§10):

| Mode | Public leg | Node's listener |
|---|---|---|
| direct mode, own domain | the account's chain, or an ACME/WebPKI certificate for the hostname — HDTP §2 accepts either, and a peer that cannot validate the chain falls back to WebPKI for the name it dialed | the same — the node terminates public TLS itself |
| direct mode, no domain | the account's **chain** — leaf then root; a peer validates it to the root it pinned, at the address the leaf names (HDTP §2, §14.2). A lone self-signed certificate is not accepted by a 2.0 peer: it names no root | the same |
| edge mode | the edge provider's certificate — public TLS terminates at the edge (§10, §13) | an origin-leg cert on the tunnel-only listener, serving only the connector's leg |

The ingress role (§10) splits per subdomain: a **passthrough** subdomain carries the node's own certificate end-to-end (any direct-mode strategy above, routed by SNI); a **terminate** subdomain holds an ACME certificate at the ingress and speaks a fresh, mutually-pinned mTLS leg to the node, both ends pinned at one-time-token pairing.

Client side, in every mode: outbound connections MUST supply the **chain** through Go's `GetClientCertificate` callback rather than default certificate selection — edges advertise CA distinguished names in their CertificateRequest, and default selection would silently send nothing at all (§10). A key that holds no leaf presents no certificate rather than self-signing one: a lone certificate establishes no identity with a conforming peer (§3.5), so sending one would make the call anonymous while looking like it carried credentials.

### 3.9 Losing a leaf, losing a root

The node holds a **leaf** private key and nothing more (§3.2). Losing it is an
inconvenience, not the loss of an identity: the owner generates a fresh key,
`account csr -purpose renew` emits a signing request for the same endpoint, and the
wallet issues a new leaf under the same root. Contacts learn it the first time the node
calls them — the chain travels in that envelope (HDTP §13.2) — and a contact that hears
nothing keeps the old pin until the old leaf expires, because the newest leaf at the
pinned endpoint wins whenever it arrives (HDTP §14.3). There is no rotation ceremony and
no grace period to configure: nothing contacts hold is pinned to anything the node keeps.

**A leaf's key does not outlive its leaf.** A leaf is the root's trust in this host *until one
date*. Past that date every verifier refuses the leaf (HDTP §14.2 rule 4), so the key can do
nothing legitimate, and the node MUST stop using it at once and MUST destroy it: from `notAfter`
the key is no longer offered for opening an envelope or presented at a handshake, and the next
retirement pass — at start, on the hourly sweep, and when an account is adopted — sets the ledger
row to `former` with no key, clears the account's copy of the same key, stops serving the account
if the leaf was its current one, and records `account_leaf_key_retired` with `reason:expired`.
The ledger row and its key id stay, so an envelope still sealed to it is answered
`certificate_renewed` (HDTP §14.4); the account keeps its name, its root and its contacts, and
waits for a renewal, which has never needed the old key. This holds for the current leaf as much
as a superseded one. It did not: a leaf nobody renewed was served, and its key held, for as long
as the process ran.

**Destroyed, on SQLite; not on Postgres.** On SQLite the node runs with `secure_delete` on and, after every leave, retirement and install, checkpoints the write-ahead log and truncates it (`store.Store.Scrub`), so a destroyed key's bytes are overwritten in the database file and gone from the log (`TestALeaveLeavesNoLeafKeyOnDisk`, `TestARetiredLeafKeyIsNotLeftOnDisk` read the files byte for byte). On Postgres the node cannot do this: a deleted or overwritten row stays in its page as a dead tuple until VACUUM reuses the space, in the write-ahead log until its segment is recycled, and in every base backup and WAL archive for as long as they are kept, so what HDTP §9 calls destroying the leaf's key is, on Postgres, deleting it — a named divergence. What remains there is the key sealed under the node's keyring (AES-256-GCM), readable only by someone who also holds that keyring.

Losing the **root** is losing the identity, and the root is not here. It lives in the
person's wallet (HDTP §9): no third party holds a copy, this node cannot mint one, and
there is no recovery ceremony. That trade-off is the wallet's to state; it is repeated
once here so that nobody reads an export from this node (§3.10) as a copy of the identity.
It is not, and it holds no key of any kind.

### 3.10 What leaves a host, and what arrives

`export` and `import` (§12) are **offline** and reachable **only over host shell access** — never the portal, never the owner MCP, and never a bearer token.

**An export carries one identity's contacts, chats and files, and nothing else** (HDTP §9.2). It is one unencrypted zip: `manifest.json` (the format, `pact_export: 2`; the owner — the identity's root fingerprint, the only place the file says whose it is — and its name; the counts; and the SHA-256 of every other member), `contacts.csv`, `threads.csv`, `messages.jsonl` and `media/<sha256>`. A contact travels as it is pinned and as the owner marked it — root, endpoint, the owner's name for it and its own, status, whether it was ever a contact (which decides what an unblock restores), the permissions granted each way, the leaf and the root certificate — and a stranger's request (`pending_in`) does not travel, nor does its conversation: it is the host's, not the person's. A message's file is lifted out of the node's media record into the message's one attachment; a link the node never fetched travels as the body. An export MUST NOT carry a key of any kind: not a leaf's (a leaf is the root entrusting *this host*, for one address, until one date — HDTP §9, §14.1 — and a copy of its key lets whoever holds the file speak as this host), and not the node's master key. It MUST NOT carry what belongs to the host rather than the person: saved settings, integration credentials, owners, passkeys, sessions, tokens, invites, the audit chain, the ledger of leaves, a contact's preset, trust flag or card. There is no option that adds any of these. `export -slug S` says before it writes that the file is not encrypted and what that means (HDTP §9.2's words).

It is written THROUGH the `Store` interface (§11.1), not copied out of a database: an allow-list by construction, and the same on Postgres as on SQLite. The format and every rule about it are hdtp-identity's (`WriteExportZip`, `ReadExportZip`, `export_merge`), the same for the cloud and the `hdtp` CLI. The file is created `0600`, an export never replaces an existing one, and a file the node says it holds and does not is refused by name rather than left out. Before it reports the file written, `export` reads it back through `ReadExportZip` as an importer would, under the identity's own root; a file that does not read is removed and the export fails, naming why. What a contact controls never stops the export (the writer, the identity core 0.4.2): a `reply_to` whose message the file does not carry — a reply to one never held, or to one retention deleted — is written null, and a message whose body or file reads as a private key is left out with its file and named in the output and in the `account_export` row (`left_out:` the ids). What an export leaves out it names, with the true reason: a request that was never accepted, or a conversation whose contact was removed. A message still waiting for its human (the legacy `queued_for_human`) travels `queued`, as the cloud's exporter writes it. An export over what BatonDeck's import takes (5,000 contacts or 4 MiB of `contacts.csv`, 20,000 threads or 4 MiB of `threads.csv`, 150,000 message lines, 10,000,000 characters of message ids, 5,000 files or 95 MiB of them as their directory entries state, a 95 MiB zip) is written all the same and warned about, naming each limit: another host may take it.

**An import is checked whole, reviewed, and ends with a new leaf.** `import FILE.zip -slug S` reads the whole file through `ReadExportZip` — every entry name, every member's hash, every row, every line, every file's bytes, by bytes actually decompressed under a whole-file ceiling — and a file that fails any check is refused whole, before anything is written. The review — the contacts it would write, the ones held here with no leaf whose pin the file fills, the ones it keeps and any disagreement, the owner's name quoted — is printed on every run before anything is written: without `-yes` nothing more happens, and with `-yes`, the agreement to the review printed above it in the same run, the rows go in under one transaction (`Store.Atomically`) and the files after it commits. The review already refuses what the write would: an owner name the node's one display-name rule refuses (no control character: it becomes a line of the card), a slug reserved by an identity that left (§3.11), and a file thread whose id this identity holds for another contact. The write refuses a message whose id, or whose msg_id with that contact, is another message's on the node. `messages.jsonl`, the one member read into memory whole, is refused by its declared size over 128 MiB (measured: reading allocates about 11.5 bytes per byte of it and holds about 1.2); the whole-file ceiling, which the media dominate, bounds the disk. A slug that is not here is created **keyless**, holding only the root the file names as its owner: no certificate, no key, no ledger, and not served until the wallet issues this host a leaf under that root. A slug that is here must be that same root, and the file is **merged**: a contact this host holds with a leaf keeps its pin whatever the file says (HDTP §14.5, `export_merge`), one it holds with no leaf takes the file's, and threads, messages and files already here are left as they are and counted as such; a filled pin is counted apart from a contact added. The same root under another slug is refused. A contact's leaf is carried only when it validates at the contact's endpoint; otherwise the contact is pinned by its root alone. An undelivered outbound message arrives as `failed` with no retry schedule — delivering it was the old host's job, under the old host's leaf — and an inbound message arrives as `delivered`: it reached the host that exported it. The import and each refusal are audited (`account_import`), as the export is (`account_export`).

Every import therefore ends in the same place: the identity is here with its contacts and conversations, every contact the file wrote is owed this host's handshake (§9.1), and the next step is a **new leaf** from the wallet. The import mints the request itself, through the service `account csr` uses (audited `account_csr`): `move` for an identity that arrived, at this node's address for its slug, and `renew` for one that was here, at the address its current leaf names — and prints how to complete it, in the web wallet from the portal's `/identity/<slug>/wallet` or with the CLI wallet from the request it prints. With no public URL configured it names the command instead. Until it is installed, `account certificate` and `doctor` both name the identity and how many imported contacts wait, with the command that ends the wait; installing it sends the handshake.

This is not a backup of the node and there is none: nothing this node writes carries a key, a master key or a setting out of it. What a host accumulates beyond contacts and chats is rebuilt after a loss, not restored.

### 3.11 When the person leaves

`account leave -slug S` (§12) is what this node does when the person leaves it (HDTP §9, "What a host must do when the person leaves"). It runs on the admin socket only and, like `export` and `import`, needs host shell access: no portal page, owner-MCP tool or bearer token reaches it. It takes two steps, as an import does: without `-yes` it shows what it would erase — the slug, the root, how many leaf keys, contacts, conversations and media records — and erases nothing; with `-yes` it erases. It refuses an identity whose current leaf names this node's own address for it — one served here, now — unless `-force-current` is given, and says why: after a move to another address on this same node, "delete the identity at the old host" names this node, and the old leaf answers here until it expires with nothing to delete.

It erases the identity in ONE transaction (`identity.Manager.Leave`): the account row, and with it every row that names the account by a foreign key — contacts, invites, threads, messages, media records, integrations with their catalogs and exposures, pending requests, the move campaign's ledger, every leaf with its sealed key, removal tombstones, former endpoints and pending addresses — and the rows that name it without one: tokens scoped to it, its idempotency records, its per-account settings and the OAuth client credentials of each of its integrations (a settings row keyed by the integration's id). What the erase decides from — the account, its leaves, its media — is read inside the same transaction. A media file goes only when no other identity on the node still refers to its hash. The live node then forgets the identity, so its address is answered as an address this node never served. The erase does not reach the audit chain (§11.4), which is append-only by trigger; the identity's trail leaves it later, in a step of its own, below. `TestSQLiteLeaveErasesEveryRowThatNamesTheIdentity` (and its Postgres twin) reads the tables from the migrated schema and holds every one of them to this.

**The audit trail after a leave** (HDTP §9, "keep nothing beyond what law compels"; the owner's decision of 2026-09-28, "audit trail goes to archive eventually"). The rows that name the identity by its account id — in the row's account column, or in its resource as `account:<id>` — stay in the live trail, each with the slug and the contacts' fingerprints it wrote, for `audit_archive_after` after the leave (§12.2; **90 days** unless configured, so the owner can review the leave and whatever led to it on the portal's audit page for a quarter). The hourly sweep then moves every one of them, the leave's own `account_leave` row among them, to a file of the identity's own, `<data_dir>/audit-archive/<account-id>-<first seq>-<last seq>.jsonl` (mode `0600`), and appends one `audit_archive` row that names the segment and its hashes — `segment:<first>-<last> rows:<n> before:<prev_hash of the first> after:<hash of the last>` — and not the identity. Rows are matched by the account id alone: a slug is free again once its reservation ends and a fingerprint may be another identity's contact too, so neither names the identity by itself. A row that names the slug or a contact's fingerprint without the account id would therefore stay; `TestAccountLeaveOnARunningNode` measures, on a running node that made contacts, refused a leave and left, that after the archive the live trail names neither the slug nor the contact. A leave that did not erase (`refused`, `error`) is not a departure, and an account a leave row names that is still on the node is not archived. The archive is part of the chain and is verified with it (§11.6); the node never deletes it. One exception to "every one of them": a row an owner's `audit archive -through N` had already moved to the head archive (`<data_dir>/audit/`) before the period ended stays there, with the rest of that segment; the identity's archive takes the rows still in the table, and `erase-archive` works on identity archives only. When law requires the rows themselves to go, `audit erase-archive -file NAME` (§12.1, the node stopped) replaces the file's rows with their seq, `prev_hash` and hash alone, under a name of their seqs (`erased-<first>-<last>.jsonl`): the chain still verifies through them, `audit verify` reports them as erased, and the erase writes one `audit_archive_erase` row. `internal/core/audit/departed_test.go` holds the lifecycle on both engines.

The address stays reserved: HDTP §9 has "An address an identity has vacated MUST NOT be assigned to another identity until the last leaf issued for it has expired." For each endpoint a leaf installed here named, with its latest `notAfter` still ahead, the node keeps a row of the endpoint, the slug and that date, and nothing that names the identity (`vacated_addresses`, migration 0040). While the row is live, creating an account with that slug is refused at every door (the store's `CreateAccount`, which `import` reaches too), and so is a signing request naming that endpoint (`IssueCSR`). The hourly sweep drops a row once its date has passed. A person returning to this node under the same slug before then is refused too: the row cannot tell them from anybody else.

A leave is refused while the identity's move campaign is walking (it holds the key and writes the rows the leave erases), and for a slug the node does not hold; from that check to the end of the erase the leave holds the identity's one campaign slot, so no walk can start in between. On Postgres, the reservation and a create of the same slug take a lock on the slug, so a create that arrives while a leave is committing waits and is refused (SQLite's transactions already run one at a time). Each attempt to erase (a run with `-yes`) on a slug the node holds writes one `account_leave` row: `refused` (reason `campaign_walking` or `current_endpoint`), `error`, `ok`, or `partial` when the records are erased and a media file could not be removed, or the erased keys could not yet be scrubbed from disk.


### 3.12 A signing request to a web wallet

Besides `account csr` and `install-leaf -chain FILE` (the `hdtp` CLI's path), the portal asks a **web wallet** for a leaf and installs its answer (HDTP §9.1; the identity-boundary design §2). The wallet is `wallet_url` (§12.2), by default batondeck's ceremony host.

- `GET /identity/{slug}/wallet` shows what would be asked: the address, `renew` or `move`, the wallet, and a request already pending (its age and where it went). It writes nothing and is served `no-store`; signed out, it sends the person to sign in (`/login?next=`), and the sign-in view returns to it. An identity with no root is refused: the web wallet does not take `signup`, so a first leaf comes from the CLI wallet. So is a portal served over http at an address the wallet does not take as loopback — localhost, a dotted quad in 127.0.0.0/8 in normal form, or `[::1]`, the wallet's own rule and no other spelling (`[::ffff:7f00:1]` is refused) — which a wallet will not answer.
- `POST /identity/{slug}/wallet/start` (session and CSRF) mints the request through the same service `account csr` uses (`internal/cli/leafservice.go`), audited `account_csr` with `wallet_origin:`, and answers with a page whose form POSTs `csr`, `purpose`, `expect_root`, `root_cert`, `redirect`, `state`, `recipient`, `valid_days` and `expires` to `<wallet_url>/sign` and nothing else. A request already pending is replaced only when the form says `replace=1`. That page alone sets `Referrer-Policy: strict-origin-when-cross-origin` (under the portal's `no-referrer` the POST's `Origin` would be `null`) and adds the wallet's origin to `form-action`. `state` is 32 random bytes, base64url; the node keeps its SHA-256, never the state. `expires` is eight minutes ahead. `purpose` is `move` exactly when installing a leaf at that address would move the identity, by the rule the install itself uses.
- The wallet answers by navigating to `/wallet/return?slug=S#chain=<leaf>.<root>&state=<state>` (or `#error=…`). That page and its script are served without a session and hold no data (the page links the portal's own built stylesheet, which is served without one too), and a wallet's refusal is shown as a fixed state for its code (`cancelled`, `failed`, or any other, an unknown code not even repeated), never as the text the fragment carries: the session and CSRF cookies are `SameSite=Strict`, so the wallet's cross-site navigation arrives without them. The script reads the fragment, clears it, and POSTs it same-site to `POST /identity/{slug}/wallet/install`, where the session and the CSRF header are required. The page carries a worded state for each way this ends — installed (the identity's name, its address, the leaf's validity as the chain gives it, and any move notice or warning), each refusal code below, no session (401), the CSRF check (403), and no reply at all — and shows one, in a polite live region.
- The install is the one `install-leaf` runs, with the state: an answer with no state, or a chain that does not parse as two base64url certificates, is refused before anything else (`account_leaf_install_refused`, reason `malformed`); then it is refused (reason `state`) unless the state is the pending request's, then by the chain checks of §14.2 (reason `chain`), and only then is the state consumed, by the statement that checks it, which keeps its hash on the installed leaf (`answered_state_hash`, migration 0051). Every answer is JSON, a refusal `{"error", "code"}`: `answered` (409, this state was installed already), `no_request` (409, nothing is pending and the state was never installed), `not_this_request` (409, a request is pending and this is not its state: a replaced request, or one this identity never had), `wrong_root`, `wrong_key`, `not_newer` or `chain` (400, the chain refusals; `chain` names the rule), `malformed` (400), `not_found` (404, an identity that does not exist or is not the caller's) and `failed` (500, never the error's text). A refused chain leaves the request answerable; an answer is installed once: the consumption and every write of the install are one transaction, so of two answers carrying one state that pass their checks together exactly one is installed (`TestTwoAnswersTogetherInstallOnce`). An install that is committed stays installed: if the running node then cannot load the account, both doors answer "installed" with a warning to restart the node and announce, the one `account_leaf_install` row is `partial` and names it by code, and no campaign starts from a node that still holds the old card. A request is audited whether or not it is made — `account_csr` `refused` (a purpose or a vacated address) or `error`, with a reason code and never an error's text — and the portal's page for a request that could not be made carries a fixed sentence. One request is pending per identity at a time: replacing it is one transaction, and a second pending row is refused by the store (migration 0044). A moving install prints the move notice (the design's §3) on both doors: announce until no contact is waiting, then delete the identity at the old host — or, when the move was to a new address on this same node, no deletion, since the superseded leaf answers here until it expires (the design's wording would have the person erase the identity they had just moved).

What is built is the node's side. The wallet's `/sign` is batondeck's (its WU-C1), and a browser's handling of a public page navigating to `http://localhost` has not been measured yet (the plan's WU-X).

---

## 4. Sealed envelopes

**Normative elsewhere.** The envelope format, the two suites, the sealing and opening
order, the `sealed_call` tool and the error codes are `hdtp-spec/SPEC.md` §13; the
certificate profile and chain validation they rest on are §14. This document does not
restate them. It used to, in 146 lines describing the `v: 1` envelope, and two normative
texts for one wire format is how implementations drift — the node is not the protocol's
author.

What belongs here is what is the node's own:

- **Where it lives.** `internal/public/sealed.go` and `decide.go` open and dispatch
  an inbound envelope; `internal/outbound/seal.go` seals an outbound one;
  the wire struct is `hdtp-identity`'s `Envelope`, handed to its `Decide` exactly as it
  arrived, and `internal/envelope` keeps only the protected header's shape and the
  `envelope_invalid` error. Chain validation and the
  certificate profile come from `hdtp-identity` (`CONTRACT.md`) and never from a general
  X.509 path validator — HDTP §14.2 is deliberately not RFC 5280 path validation, and
  reaching for one refuses chains a conforming implementation accepts.
- **What the node requires.** `seal` defaults to `required` and is forced `required` in
  edge mode (§10.1), where the edge terminates TLS and the envelope is the only identity
  carrier that survives it.
- **Where the node's posture is its own.** The `client_cert` knob (§5.1) is the
  front-door hardening HDTP §13.4 permits and does not require: it decides who may knock
  at all, and is satisfied only by a chain that validates.
- **What a refusal costs.** Once an envelope has opened there is a proven key, so §13.2
  requires the answer sealed — including an error. The node seals `pending_approval`,
  the §5.3 refusal and a budget refusal, and answers in plaintext only where nothing
  opened: `chain_required`, `certificate_renewed`, and envelopes that failed to open.

## 5. Public surface

The public surface is the node's internet-facing listener: the MCP server that contacts and guests call. Every request on it is authorized by transport-and-envelope identity per the rules of §3.5 — there is no OAuth on this surface (HDTP §6). The internal surface — portal and owner MCP — never shares this listener; it binds separately under its own auth rules (§8). Everything below applies uniformly across direct and edge mode; the deployment mode changes which identity carrier is available and which knob values are forced (§10), never the pipeline itself.

### 5.1 Listener and TLS posture

**Server certificate.** The listener MUST select its server certificate through an SNI-driven `GetCertificate` callback, never a single static certificate, so one node can serve several hostnames (per-account endpoints, tunnel hostnames, ingress-paired names, §10) without restart. What it serves is the account's **chain** — leaf then root — which is what a peer validates to the root it pinned (HDTP §2); behind a terminating edge the certificate a caller sees is the edge's, and WebPKI for that hostname is the rule there (§10.1).

**Client certificates: request, never require.** The listener MUST operate in request-client-cert mode and MUST NOT require a certificate at the TLS layer (in Go terms: `RequestClientCert`, never `RequireAnyClientCert` or stricter). Two reasons: with sealing (§4), a caller's identity can arrive solely as an envelope signature, with no certificate on the wire at all; and a policy denial must surface as a structured HDTP §12 error the caller's agent can act on, not as an opaque TLS alert. A presented certificate is never validated against a CA pool — there is no authority above the person — but a presented **chain** is validated against the profile of HDTP §14.2, and its root is the caller. A single certificate is not a chain: it names no root and establishes no identity (§3.5).

**Knobs.** Three per-node knobs shape the surface; their forced values derive from the active adapter's `TerminatesAtEdge` property (§10):

| Knob | Values | Default | Forced |
|---|---|---|---|
| seal (card property `X-PACT-SEAL`) | `none` \| `optional` \| `required` | `required` | `required` in edge mode |
| client_cert | `required` \| `preferred` \| `off` | `preferred` in direct mode | `off` in edge mode (a terminating edge never delivers the caller's certificate) |
| LAN connections flag | on \| off | direct mode: on; edge mode: off | meaningful only while a tunnel adapter is active (§10.1) |

**Behind a proxy.** A node may stand behind one proxy that terminates the caller's TLS itself: `deploy/envoy` is that proxy, Envoy, configured to ask for the caller's certificate chain and accept any (there is no authority above the person), and to forward it to the node in `X-Forwarded-Client-Cert`, and the address its own socket saw in `X-HDTP-Client-Address`, replacing whatever a caller sent in either. `proxy_address` names it (§12.2). A request whose connection comes from that address is judged by what the proxy forwarded: the chain is the `Chain` member of a single-element `X-Forwarded-Client-Cert` (URL-encoded PEM, leaf first), validated exactly as a presented chain is, and anything else there — no header, two elements, a `Chain` that does not decode — is no chain at all; the source address is `X-HDTP-Client-Address` when it is an IP address, and none otherwise. From any other address neither header is read, and the proxy's own connection carries no certificate of the caller's. A caller sees the proxy's certificate, WebPKI for the node's hostname, as behind a terminating edge (§10.1) — but unlike a terminating edge the caller's chain arrives, so `client_cert` keeps its direct-mode meaning. Envelopes are opened by the node, never by the proxy.

`client_cert: off` means the handshake omits the CertificateRequest entirely. `preferred` and `required` both request-without-requiring at the TLS layer; `required` is enforced post-handshake at the application layer so the denial is an HDTP §12 error. Under `client_cert: required`, any `tools/call` on a connection that did not present a **chain that validates** is refused with `identity_required` — including a `sealed_call` whose envelope alone established an identity: the knob demands transport-carried identity, and an envelope does not satisfy it (HDTP §13.4, §5.8). A lone self-signed certificate does not satisfy it either, and this is the point of the knob: it is satisfied only by something a stranger cannot mint (§3.5). `required` is therefore unusable behind a terminating edge, where no certificate can arrive (§10).

**LAN connections flag.** The flag applies only to configurations with an active tunnel adapter (§10.1); with no tunnel it is inert. When the flag is off, connections from private-range source addresses MUST be refused, and every refusal MUST still produce an audit event (§11). Private ranges are the SSRF range list of §7.5 — RFC 1918, unique-local, link-local — plus CGNAT `100.64.0.0/10` on OS listeners; connections arriving via the `tailscale` adapter's own listener are not classified as LAN by their `100.64.0.0/10` source, which is Tailscale's own address space. **Loopback is likewise not classified as LAN**: it is the carrier's own delivery, not a bypass of it. Every reverse tunnel dials this bind from this host — `frp`, `ngrok` and `tailscale` in-process, `cloudflared` as a child process — so classifying loopback as LAN left every edge-mode deployment refusing its own connector and unable to serve a single request. No LAN host can present a loopback source; the kernel drops `127/8` arriving on an external interface. This is safe because loopback grants no authority on the public surface — the caller remains a guest without a client certificate or a sealed envelope — and is therefore not in tension with §8.4, which refuses loopback as authority for the owner MCP, where it would grant everything. The §7.5 SSRF list itself is unchanged and still blocks loopback. Residual: a connector run OUT of process and off-host — the `cloudflared` compose sidecar of §10 — reaches the node from an RFC 1918 address and is still refused; such a deployment must turn the flag on. Mode defaults and rationale are in (§10).

### 5.2 Routing

| Path | Serves |
|---|---|
| `/a/<account>/mcp` | The account's public MCP endpoint (a node hosts multiple accounts, §3) |
| `/mcp` | Alias for the account's endpoint, mounted only while the node has exactly one account |
| `/i/<token>` | Invite landing page (§9): human-facing HTML serving the issuer's signed card and its QR before any redemption |

The invite URL is bearer-token-only: possession of the URL is the whole credential, and nothing else sensitive rides in it (HDTP §4). The landing page is informational; redemption itself is always the `redeem_invite` MCP tool call on the account endpoint. Requests to unknown paths or nonexistent accounts MUST receive a plain HTTP 404.

### 5.3 Ingress facts and caller identity

Each accepted connection and request is reduced to two fact records before any dispatch decision.

**TransportFacts** — recorded at accept/request time:

| Field | Source |
|---|---|
| adapter, `TerminatesAtEdge` | which listener/tunnel adapter accepted the connection (§10) |
| source address, LAN classification | socket, or from the proxy `proxy_address` names its `X-HDTP-Client-Address` (§5.1); drives the LAN connections flag check |
| SNI server name | TLS handshake |
| the root of a validated client chain, its leaf, the leaf's key and the endpoint it names — or absence | presented certificates, or from the proxy `proxy_address` names the chain it forwarded (§5.1), if two of them validated as a chain (HDTP §14.2). A single certificate records nothing (§3.5) |
| account | path routing (§5.2) |

**EnvelopeFacts** — produced only by a successfully opened `sealed_call` per the open order of HDTP §13.3: the sender's root and leaf, the protected header `{v, suite, kid, msg_id, ts, exp, cty}`, the suite, and — for guests — the card carried inside the sealed payload, whose certificate must byte-equal the chain's leaf. Envelope failures are the library's to classify; the pipeline sees either EnvelopeFacts or an HDTP §12 error.

**Caller identity.** The rule and its outcomes are §3.5. In summary: the caller is the
root of a chain that validated, presented on the transport or carried in the envelope;
when both are present their leaf keys MUST match, else `envelope_invalid`; a lone
certificate is not a proof, and a plaintext caller with none is anonymous — free to
complete MCP `initialize` and `tools/list` and see the guest view, refused
`identity_required` on any `tools/call`.

**Guest binding rule.** A guest has no pin, so the identity it claims through a card must
be proven in the same request. On a sealed guest call the chain inside the payload MUST
validate, the signature MUST verify under its leaf key, and that leaf MUST byte-equal the
`card` argument's `X-PACT-CERT` (HDTP §13.2). On a plaintext guest call the chain
presented on the transport binds the same way. A sealed guest `tools/list` has no card to
bind and is refused `envelope_invalid` — guests discover their surface with plain
`tools/list`, which always answers. A guest whose leaf names this node's own address is
refused: no honest card carries it (HDTP §14.5).

**Seal enforcement.** With `seal: required`, any plaintext inner-tool call from an identified caller MUST be rejected with `seal_required`; `tools/list` remains answerable so callers can discover `sealed_call` and the requirement. An inner `tools/list` carried inside a sealed call is answered with the tier view of the envelope identity (§4).

```mermaid
flowchart TD
    C["TLS accepted - TransportFacts recorded"] --> R{"route by path"}
    R -- "invite landing" --> L["/i/token page: signed card + QR"]
    R -- "account endpoint" --> B["boundary checks: size caps, rate limits"]
    B --> S{"sealed_call?"}
    S -- "yes" --> E["open envelope (HDTP §13.3) - EnvelopeFacts"]
    E --> I["resolve caller: the ROOT of a validated chain;<br/>transport and envelope leaf keys must match"]
    S -- "no" --> I
    I --> T["tier: guest / pending / contact / blocked-as-guest"]
    T --> P["per-caller server (LRU) - policy.Allow at call time"]
    P --> D["dispatch: built-in or integration serving mode (§6)"]
    D --> A["audit event (§11)"]
    B -. "deny" .-> X["HDTP §12 error + audit event"]
    E -. "deny" .-> X
    I -. "deny" .-> X
    T -. "deny" .-> X
    P -. "deny" .-> X
```

### 5.4 Tier resolution

The resolved identity is looked up in the account's contact list and mapped to a tier exactly per HDTP §6.1:

| Contact state for this fingerprint | Tier | Sees |
|---|---|---|
| not in the list | guest | `redeem_invite`, `request_contact` (+ `sealed_call`, §4) |
| `pending_out` (their approval of me is outstanding) | pending | `contact_accepted`, `contact_rejected` |
| `active` | contact | tools filtered by this contact's switchboard (§3, HDTP §8) |
| `blocked` | guest | identical to guest — blocking is silent demotion (§9) |

A blocked caller MUST be served indistinguishably from an unknown one; the guest-tier catch-all error is `blocked_or_unknown`, indistinguishable by design (HDTP §12). A caller whose own request is still awaiting the owner's approval (`pending_in` on our side) resolves to guest — the node hands the identity core no pin for such a row, as BatonDeck hands none (the owner's decision of 2026-09-30, taking the cloud's side of the one divergence the identity core 0.4.2's three pin states surfaced), so its small-form envelope names a leaf nobody pinned and is `chain_required`, its chain form is decided as a stranger's, its audit row is a guest's, and no effect the core returns for an active pin reaches the unanswered request (`TestAPendingRequestIsHandedToDecideWithNoPin`) — and a duplicate request returns `pending_approval` (HDTP §12). A row in any other state — one the schema does not admit (migration 0002 holds a contact's status to `active`, `pending_in`, `pending_out` and `blocked`, on both engines), so a hand-edited store's or a later binary's — is handed to the core as no pin too, where the core would refuse the state as unreadable: its small form is `chain_required`, its chain form is decided as a stranger's, and no effect reaches the row; `serve`'s banner and `check store` count such rows and name each (§12.1), so the owner is told (`TestARowInAStateThisNodeDoesNotKnowIsHandedToDecideAsNoPin`). A pending-tier caller invoking anything beyond `contact_accepted`, `contact_rejected`, and `sealed_call` is refused `permission_denied` — the caller is known, so the guest catch-all does not apply (§5.8).

### 5.5 Per-caller servers, and no sessions

The node holds every exposable tool — built-in and integration-backed — as data in a registry, and composes an MCP server per caller: for each `(account, caller-fingerprint)` pair it evaluates `policy.Allow` (Cedar — static policies, dynamic entities, §3) over the registry and materializes a server exposing exactly the allowed set. Composed servers are LRU-cached per `(account, caller-fingerprint)`, 256 per account. All guest-tier callers of an account share one cached server exposing the two guest tools plus `sealed_call`.

**Stateless transport.** The public surface serves MCP Streamable HTTP **statelessly** (go-sdk `StreamableHTTPOptions.Stateless`): every POST is the whole of its exchange, runs the full pipeline of §5.3, and is answered by a session that exists for that request alone. The node issues no `Mcp-Session-Id` and reads none — a presented one is ignored, so it can never stand in for identity — and needs no `initialize` before a call. GET and DELETE, which only a session gave a meaning to, are answered `405` with `Allow: POST`. Both MCP eras are served: a client of the 2026-07-28 revision (`server/discover`, the per-request `_meta`) and a client of the handshake revisions (`initialize`, up to 2025-11-25), which the SDK serves with a temporary session of default parameters per request. For a 2026-07-28 client the handler's context ends with the request's, so a caller that hangs up stops holding the work it started. The server declares `tools` without `listChanged`: nothing carries a list-change notification to a stateless client, and a client re-lists.

A cached server MUST be dropped when the contact's switchboard changes, when an exposure set vM or catalog snapshot vN backing one of its tools changes (§6), or when the contact's tier changes; the caller's next request composes the new surface. The cache is a performance layer only, never the authority: every `tools/call` MUST re-evaluate `policy.Allow` at call time, so revocation is instant — the flipped switch removes the tool from `tools/list` and any in-flight or stale-cache call returns `permission_denied` (HDTP §8).

### 5.6 Dispatch: built-in versus integration-backed

A permitted call lands in one of two implementations:

- **Built-in tools** — the guest, pending, contact-management, messaging, and media tools of HDTP §6.2 — execute against the node's own store: contacts and invites (§9), threads, messages and blobs (§7). `msg_id`-bearing calls are idempotent per HDTP §6.2, backed by the store's uniqueness constraint (§11).
- **Integration-backed tools** execute in the serving mode configured for that exposed capability — passthrough, mapped, or agent-answered (§6). Arguments MUST be validated against the schema recorded in the backing catalog snapshot vN (the MCP SDK's low-level tool registration does not validate; the node validates with `google/jsonschema-go`), and failures return `bad_request`. A stale mapping — an exposure whose tool no longer matches the catalog snapshot hash it was confirmed against — MUST be withheld: absent from `tools/list`, and `unavailable` on call, until the owner re-confirms it (§6).

Payloads that agent-answered dispatch relays to the owner's connected agent carry the per-contact trust flag and untrusted-input labeling of (§6); inbound strings are stored raw and never concatenated into instructions (§7, HDTP §11).

### 5.7 Boundary limits

The size limits of HDTP §12 are enforced at this boundary, before dispatch, and again at the store layer (§11) as defense in depth:

| Limit | Value (HDTP §12 defaults) |
|---|---|
| `text` | ≤16 KiB |
| inline media | ≤5 MiB (larger by `url`; inbound URLs are never auto-fetched, §7) |
| `note` | ≤1 KiB |
| availability slots | ≤5 per response |
| contacts per account | `limit.contacts`, default 500: active contacts plus sent requests; refused `payment_required` to the owner and `unavailable` to a redeeming peer |

**The call budgets are decided by the limits sidecar**, `hdtp-limitd` (`cmd/hdtp-limitd`): a process of its own beside the node, which holds the numbers — its configuration file, `deploy/limitd/limits.json` as shipped, the rules document of hdtp-identity's contract (`LimitsRules`) — and the counters, and decides each call with hdtp-identity's `pact-limits` crate, the decision the hosted cloud makes. The node opens the envelope, works out what the call is charged to (the caller's tier and root, its source address, the account's contact cap) and asks the sidecar over a kept-open unix socket (`limits_socket`, §12.2); no key and no plaintext leave the node process. One sidecar serves every node process on a host, so every process on a data directory spends one counter. The budgets, by the members of that document:

| Budget | Keyed by | Member |
|---|---|---|
| per contact | account called, contact root | `contact_calls_per_second`, burst `contact_burst` |
| per account, every contact together | account | `limit.contacts` × `contact_calls_per_second`, burst one second of it, at most `identity_capacity_per_second` (what one node was measured to serve; `internal/node/capacity_test.go` records the measurement) |
| guest | account, root, IP | `guest_calls_per_hour` |
| source, for a caller that proved no root (a small form answered `chain_required`, an anonymous or unchained plaintext call) | account, IP | `guest_source_calls_per_hour` |
| calls out to anybody who is not an active contact | account | `stranger_calls_out_per_hour` |
| one integration, per contact (§6) | account, integration, contact | `integration_calls_per_hour` |
| requests waiting on the owner (`pending_in` rows a stranger writes: `request_contact`, a redemption the owner must approve) | account | `pending_in_cap`, a count: refused `unavailable` to the peer, since no wait empties it |
| every caller the open does not prove a contact, together (below) | account | `guest_total_calls_per_hour` |

**The guest total is checked BEFORE the open** (the owner's decision of 2026-09-29). Nothing unopened says who sent a sealed call, so the node asks the sidecar first (`admit`), before a key is read: while the account's `guest_total_calls_per_hour` holds a call, every sealed call goes on to the open; once it holds none, only a call from a known source does — an address that carried an active or pending_out contact's call to this account in the last hour, which the sidecar remembers when the node tells it so with that call's decision — and everything else is refused `rate_limited` with the total's `retry_after`, in the clear. Nothing is spent there. The total is spent after the open, beside the caller's own buckets and all or none with them, by every call that is opened and does not prove an active or pending_out contact: a guest, a blocked or superseded root, a root whose only row is the request it left (`pending_in`), a small form naming a leaf nobody pinned (`chain_required`, with the source's own budget), and an `envelope_invalid` or `certificate_renewed` the open found. A proven contact never spends it, and a guest from a known source is still refused after the open once it is spent. A plaintext call opens nothing and never spends it. The known cost: during a flood, a contact calling from an address it has not used in the last hour is refused before the open as a stranger is, with `retry_after`; and a sidecar restart forgets the known sources as it refills the buckets. And a known source is an address: every caller that arrives from one shares its standing. Behind a NAT or a proxy that names no caller, and behind a carrier that delivers every caller from one address of its own (`frp`, `ngrok` and `tailscale` dial from the node's host, a terminate-mode ingress from its own, and none names the client's address: §5.7's source IP), one contact's call makes that one address known, and from then on the check lets every stranger through to the open — each still refused after it, having cost an open. The check before the open does its work where each caller has an address of its own: behind Envoy (§5.1), which names it, or the `cloudflare` adapter, whose trusted header does.

Every budget but the requests waiting on the owner is a token bucket; `retry_after` is the whole seconds, at least one, until the bucket that refused holds a call again. Every call that reaches dispatch spends — a sealed `tools/list` and a tool that does not exist included — and a replay answered from its record does not. What an account sends is budgeted too: to an active contact at that contact's rate and within the account's aggregate, and to anybody else (`request_contact`, `redeem_invite`, `contact_accepted`, `contact_rejected`, any unpinned address) at `stranger_calls_out_per_hour`; a refused call leaves the node as nothing and returns `rate_limited` to the owner. `get_card` advertises the sidecar's numbers for the account (HDTP §12's `limits`), asked of the sidecar, never compiled in.

**When the sidecar does not answer, the node refuses.** Every call it would decide — every sealed call, every call out, every request and every integration call — is answered `unavailable` until it answers again, and the node reconnects by itself with no restart. `/healthz` answers 503 naming the socket (so the container HEALTHCHECK fails), and `doctor` and the `serve` banner say the same: a budget nobody can enforce is not one the node guesses at.

The listener MUST cap request bodies before JSON parsing at **8 MiB** — sized to the largest legitimate payload: 5 MiB inline media × 4/3 base64 expansion plus envelope and JSON overhead, rounded up — rejecting larger requests with `too_large`. Rate-limit denials return `rate_limited` with `retry_after`.

**Connection bounds.** The listener holds at most 1,024 connections open; one more is closed as it is accepted, beneath TLS, before a handshake is begun, and the refusals are audited as one `listener_full` row a minute at most, counting them. It reads a request's headers within 10 s and the whole request within 60 s (an 8 MiB body at 140 KB/s), answers within 75 s (above the 30 s an agent-answered call is held, §6.8), keeps an idle connection 120 s, and takes 64 KiB of headers. Rate limits per source address and for the node as a whole are not the node's: they belong to what stands in front of it — the edge, or a proxy before the node (the owner's decision of 2026-09-28). `deploy/envoy` is such a proxy (§5.1): it limits each source address per path before the node sees a request — the MCP endpoints, the invite landing and everything else each at the number in `deploy/envoy/envoy.yaml`, refused with HTTP 429 — and holds the same connection cap and timeouts as the listener; a deployment on it is `deploy/envoy/compose.yaml`, which runs Envoy, the node and the sidecar.

**Source IP behind a terminating edge.** Per-IP limits need a source address the node can trust. On a `TerminatesAtEdge` adapter (§10.2) every connection reaches the node from the tunnel connector's address, so the node MUST take the client IP from that adapter's specific trusted header on the tunnel-only listener — `CF-Connecting-IP` for the `cloudflare` adapter — and MUST NOT honor generic `X-Forwarded-For` anywhere; direct listeners never honor forwarded-IP headers at all, but for the proxy `proxy_address` names, whose own `X-HDTP-Client-Address` is read from its connections alone (§5.1). Where an edge adapter provides no trusted header, per-IP limiting of anonymous callers degrades to a single per-node aggregate cap.

### 5.8 Denials and audit

Every deny on this surface maps to an HDTP §12 error code, including `seal_required`, `identity_required`, `envelope_invalid`, `chain_required` and `certificate_renewed`. The denials §5 itself issues:

| Condition | Code |
|---|---|
| anonymous `tools/call` (no certificate, no envelope) | `identity_required` |
| call without a client certificate under `client_cert: required`, sealed included | `identity_required` (§5.1) |
| pending-tier caller invoking a tool beyond `contact_accepted` / `contact_rejected` / `sealed_call` | `permission_denied` (§5.4) |
| plaintext inner call under `seal: required` | `seal_required` |
| envelope open/verify failure; envelope–certificate identity mismatch | `envelope_invalid` (§4) |
| guest or blocked caller invoking a non-guest tool | `blocked_or_unknown` |
| contact invoking a tool its switchboard does not grant | `permission_denied` |
| duplicate contact request while approval pending | `pending_approval` |
| expired / revoked / used-up invite token | `invite_invalid` |
| stale or withheld integration tool | `unavailable` |
| body or field over cap | `too_large` |
| rate cap exceeded | `rate_limited` (+`retry_after`) |
| argument schema validation failure | `bad_request` |

**Audit.** Every public call — allowed or denied, at every stage of the pipeline — MUST append an audit event to the hash chain of (§11), recording caller fingerprint, account, tool, decision, and error code, with bodies referenced (content-addressed), never copied. Refused LAN connection attempts are audited even though they die before reaching MCP. The public dispatch path is one of the three audit write sites (§11); no §5 code path may respond without its audit write.


---

## 6. Integrations

An integration is an upstream MCP server the owner connects to their node: a calendar, a task tracker, anything speaking MCP. The node is an MCP **client** to these upstreams (official Go SDK, go-sdk v1.8.0) and re-serves a curated subset of their capabilities to contacts through the public surface (§5). Two rules govern everything in this section: **nothing an upstream offers is ever exposed to a caller by default**, and a contact gains access to passthrough and agent-answered capabilities only through the per-integration permission `integration.<slug>` — HDTP §8's `integration.<name>`, with the name fixed to the integration's slug. Mapped-mode capabilities are the exception: they serve HDTP's own core vocabulary and are gated by the corresponding HDTP §8 core permission (§6.6). Authorization is evaluated at the single Cedar call site `policy.Allow` (static policies, dynamic entities — §3); the store tables involved are `integrations`, `catalogs`, `exposures`, and `pending_requests` (§11).

### 6.1 The integration object

| Field | Meaning |
|---|---|
| `slug` | Stable snake_case identifier chosen at creation. It prefixes exposed tool names (§6.5) and names the permission `integration.<slug>`; it MUST NOT change after creation. |
| `transport` | `streamable-http` \| `sse` \| `stdio-supervised` |
| `endpoint` / `command` | URL for the HTTP transports; the command line (plus environment) for `stdio-supervised` |
| `auth` | `none` \| `static` (owner-supplied header credential) \| `oauth` (§6.3) |
| `status` | Node-local, never wire-visible: `disabled` \| `connecting` \| `ok` \| `auth_error` \| `unreachable` (§6.3, §6.10) |
| catalog / exposure | Pointers to the latest catalog snapshot vN (§6.4) and the active exposure set vM (§6.5) |

Transports map onto the SDK's struct-literal client transports:

| `transport` | SDK type |
|---|---|
| `streamable-http` | `mcp.StreamableClientTransport{Endpoint, HTTPClient, MaxRetries, DisableStandaloneSSE, OAuthHandler}` |
| `sse` | `mcp.SSEClientTransport{Endpoint, HTTPClient}` |
| `stdio-supervised` | `mcp.CommandTransport{Command, TerminateDuration}` |

The node MUST leave the standalone SSE stream enabled (`DisableStandaloneSSE` false): on stateful upstreams (protocol ≤ 2025-11-25) that stream is the only carrier of `notifications/tools/list_changed`, which the catalog machinery depends on (§6.4). Only a stateless SEP-2575 upstream delivers it over the `subscriptions/listen` POST stream instead. `static` credentials and all OAuth tokens are stored encrypted under the keyring master key (§11, §12) and never appear in config files or logs.

### 6.2 Supervised stdio children

A `stdio-supervised` integration runs a local child process (newline-delimited JSON over stdin/stdout via `mcp.CommandTransport`). The node is the child's supervisor:

- The child receives only the command, arguments, and environment variables configured for the integration; `static` credentials destined for the child are decrypted at spawn time and passed via that environment, never written to disk.
- On unexpected exit the node MUST restart the child with backoff; repeated failures mark the integration `unreachable` and follow §6.10. Shutdown uses `TerminateDuration` for a graceful stop before killing. Every crash and restart is audited (§11).
- Children MUST run under resource caps (memory/CPU) so a misbehaving upstream cannot starve the node. Defaults, each configurable per integration: restart backoff exponential from 1 s to a 60 s cap; give-up after 5 consecutive failures within 5 minutes, marking the integration `unreachable` (§6.10); per-child caps of 512 MiB RSS and 1 CPU. Both are enforced by `setrlimit` as the closest approximations a plain binary can apply without cgroups: `RLIMIT_DATA` for the memory cap and `RLIMIT_CPU` for the CPU one. `RLIMIT_AS` is NOT usable here — it bounds reserved address space rather than memory in use, and a Node child needs more than 8 GiB of address space to start at all, so no `RLIMIT_AS` value both admits an `npx` child (§12.3) and bounds anything.
- The slim container image is static and ships no runtimes. stdio servers that need `node`/`npx` or `uv`/`uvx` require the **`-full` image tag** (which ships node and uv), or the owner mounts the runtime or a native server binary into the container (§12).

### 6.3 Upstream authentication and OAuth

`auth: none` sends no credential. `auth: static` attaches an owner-supplied header credential (e.g. a bearer token or API key) to every request. `auth: oauth` implements the MCP authorization spec, revision **2026-07-28**, exactly as verified:

| Requirement | Level |
|---|---|
| RFC 9728 protected-resource metadata discovery | MUST (clients MUST use it to discover the authorization server) |
| Authorization-server metadata: RFC 8414 **or** OIDC Discovery | Client MUST support both |
| Client identity | Prefer **Client ID Metadata Documents**; else pre-registered client ID; RFC 7591 DCR is deprecated, kept only as a last-resort fallback |
| PKCE with S256 | MUST; MUST refuse to proceed if the AS metadata lacks `code_challenge_methods_supported` |
| RFC 8707 `resource` parameter | MUST, in both the authorization and the token request |
| RFC 9207 `iss` validation on the authorization response | MUST |
| Passing a caller's token through to an upstream | MUST NOT — ever. Tokens presented to the node (owner-MCP bearer tokens, portal sessions) never leave the node; each upstream gets its own credential. |

The SDK carries all of this: the node wires an `auth.OAuthHandler` into `StreamableClientTransport.OAuthHandler`. For interactive upstreams it uses `auth.NewAuthorizationCodeHandler`, which performs the 401/`WWW-Authenticate` parse, RFC 9728 + AS-metadata discovery, client registration modes, PKCE, the `resource` parameter, and token refresh — the node supplies only the code-fetching callback. For service-to-service upstreams the node uses `extauth.ClientCredentialsHandler`.

**Portal Connect flow** (§8): the owner adds the integration and clicks **Connect**. The node probes the endpoint, runs discovery, and redirects the owner's browser to the authorization server. The AS redirects back to the portal's callback route, which hands `code`/`state`/`iss` to the handler; after `iss` and `state` validation the code is exchanged (with `resource`) and the tokens are stored encrypted (§6.1). Status moves to `ok` and the first catalog snapshot is taken (§6.4). Refresh happens automatically through the handler's token source; a failed refresh or a mid-operation 401 sets `status: auth_error`, makes the integration's exposed tools behave per §6.10, surfaces a **Reconnect** action in the portal — the owner MCP has no reconnect tool; its `list_integrations` shows the status (§8) — and writes an audit event.

### 6.4 Catalog snapshots (vN)

On every successful connect the node walks the upstream's tools (`ListTools` / the `Tools` iterator) and computes, per tool, a content hash over **name + description + inputSchema** (canonical key-sorted JSON serialization). The resulting **catalog snapshot vN** — the tool set with definitions, hashes, and annotations as captured — is an immutable row in `catalogs`; a new snapshot is minted whenever the tool set or any per-tool hash changes. Annotations are captured but excluded from the hash: they are untrusted UI hints (§6.9), so drift in them never trips the stale guard.

Snapshots refresh: on connect, when `ClientOptions.ToolListChangedHandler` fires (which is why standalone SSE stays enabled, §6.1), on the periodic health cycle (§6.10), and on manual refresh from the portal. The portal shows the current snapshot — its version and its tools — and does not render a diff between snapshots. Callers never see live upstream state: everything shown in a contact's `tools/list` comes from snapshotted definitions, so the surface a caller sees is exactly the surface the owner confirmed.

### 6.5 Exposure sets (vM) and the stale guard

An **exposure set vM** binds to exactly one catalog snapshot vN and lists what is actually served. The portal's picker is two columns — snapshot tools on the left, exposed capabilities on the right — and the right column starts **empty**: nothing is exposed by default. Each exposed entry records the upstream tool, the serving mode (§6.6), a mapped entry's recipe binding (§6.7), an optional `fallback` serving mode for agent-answered entries (`passthrough` or `mapped` only — falling back to agent-answered would be circular; default none, §6.8), and the exposed name. For passthrough and agent-answered entries the name defaults to `<slug>_<tool>`, normalized to snake_case, editable, unique within the account's exposed surface; a mapped entry is always exposed under the exact HDTP §6.2 capability name it implements (`book_slot`, never `<slug>_book_slot` — §6.6, §6.7). Every edit mints vM+1; activating a set rebuilds the per-caller servers and emits `notifications/tools/list_changed` to connected callers (§5). Contacts holding `integration.<slug>` see all of that integration's exposed capabilities; per-tool grants are deliberately not in v1.

**Stale guard.** When a new catalog snapshot arrives, each exposed entry's confirmed hash is compared against the same tool in the new snapshot. A missing tool or a changed hash makes the entry a **stale mapping**: it is withheld from every caller's `tools/list`, in-flight or racing calls return `unavailable` (HDTP §12 records this use for a tool an implementation is temporarily withholding), and the transition is audited. The portal marks each stale entry and offers a **one-click reconfirm** of every stale entry (the route, `POST /integrations/{id}/reconfirm`, also takes named entries; the portal does not offer them one at a time), which re-binds the entry to the new snapshot in a fresh exposure set vM+1 — also audited. A silently changed upstream can therefore never widen what contacts reach.

### 6.6 Serving modes

Each exposed capability is served in exactly one of three modes:

| Mode | The node… |
|---|---|
| **passthrough** | validates the caller's arguments, forwards the call to the upstream tool, relays the result |
| **mapped** | implements an HDTP core capability through a provider plus a per-server recipe (§6.7) |
| **agent-answered** | parks the call as a `pending_request` for the owner's connected agent to answer (§6.8) |

**Passthrough.** The node registers exposed tools on the SDK's low-level server path, which does **not** validate arguments (only the generic `mcp.AddTool[In,Out]` does). The node therefore MUST validate caller arguments itself, using `github.com/google/jsonschema-go` (unmarshal the stored schema, `Resolve`, `Resolved.Validate`) — and always against the **snapshotted** `inputSchema` the exposure was confirmed on, never a live upstream schema. Invalid arguments fail `bad_request` without touching the upstream. Valid calls are forwarded under the upstream tool name from the snapshot; results are relayed to the caller as data (untrusted content, boundary limits per §11). Upstream tool errors are relayed as tool errors; transport failures surface as `unavailable`.

**Mapped** and **agent-answered** are specified in §6.7 and §6.8. A mapped entry is exposed under its HDTP §6.2 capability name and authorized by the corresponding HDTP §8 core permission (`calendar.availability`, `calendar.book`, …), never by `integration.<slug>`, which gates only passthrough and agent-answered entries. In all three modes the call is admitted first by `policy.Allow` and the call-time permission re-check (§3, §5).

### 6.7 Mapped providers, the mapping DSL, and recipes

Mapped mode exists so a contact sees HDTP's own vocabulary — never a vendor's. Two providers ship in v1:

**Calendar provider** — implements `check_availability`, `book_slot`, and `cancel_booking` per HDTP §6.2. Availability answers are computed from the upstream response inside the requested window, earliest first, returning **at most 5 candidate slots** (HDTP §12), never raw free/busy. No working-hours filter is applied: the connected calendar is the authority on when its owner meets, so a calendar whose product encodes the owner's hours answers with bookable slots, and a raw free/busy calendar offers any free time the owner has not blocked. `book_slot` creates the event upstream, honors `msg_id` idempotency — the recorded acknowledgment (`booking_id` plus ICS) lives in the `idempotency` table (§11.2) for replay — and returns `booking_id` plus an ICS the provider synthesizes from the confirmed slot and subject; the store keeps no booking table (§11), so `booking_id` is an opaque wrapper over the upstream event identifier, which `cancel_booking` maps back.

**Status provider** — serves `get_status` (HDTP §6.2) from the owner's node-local status by default; a recipe MAY source it from an upstream tool instead.

**Field-mapping DSL.** A recipe binds provider fields to upstream request/response fields with a deliberately tiny declarative DSL: **field-to-field bindings and constants, nothing else** — no expressions, no conditionals, no scripting. Anything beyond that (slot computation, policy filtering, ICS synthesis) lives in provider code, where it is testable and cannot be smuggled in via configuration.

**Per-server recipes.** Because upstream tool naming is not uniform, recipes are per-server maps. The three verified Google Calendar servers:

| Server | Transport / auth | `check_availability` | `book_slot` | `cancel_booking` |
|---|---|---|---|---|
| Google official Calendar MCP — `https://calendarmcp.googleapis.com/mcp/v1` (Developer Preview) | streamable-http / oauth | `suggest_time` | `create_event` ⚠️ | `delete_event` |
| nspady/google-calendar-mcp (`@cocal/google-calendar-mcp`) | stdio-supervised (default) or HTTP / oauth (Desktop-app credentials) | `get-freebusy` | `create-event` | `delete-event` |
| taylorwilsdon/google_workspace_mcp (`workspace-mcp`) | stdio-supervised or streamable-http / oauth (several modes) | `query_freebusy` | `manage_event` (`action=create`) | `manage_event` (`action=delete`) |

⚠️ The official server's **write scope for `create_event` is unverified** (its configuration docs showed only read-only and free-busy scopes); the shipped recipe carries this caveat and implementations MUST confirm the scope during setup before enabling booking on it. Note the semantic split: `suggest_time` already returns candidate times (a natural fit for the ≤5-slot rule), while the free-busy tools require the provider to compute candidate slots from busy blocks, the requested window and duration.

### 6.8 Agent-answered mode

Some capabilities have no API behind them — they need the owner's agent's judgment. An agent-answered call is parked and relayed:

```mermaid
sequenceDiagram
    autonumber
    participant C as Contact's agent
    participant N as hdtp-gateway node
    participant OA as Owner's agent (owner MCP)

    C->>N: tools/call on an agent-answered capability [mTLS]
    N->>N: policy.Allow, then create pending_request (TTL)
    N-->>OA: notifications/resources/updated for hdtp://pending
    OA->>N: read pending (resource or list_pending)
    OA->>N: answer_request(id, result)
    N-->>C: relayed tool result
    Note over N: no answer within the wait budget - fallback chain<br/>(messaging never enters this path, §5.6)
```

Mechanics, in order:

1. After `policy.Allow`, the call becomes a `pending_requests` row (caller fingerprint, exposed capability, arguments, creation time, TTL) and the caller's request is held open. Arguments are peer-supplied untrusted content and are handed to the owner's agent labeled with the contact's message-vs-instruction trust flag (§7).
2. The owner's agent learns of it by asking: `wait_for_updates` (§8.4) wakes as the row is written and counts it as `pending_requests`, and `list_pending` and the `hdtp://pending` resource read the rows. The owner MCP is stateless (§8.5), so nothing is pushed; an agent that is attached is one that keeps asking.
3. The agent answers via the owner-MCP tool `answer_request(id, result)` (§8); the node relays the result to the waiting caller, closes the row, and audits the exchange. The call and the answer may reach different node processes sharing the store (§11.1): the answer is written to the row, the held call re-reads its row on every event for its account (§7.8) and, having handed the answer on, says so with an event of its own, and `answer_request` reports `relayed` only on that word, waiting up to 3 s for it — past that the answer is recorded and reported late.
4. If the synchronous wait budget expires with no answer — or no agent is attached, meaning no owner-MCP request has arrived, at any node process on the store, for a minute, longer than a `wait_for_updates` may hold one call (the time of the last request is kept in the store, written at most once per 5 s per process; one host's write is compared with another host's clock) — the **fallback chain** runs: the exposure's configured `fallback` serving mode (§6.5) if one is set, otherwise the call fails `unavailable`. Messaging never enters this path: `send_message` and `send_media` are built-ins that execute against the store (§5.6), so a message is always stored and answered `delivered | queued_for_human` (HDTP §6.2, §7) regardless of whether the owner's agent is online — the fallback chain applies only to integration-backed capabilities.

Defaults, each configurable per exposure: the caller's call is held for a synchronous wait budget of **30 s**; the `pending_request` row's TTL is **10 minutes**. The wait budget — not the TTL — triggers the fallback chain: when it expires, the caller receives the fallback result (point 4). The TTL only bounds how long the row stays open for a late answer, which is recorded and audited but no longer relayed to the departed caller.

### 6.9 Safety rails

Upstream tool annotations are captured into snapshots and used **only** to sort and badge the exposure picker:

| Annotation | Default | Go field |
|---|---|---|
| `readOnlyHint` | false | `ReadOnlyHint bool` |
| `destructiveHint` | true | `DestructiveHint *bool` |
| `idempotentHint` | false | `IdempotentHint bool` |
| `openWorldHint` | true | `OpenWorldHint *bool` |

The default-true hints are **pointer fields**: when re-serving a tool the node MUST proxy `DestructiveHint`/`OpenWorldHint` without collapsing nil to false (nil means "assume destructive / open-world"). Annotations are **untrusted** — the spec is normative here — so the node MUST NOT gate any permission or authorization decision on them; they are UI-sorting input only. Alongside the hints, the portal applies **name heuristics** (flagging tools whose names suggest writes: create, delete, update, send, pay, transfer, and similar) — equally advisory.

Exposing a tool flagged write-capable by either signal, or connecting an integration holding broad credentials, triggers an explicit portal warning; the owner must acknowledge it to proceed, and the **acknowledgment is recorded** in `audit_events` (§11). The standing recommendation, restated in every recipe: use the **narrowest credential that works** — free-busy or read-only scopes when only availability is exposed, dedicated accounts, minimal grants.

### 6.10 Health and withholding

The node pings each connected integration on a periodic cycle (MCP ping for HTTP transports; a child-process exit counts as failure for stdio). A failed integration moves to `unreachable` (or `auth_error`, §6.3) and its exposed capabilities immediately fail with `unavailable`. If the failure persists past a threshold, those tools are additionally **withheld** from callers' `tools/list` — emitting `list_changed` (§5) — so contacts stop seeing capabilities that cannot run. Recovery reconnects, refreshes the catalog (which may trip the stale guard of §6.5 if the upstream changed while away), restores the surface, and — like every transition in this section — is audited (§11).

Defaults, each configurable per integration: ping every **60 s**; withhold from `tools/list` after **5 consecutive failures** (≈5 minutes of outage).


---

## 7. Messaging and media

Messaging on the public surface follows HDTP §7 unchanged: a conversation is a `thread_id` (UUID, minted by whoever sends first) plus an optional human-readable `topic`, stored by both sides, and each message is one `send_message` or `send_media` call against the peer's server. Whether a call arrives plain over mTLS or inside a sealed envelope (§4), the node opens it to the same inner tool call and dispatches it with identical semantics. This section specifies what the node does with that traffic: storage, deduplication, sender labeling, media handling, fan-out to consumers, and retention.

### 7.1 Threads and messages

The node persists conversations in the `threads` and `messages` tables (§11). An inbound `send_message` passes, in order: caller identity resolution (§3), permission check via the single `policy.Allow` call site (§3), HDTP §12 limit checks at the boundary, the idempotency check of §7.2, then a store append and an event-bus publish (§7.8). Responses use the HDTP §6.2 statuses (`delivered | queued_for_human`).

Outbound messages originate from exactly three places: the portal composer (§8.2), the owner-MCP `send_to_contact` / `call_contact` tools (§8.4), and agent-answered integration flows (§6). For outbound delivery the node is the MCP client: it mints the `msg_id`, retries with backoff until the sender-chosen `expires` (default 24 h, HDTP §7), and then reports failure to the owner. There is nowhere to fall back to: HDTP 1.0 has no relay role and no store-and-forward gateway, because one would see every sender, recipient and timestamp for its trouble (HDTP §9). The same `msg_id` MUST be reused across every retry, so the recipient's idempotency handling makes the retry path safe.

### 7.2 Idempotency

The `messages` table carries a `unique(account, contact, direction, msg_id)` constraint (§11). A call bearing an already-seen `msg_id` is **acknowledged, not re-executed** (HDTP §6.2): the node MUST return an acknowledgment equivalent to the original outcome and MUST NOT append a second message row or re-run any side effect. This applies to every `msg_id`-bearing tool: `send_message` and `send_media` are backed by the `messages` constraint; `book_slot`, which appends no message row, records its acknowledgment in the `idempotency` table instead (§6.7, §11.2). The uniqueness scope is per (account, contact, direction): two different contacts reusing the same `msg_id` value do not collide, and neither do the two sides of one conversation. `direction` is in the key because `msg_id` is chosen by whoever sent the message (§7.1), so each side has its own namespace; without it, a message the node was about to send collided with one the contact had already sent, and the idempotency lookup returned the peer's row — reporting the owner's message delivered when it had never been written. Inbound idempotency is unaffected: a repeated inbound `msg_id` is still the same key. The envelope open order's own `msg_id` idempotency step (§4) and this store constraint enforce the same rule at two layers; the store constraint is authoritative.

### 7.3 Sender labels

The wire-level `sender: agent|human` label is **derived from the surface that originated the send — it is never a parameter** on any internal surface. The portal composer produces `sender: human`; sends initiated through the owner MCP or an agent-answered flow produce `sender: agent`. No internal tool or form accepts a `sender` argument, so an agent cannot label its output as its owner. On inbound messages the peer's label is stored and displayed as claimed — honest labeling is the sending side's obligation under HDTP §7.

### 7.4 Media and the blob store

Media bytes live in a content-addressed blob store: each blob is stored at a path derived from the SHA-256 of its content, with metadata in the `blobs` table (§11). Content addressing means identical content is stored once, referenced many times. Inline media (`data`, base64) is accepted up to the HDTP §12 limit of 5 MiB; larger media travels by `url` reference only. Oversize inline payloads are rejected with `too_large`. Each account has a storage quota — default **10 GiB**, configurable (§8.2) — enforced at write time; media that would exceed it is refused. Outbound `send_media` reads from the same store.

### 7.5 URL media is never auto-fetched

A `url` received in `send_media` is **never fetched automatically**. The rationale is SSRF: the node frequently runs inside a home LAN, and auto-fetching attacker-supplied URLs would let any contact drive server-side requests into loopback services, RFC 1918 ranges, or cloud metadata endpoints. Instead:

- Fetching is **click-to-fetch**: it happens only on an explicit owner action in the portal (§8.2).
- The fetcher MUST enforce a size cap, MUST block private ranges (loopback, RFC 1918, unique-local, link-local — checked against the *resolved* address, and the connection pinned to that vetted address so DNS rebinding cannot bypass the check), and MUST count fetched bytes against the account quota, storing them content-addressed (§7.4).
- Fetched or not, the URL string itself is stored raw and treated as untrusted text (§7.6).

### 7.6 Inbound text: cap, raw storage, escape on render

Inbound text is capped at 16 KiB (HDTP §12), enforced at the boundary before any processing; beyond the cap the call fails with `too_large`. Within the cap, text is stored **raw** — the node MUST NOT sanitize, strip, or rewrite content on write, so the record stays faithful for audit and export. All escaping happens at render time: the portal renders inbound strings (text, topics, notes, filenames) through templ's contextual escaping, always as quoted content, never interpreted as markup. Sanitize-on-write is explicitly rejected because it destroys evidence and still misses sinks; escape-on-render covers every sink at the sink.

### 7.7 Trust-label wrapping for the owner's agent

Every inbound payload handed to the owner's agent — via owner-MCP resources or tools (§8) or an agent-answered flow (§6) — MUST be wrapped with the sending contact's identity and that contact's **message-vs-instruction trust flag** (set per contact, default *messages-only*; managed via the switchboard and `set_trust_flag`, §8). Under the default, the content is presented to the agent as data to convey to the owner, never as instructions to act on. In no case may inbound strings be concatenated into the agent's instructions — the HDTP §11 prompt-injection rule applies to the gateway's own hand-off exactly as it applies to UIs.

### 7.8 The event bus

Every messaging event (new message, new media, pending request, contact-state change, a contact's substantive call) is published on the event bus. It has two consumers, and each only wakes a waiter, which then re-reads the store — the bus says "look", the store says what, so an event dropped by a full subscriber costs a wake and never a fact:

```mermaid
flowchart LR
    PD["Public dispatch<br/>(inbound tool calls)"] --> BUS(("event bus"))
    OS["Owner surfaces<br/>(portal · owner MCP)"] --> BUS
    IF["Integration flows<br/>(pending requests, §6)"] --> BUS
    BUS --> SSE["Portal SSE<br/>(live inbox, §8.2)"]
    BUS --> RES["Owner MCP<br/>wait_for_updates (§8.5)"]
```

The audit trail is not a consumer: its writes live in the dispatch paths and the store mutation layer (§11.5).

**The change log.** Every event is also a row of the store's `changes` table, so that every node process sharing the store (§11.1) hears it. Publishing appends the row and wakes this process's waiters at once; each process reads the rows other processes appended every 250 ms, and on PostgreSQL wakes sooner on a notification the appending transaction sends at its commit (`LISTEN`/`NOTIFY`; the poll, not the notification, is what is relied on). A row's id is store-assigned and ids commit in order — on PostgreSQL every append takes one advisory lock first — so a reader past an id never misses a row committed later below it. The id is the cursor `wait_for_updates` answers with (§8.5). Rows are kept for a week; an idle reader's poll costs about 23 µs on SQLite.

### 7.9 Retention and deletion

Retention is configured **per account** (§8.2, storage settings), unlimited by default: when a finite window is set, messages and their blobs past it are deleted locally, and quota pressure is resolved against the same policy. The forward-secrecy mitigation of §13.2 — what is not stored cannot be decrypted later — leans on this setting; owners for whom recorded-ciphertext exposure matters should set a finite window. All deletes are **local**: removing a message, thread, or contact deletes this node's copy only. There is deliberately no wire protocol for remote deletion — the peer's copy is the peer's, and the UI never suggests otherwise (§13).

## 8. Internal surface: portal and owner MCP

The internal surface is how the owner (human or their agent) operates the node. It has two halves: a server-rendered web **portal** for humans, and an **owner MCP** endpoint for the owner's agent. Both surfaces drive the same store and emit the same audit records; neither is reachable through the public HDTP surface (§5).

### 8.1 Portal

The portal is server-side rendered from Go templates. It ships **zero external assets**: all CSS, JavaScript, and fonts are compiled into the binary, so the portal is fully functional air-gapped — no CDN, no external fonts, no telemetry (§12). The pages that need behaviour — the setup and sign-in ceremonies, and the live inbox — carry small hand-written inline scripts. An earlier draft named htmx here; it was never vendored, and a WebAuthn ceremony is a sequence of promises over binary values that no declarative attribute library expresses, so the dependency would have bought nothing the portal uses. Live updates (inbox, pending requests, probe results) arrive over SSE fed by the event bus (§7.8).

### 8.2 Page map

| Page | What it does |
|---|---|
| Setup wizard | First-run flow; auto-shows while the node has zero passkeys; reachable only from loopback or with a one-time setup URL minted by `passkey reset-wizard` (§12) |
| Dashboard | At-a-glance node state, for the identities the signed-in owner administers: what needs the owner first (people waiting, certificates to renew or sign), each with the button that does it; the identities, their active contacts, the people waiting and the certificates that need a wallet as four counts; a card per identity with its address, its certificate's state and days left (the renewal flag is the reader's) and, with more than one identity, its counts; and reachability and posture in one strip. A read that fails is shown as failed, never as zero (the trail is Audit's) |
| Inbox | Threads and messages, live over SSE; composer (sends labeled `human`, §7.3); click-to-fetch for `url` media (§7.5); one page of the 50 most recently active conversations, a search reaching the rest, each with its unread count read at runtime from the conversation's read marker (`threads.last_read_seq`, local and never wire-visible) and stopped at 50 ("50+"), and the sidebar's Inbox count the page's sum, stopped at the same 50 ("50+", as BatonDeck's), and "N+" under it when a conversation past the page has unread too; showing a conversation marks it read through the newest message shown, and listing them marks nothing; the owner MCP's `read_thread` and the thread view (`GET /api/threads/{id}`) mark their thread read through the newest message they return |
| Contacts | Accept an invite link, or connect from a card (§9.3); per-contact permission switchboard, preset assignment, message-vs-instruction trust flag, tier; block, unblock and remove on each contact's page, approve and reject on the Requests tab (§9.1, HDTP §8) |
| Invites | Issue, label, revoke; expiry / max_uses / auto_accept / preset (§9) |
| Card builder | vCard fields with auto-filled `X-PACT-*` properties; export as .vcf / QR / link (§9) |
| Integrations | The current catalog snapshot vN, exposure picker over the exposure set vM with stale entries marked, per-server recipes, warnings with recorded acknowledgment; stale mappings withheld until re-confirmed (§6) |
| Settings · security | `seal` knob (`none\|optional\|required`), `client_cert` knob (`required\|preferred\|off`), LAN connections flag (§3, §4, §10, §12.2) |
| Settings · reachability | Public URL, tunnel adapter selection, adapter credentials (sealed), reachability probe (§10, §12.2) |
| Settings · identity | The node's identities: each account's slug, root, the endpoint its leaf names, the leaf's `notAfter`, and whether a renewal is due (§3.9). Creating a second identity, by the same procedure `account create` runs. A new identity is not served until its wallet has issued it a leaf, and the page says so. There is nothing to rotate here: the identity is a root the node does not hold, and a leaf is replaced by the wallet signing a new one (`account csr`, `account install-leaf`, §12) |
| Settings · ingress | Ingress pairing via one-time token (§10) |
| Settings · owners | Owners, tagged passkeys, named owner-MCP bearer tokens (§3) |
| Settings · storage | Blob quota and per-account retention (§7) |
| Settings · audit | Audit trail browser (§11): each id a row carries — an owner, an identity, a contact, a token, a passkey — shown by its name, with the id in its tooltip and a copy button; an id whose owner, token or contact has gone, or whose list the reader may not see, is shown as such, with its id shortened beside it |

### 8.3 Portal authentication

The portal requires an owner session on **every** bind, loopback included. The only requests served without one are the sign-in and setup ceremonies (`/login/*`, `/setup/*`), the static application shell that delivers them, and the health probe; everything else — including all of `/api` — answers `identity_required`. CSRF protection stays on regardless, so a hostile local page cannot drive the portal cross-origin.

- **Loopback bind:** a session is still required. Reaching the portal over loopback is not authentication: on a shared host every local process can open that socket, and a sidecar that forwards a published port into the container's loopback — which is how a tunnelled deployment reaches a §8.3-compliant portal at all — extends "local" to whoever can reach the forwarder.
- **Any non-loopback bind:** the node **refuses to start** unless passkey authentication (WebAuthn, §3) and TLS are both configured. This is a startup invariant, not a per-request check — there is no window in which the portal is exposed unauthenticated. Configured TLS is served: the certificate and key are loaded when the node starts, a pair that does not load refuses the start and names the files, and the portal (and the health probe that asks it) speaks only TLS — never plaintext in its place.

One window has no session because no credential exists yet: the **zero-passkey** state, in which the portal serves only the setup wizard under §8.6's gate. Registering the first passkey closes it permanently — after that, only a recovery token re-opens the wizard (§8.6).

The owner's deployment matrix (portal and public surface both local, both tunneled, or split) is configuration over these same rules (§10, §12). Refused connection attempts are audited (§11).

### 8.4 Owner MCP: tools

The owner MCP endpoint authenticates with **named, revocable bearer tokens** (§3), created and revoked in the portal or CLI, on **every** bind including loopback (§8.3). Its tools mirror the portal:

| Area | Tools |
|---|---|
| Messaging | `get_inbox`, `read_thread`, `send_to_contact`, `call_contact`, `wait_for_updates`, `digest` |
| Identity | `list_accounts`, `identity_certificate` |
| Contacts & permissions | contact management — `list_contacts` (named fields, the cloud's where the node holds them: never the row id, the pinned key, the card or the invite), `add_contact`, `approve_contact`, `reject_contact`, `block_contact`, `unblock_contact`, `remove_contact`, `rename_contact` (§9.1) — `set_permissions` (the portal's switchboard: a name it does not offer is refused), `set_trust_flag`, `refresh_contact` (below) |
| Contacts at a new address | `list_pending_addresses`, `approve_address`, `reject_address` — the owner's answer to a contact that moved while this identity's policy is *ask* (HDTP §5.3, §9.1) |
| Invites & card | `create_invite` (answers the cloud's shape — id, url, expires_at — the link at this node's public address, and mints nothing when there is none), `list_invites`, `revoke_invite`, `export_card` |
| Requests | `list_pending`, `answer_request` |
| Integrations | `list_integrations`, `set_exposure` |
| Audit | `audit_query` |
| Passkeys | `list_passkeys`, `remove_passkey` — listing and removal only; **registration is portal-only** (§8.6) |

Every backticked name in this table is a tool the owner MCP registers, and every tool it registers is in the table once; a test holds the two to each other.

`refresh_contact` re-fetches the card of ONE contact, named by the caller, **when the owner asks**: the same function as the *Refresh now* button on that contact's portal page. Nothing refreshes more than one contact, and the node never does it by itself: a pin is confirmed when it is needed, and a newer leaf arrives on use (HDTP §14.3). A refresh can learn a renewed leaf, a changed name or a changed seal policy; it cannot move the pinned root or the address. It answers `unchanged`, `updated`, `renewed`, `unreachable` or `refused` (with why), and the last two leave the pin exactly as it was.

No tool on this surface takes a `sender` argument; everything sent through it is labeled `agent` (§7.3). Payloads returned to the agent carry the per-contact trust-label wrapping of §7.7.

### 8.5 Owner MCP: resources and waiting

The owner MCP is served **statelessly**, exactly as the public surface is (§5.5): every request carries its bearer token and is answered on its own, no `Mcp-Session-Id` is issued or read, GET and DELETE are `405`, and both MCP eras — 2026-07-28 and the handshake revisions — are served. Revoking a token therefore refuses its very next request (§3.4).

Four resources are readable on demand:

```
hdtp://inbox        hdtp://thread/<id>        hdtp://pending        hdtp://requests
```

`hdtp://inbox` summarizes unread messages per account and `hdtp://thread/<id>` is one conversation (§7.8); `hdtp://pending` lists agent-answered `pending_requests` awaiting the owner's agent (§6.8); `hdtp://requests` lists incoming contact requests awaiting the owner's approval (`pending_in`, §9.1). A contact parked at a new address (§9.1) is read with `list_pending_addresses`, and `wait_for_updates` and `digest` count them as `pending_addresses`.

Nothing is pushed. The server declares `tools` and `resources` with neither `listChanged` nor `subscribe` — a stateless server has no stream to carry them — and has no subscribe method. What an agent waits for, it waits for with `wait_for_updates`: the call holds for up to 25 seconds until something moves, then answers with what moved since the caller's cursor — the threads with new messages and the calls contacts made — so a loop is one call per wake and a reconnect loses nothing. The cursor is an id of the change log (§7.8), the same in every node process on the store; a call without `since` answers at once with the newest. A wait that ends on the clock answers with the newest change it read, never a time, and a cursor the log does not hold — older than its week, or past its newest change — is answered at once with `cursor_expired` and the newest as the cursor to wait from. `get_inbox`, `read_thread`, `list_pending` and the resources return the same data on demand. `read_thread` is the owner's agent reading, which is the owner reading: it marks the thread read through the newest message it returns, as showing a conversation in the portal does.

### 8.6 Passkey registration boundary

The wizard opens under exactly two conditions. While the node has **zero** passkeys it is reachable from loopback, or with a valid setup token from anywhere; once any passkey exists it is reachable **only** with a valid recovery token minted by `passkey reset-wizard` (§3.1), never by reaching loopback and never with a leftover first-run token. The token is consumed by the registration it authorises.

Passkey **registration** happens in the portal only — never over the owner MCP; the CLI participates by minting the one-time setup URL that leads to the portal ceremony (`passkey reset-wizard`, §12). Registration is a WebAuthn ceremony requiring an authenticator, which a bearer-token MCP session cannot perform; the boundary also guarantees that an owner-MCP token can never mint a durable credential for itself. Listing and removing passkeys are available on all three management surfaces (portal, owner MCP, CLI; §3, §12).

### 8.7 Everything audited

Every portal mutation, every owner-MCP tool call, and every authentication event on this surface — logins, token use, wizard runs, refused binds and refused connection attempts — lands in the append-only audit chain (§11). The internal surface has no unaudited path.


---

## 9. Contacts, invites, and the card

Everything in this section is per-account state: contacts, invites, and the card each belong to exactly one account on the node (§3), and a caller is resolved to a relationship state by the unified caller identity rule of §3 — envelope-signature fingerprint or client-cert SPKI fingerprint, and when both are present they must match. Wire behavior follows HDTP §5; the backing `contacts` and `invites` tables are defined in §11, and every lifecycle transition described here MUST produce an audit event (§11).

### 9.1 Contact lifecycle

The node tracks one relationship state per (account, peer fingerprint), exactly as HDTP §5 defines it:

```mermaid
stateDiagram-v2
    [*] --> none
    none --> pending_out : owner redeems a non-auto_accept invite /<br/>sends request_contact
    none --> pending_in : peer redeems our invite /<br/>calls request_contact
    none --> active : either side redeems an<br/>auto_accept invite
    pending_in --> active : owner approves<br/>(peer told: contact_accepted)
    pending_in --> blocked : owner rejects<br/>(peer told: contact_rejected)
    pending_in --> none : request expires / owner removes
    pending_out --> active : peer approves<br/>(contact_accepted)
    pending_out --> blocked : peer rejects<br/>(contact_rejected)
    pending_out --> none : expires / owner withdraws
    active --> blocked : owner blocks (silent)
    blocked --> active : owner unblocks a row<br/>that was once active
    blocked --> none : owner unblocks a row that never was /<br/>owner removes (silent)
    active --> none : remove_contact (either side)
```

Relationship state selects the serving tier — which of the per-caller MCP servers of §5 the caller gets:

| State toward caller | Tier | Caller sees |
|---|---|---|
| `none` (unknown fingerprint) | guest | exactly `redeem_invite` + `request_contact`, plus the `sealed_call` wrapper (§4) |
| `pending_in` | guest | guest tools; a repeated `request_contact` from the same identity MUST NOT create a duplicate request and is answered `pending_approval` (HDTP §12) |
| `pending_out` | pending | `contact_accepted`, `contact_rejected` |
| `active` | contact | tools filtered by this contact's switchboard (§5); `update_contact`, `remove_contact`, `get_card` always |
| `blocked` | blocked | served exactly as guest — indistinguishable on the wire (`blocked_or_unknown`, HDTP §12) |

An unanswered request expires after **30 days** by default, configurable per account from 1 to 365 days (Settings · Storage & retention), returning the relationship to `none` — a `pending_in` request nobody decided, and equally a `pending_out` request of ours nobody answered (HDTP §5 `pending_out --> none : expired`). The window runs from when the request was made (`contacts.requested_at`), not from when the contact was first known — a contact the handshake after an import turns into a request waits the whole window from that moment. The hourly sweep removes them and audits each (`contact_expire`); whoever asked may ask again.

**What a peer granted us** arrives with its `contact_accepted` (HDTP §6.2) and is recorded filtered: only what a grant can be — HDTP §8's names and `integration.<slug>`, the slug as the cloud holds it (`[a-z0-9][a-z0-9-]{0,62}`: no dot, no wildcard) — each once, in the order given (`contacts.TheirPermissions`).

**Approving and rejecting** tell the requester, best-effort and within a few seconds: approval calls their `contact_accepted` with our card and the permissions the row now grants them — the preset the owner chose, or, with none chosen, the grant the request already holds (an invite's) — and rejection calls their `contact_rejected`, which moves their row to `blocked`. Rejection is a demotion, not a deletion (HDTP §5.1): the requester's row becomes `blocked`, so a repeated request from that root is answered as a stranger's and never reaches the owner. Either decision stands if the peer cannot be reached; the owner is told that they were not.

**Blocking** is local-only and silent: the relationship moves to `blocked`, the caller is demoted to the guest tier, and the node MUST NOT send any notification or otherwise let the peer distinguish "blocked" from "never met" (HDTP §5.2, §12). That includes a blocked root holding a live invite link: `redeem_invite` answers it exactly what it answers a stranger holding the same link, and nothing is written and no use is spent. **Unblocking** is silent too, and undoes what the block was: a row that was ever active returns to `active` with its permissions, trust and pin as they were; a row that never was — a request the owner rejected, or an approach of ours the peer declined — is forgotten (`none`), so that root is a stranger again and may ask again, because restoring it to `active` would make a contact of somebody nobody approved. The owner MAY also remove a blocked contact outright (`blocked → none`): pin and relationship are deleted silently, with no wire notification — unlike removal of an active contact. All of these transitions are audited even though nothing crosses the wire. The portal (a contact's page, and the Requests tab) and the owner MCP (`approve_contact`, `reject_contact`, `block_contact`, `unblock_contact`, `remove_contact`) make each of these decisions through one implementation.

**Removal** notifies and unpins both sides. When the owner removes a contact, the node calls the peer's `remove_contact` (the notification) and deletes the local pin; local deletion MUST proceed even if the peer is unreachable — enforcement is "your fingerprint is no longer in my list" (HDTP §5.2). Inbound `remove_contact` from a peer unpins that caller, surfaces the removal to the owner, and is audited.

**A contact's new card** (`update_contact`, HDTP §6.2). The pin has already followed the chain that carried the call — that is decided before dispatch, by the newest-leaf rule at the pinned address and by `accept_new_hosts` at a new one (HDTP §5.3, §14.3) — and the root never moves, so what this tool writes is the card. The card MUST name the pinned root and MUST carry the leaf the pin now holds; otherwise the call is refused and nothing changes. The display name the owner approved is kept: a contact accepted under one name cannot rename itself by pushing a card. From a new address under `ask` the answer is `pending`, sealed like any other result, and the address waits in `pending_addresses` for the owner, who answers it from the portal's Requests tab, the owner MCP (`approve_address`, `reject_address`, §8.4) or the CLI (`account address`, §12) — one decision on every surface, audited as `contact_address_approve` or `contact_address_reject`. Approving re-pins as `auto` would have; rejecting drops the waiting address and leaves the pin as it was. The outbound side is the **move campaign**: after a leaf naming a new endpoint is installed, the node calls `update_contact` on every active contact from the new address, its chain in the envelope; progress is durable per contact (`move_fanout`, §11.2), and `account announce` reports and resumes it. The same walk is the **handshake after an import** (HDTP §9.2): every contact an import wrote is marked as owed it from the time of the import (`contacts.handshake_due`), and the campaign of the first leaf requested after the import walks each one that is not blocked. Whether a leaf moved the identity is the install's decision and is kept with the leaf (`leaves.moved`): a move's campaign walks the owed contacts beside every active contact, and any other leaf's — a renewal — walks the owed contacts and nobody else, since a renewal reaches everyone else in the chain of the next envelope; the node audits a walk as `account_move_campaign` or `account_handshake_campaign` accordingly. A peer that does not pin this identity refuses `update_contact`, which is contact-tier. For a contact the campaign owes the handshake, and for no other, the campaign then sends `request_contact` (the same code the owner's add-by-card uses): the contact becomes `pending_out` BEFORE the request leaves — the state the peer's `contact_accepted` or `contact_rejected` answers (HDTP §5.1), with the request's expiry clock (`contacts.requested_at`) starting then — and that peer decides under its own policy. A request that does not reach the peer is taken back (the row returns to what it was) and tried again by the next run; one the peer refuses with an answer (any code but `pending_approval`, `rate_limited` or `unavailable`) is taken back, recorded `refused`, and not asked again for that leaf. An ordinary contact that refuses the new card is left `pending`, like one not reached. Each contact's audit row (`account_move_fanout`) names what became of it — `updated`, `awaiting_approval`, `requested`, `refused`, `unreached`, or `pending` when it was not reached — and a contact that has been told, or has refused, is not owed the handshake again. A contact whose leaf this host does not hold — any contact, typically an imported one whose leaf did not travel or did not validate — cannot be sealed to: the campaign records it once as `unreached`, never calls it, and `account announce` counts it apart (`unreached=`, and `refused=` for the refusals); it stays pinned by its root and is reached when it next calls. `account announce` on an identity with no leaf yet is refused: there is no campaign to resume until its first leaf is installed. There is no key rotation in either direction — nothing a contact holds is pinned to a key this node keeps (§3.9).

### 9.2 Invites

An invite is one server-side object; because all of its state lives with the issuer, every setting is enforceable and changeable after the link has been shared, and revocation takes effect at once (HDTP §4).

| Field | Default | Semantics |
|---|---|---|
| `expires_at` | 14 days | hard cap 90 days (HDTP §12); later redemptions fail `invite_invalid` |
| `max_uses` | 1 | `1` = one-time; `N` or `∞` = long-term/public link; each redemption becomes its own contact |
| `auto_accept` | false | `true` = redemption immediately creates an `active` contact (conference-badge mode); `false` = each redemption lands as `pending_in` for manual approval |
| `preset` | basic | permission preset applied on accept (§5; HDTP §8) |
| `label` | — | free text shown with incoming requests ("Pune conference 2026") |

The node mints a random token and stores **only a hash of it** — never the token itself (§11). Revocation marks the row revoked rather than deleting it — a contact made through the invite keeps its label — and a revoked token answers `invite_invalid` exactly as a never-issued one does. Invites are created, listed and revoked from the portal and the owner MCP (`create_invite`, `list_invites`, `revoke_invite`; §8), each only on the account it belongs to.

The shareable form is the URL `https://<host>/i/<token>` (and a QR of it). The URL carries the bearer token and nothing else — no personal data, no key (HDTP §4); everything sensitive moves only during redemption, over TLS to the issuer's endpoint.

**Human path — the landing page.** An HTTPS GET of the invite URL, before any redemption, serves the issuer's **signed card** — the vCard bytes plus a detached signature over them by the account identity key (HDTP §4) — rendered for saving into a phone book and as a QR. Viewing the page consumes nothing: no use is decremented and no contact is created. Under the default `client_cert = preferred` (§3) the TLS handshake completes without a client certificate, so plain browsers can load the page; an owner who forces `client_cert = required` cuts plain browsers off, leaving only the machine path — that trade-off is theirs. In edge mode `client_cert` is forced off (§3, §10) and the page is always browser-reachable.

**Machine path — redemption.** The redeemer's agent calls the guest-tier `redeem_invite(token, card)` (HDTP §6.2). The node MUST check: the token resolves by hash, is not expired, not revoked, and has uses left (else `invite_invalid`); and the caller's proven leaf byte-equals the submitted card's `X-PACT-CERT` — for a sealed redemption the chain inside the payload is what binds (HDTP §13.2). On success the use count is decremented and the response returns the issuer's signed card plus either `accepted` with the granted permissions (`auto_accept`) or `pending`, in which case the owner is notified with the redeemer's card and the invite's `label`. A use is spent only by a redemption that writes a row, in the same transaction as the write: a root whose own request is still waiting (`pending_in`) takes the invite's status, grant and label; a root held in any other state — blocked, or a contact served at the guest tier because it signed with a superseded leaf (HDTP §14.3) — is answered what a stranger holding the same link would be, and nothing is written or spent (§9.1). Guest-tier rate limits (HDTP §12) apply throughout. Redemption needs a reachable endpoint, which every deployment mode now has: there is no mode without an inbound path (§10.1).

### 9.3 The card and the card builder

The card builder (portal, §8) produces the account's HDTP contact card: a standard vCard 4.0 in which the owner edits the human fields — `FN`, `TEL`, `EMAIL`, `PHOTO` — and the node derives the `X-PACT-*` properties from live configuration; they are not hand-edited:

| Property | Derived from |
|---|---|
| `X-PACT-VERSION` | constant `2` |
| `X-PACT-CERT` | the account's current **leaf**, base64url DER. It carries the endpoint, the leaf's key, the root's fingerprint as its issuer key identifier, and the validity — so the card is one property where it used to be three (HDTP §3, §14.1) |
| `X-PACT-SEAL` | the seal knob, `none\|optional\|required` (HDTP §13.4) |

**Export** is offered as a `.vcf` download, a QR, and a shareable link; `get_card` returns the current signed card to contacts (HDTP §6.2), and invite responses carry it signed (§9.2).

**Import** accepts a `.vcf` — or its text — in the portal (People → Connect from a card) and through the owner MCP's `add_contact{card, note}`, both through one function. A card carrying `X-PACT-*` properties triggers the "connect our agents?" offer; on the owner's confirmation the node runs the HDTP §5.2 manual flow: it calls `request_contact(card, note)` at the address the imported card's certificate names (state `pending_out`), and when `contact_accepted` arrives it MUST verify the caller's chain against the root that certificate names as its issuer before pinning — the out-of-band card is the trust anchor, and trust in the card equals trust in the channel that carried it (HDTP §5.2, §14.2). A card is its certificate, its version and its seal policy; a property the node does not know is ignored and never honoured (HDTP §3).

### 9.4 Phone-book sync

Live synchronization with the phone contact book is explicitly **not in v1**. Card exchange in v1 is manual: `.vcf` export/import, QR, and links. The vCard carrier keeps the door open — ordinary contacts apps preserve unknown `X-` properties (HDTP §3) — so a later sync feature needs no format change.


---

## 10. Reachability: deployment modes, tunnels, ingress

A node is only a node if peers can call it. HDTP §10 sketches the reachability landscape; this section fixes it for hdtp-gateway: two deployment modes with derived constraint sets, a small verified matrix of tunnel adapters, and the ingress role for owners with their own domain. Throughout, the caller identity rule of §3.5 applies unchanged: a caller is the root of a chain that validated, and when both carriers are present their leaf keys MUST match.

### 10.1 The two deployment modes

The deployment mode is **derived from configuration, never declared**. Tunnel adapters affect reachability only; the protocol surface never changes because of a tunnel. Each adapter declares a single boolean, `TerminatesAtEdge`, and the derivation rule is:

- An inbound path whose adapter has `TerminatesAtEdge = false` (or no tunnel at all) puts the node in **direct mode**: the caller's TLS session terminates at the node, so client certificates are visible end to end.
- An inbound path whose adapter has `TerminatesAtEdge = true` puts the node in **edge mode**: a third party terminates the public TLS session, client certificates never reach the node, and caller identity rests entirely on sealed envelopes (HDTP §13).

There is no third. The relay role went with the rest of the protocol's first generation: a store-and-forward gateway would see every sender, recipient and timestamp for its trouble, and what 2.0 makes safe instead is **being hosted** — a host runs the identity's server all the time under a leaf the person issued, and can be replaced without the person losing anything (HDTP §9). A node that cannot accept inbound connections uses a tunnel. No card names a gateway, and none would be honoured.

`TerminatesAtEdge` drives the three knobs:

| Knob | direct mode | edge mode |
|---|---|---|
| `seal` (`none\|optional\|required`, card property `X-PACT-SEAL`, HDTP §13.4) | `required` by default; owner MAY relax | forced `required` |
| `client_cert` (`required\|preferred\|off`) | `preferred` by default | forced `off` |
| LAN connections flag | **on** by default — carries no security weight (see below) | default **off**; refusals audited |

In edge mode a call that is not sealed fails with `seal_required` when a transport identity was established, and with `identity_required` when none was — the identity check precedes the seal check (§5.3).

```mermaid
flowchart TD
    A["Configured inbound path?"] -->|"none"| N["unreachable: use a tunnel<br/>(there is no relay role)"]
    A -->|"listener or tunnel adapter"| T{"adapter<br/>TerminatesAtEdge?"}
    T -->|"false"| D["direct mode<br/>client_cert preferred (default)<br/>seal required (default)"]
    T -->|"true"| E["edge mode<br/>client_cert forced off<br/>seal forced required<br/>LAN flag default off"]
```

**LAN connections flag.** When a tunnel adapter is active, the node's local listener could also be reached directly from the local network, bypassing the tunnel. The LAN connections flag controls whether such direct connections are accepted. In edge mode it defaults to **off**, because the listener there is configured for edge assumptions (`client_cert` off, identity from envelopes) and a LAN caller would sidestep the constraint derivation; every refused LAN connection MUST be written to the audit log (§11). The connector's own delivery is not such a caller: an in-process or same-host connector reaches the bind over loopback, which §12.2 excludes from the classification for that reason. In direct mode a LAN connection presents the same end-to-end mTLS surface as a tunneled one, so the flag carries no security weight there.

### 10.2 Tunnel adapter matrix

Adapters shipped in v1, as verified against current vendor documentation and SDKs:

| Adapter | Mode | Mechanism | Notes |
|---|---|---|---|
| `direct` | direct | Node binds a public port (port forward, static IP, VPS); no tunnel process | Baseline; true end-to-end mTLS |
| `tailscale` | direct | Embedded tsnet, `ListenFunnel` | Free; no external binary; the Funnel relay does not decrypt; `*.ts.net` names only; ports limited to 443/8443/10000; Funnel is beta and Tailscale-hosted |
| `frp` | direct | Embedded frp client (`client.NewService`) to an owner-run `frps` on any VPS; SNI-routed passthrough | Apache-2.0; `frps` does not perform TLS termination |
| `ngrok` | direct | ngrok-go v2: `ngrok.Listen(ctx, ngrok.WithURL("tls://…"))` returns the unterminated stream | Paid — TLS endpoints are not available on ngrok's free plan |
| `cloudflare` | edge | Provision tunnel, configuration, and DNS via cloudflare-go; run a spawned `cloudflared tunnel run --token` child or the `cloudflared` compose sidecar (§12) | Edge terminates TLS; works on the free plan |
| `ngrok-https` | edge | ngrok free HTTPS endpoint | Edge terminates TLS; free |

Wrapping an adapter's raw stream, the node's own TLS server always requests client certificates when `client_cert` is not `off`; unknown certificates still land in the guest tier per HDTP §6.

### 10.3 Outbound calls MUST use GetClientCertificate

When the node calls a peer, its `tls.Config` MUST supply the identity keypair via `GetClientCertificate`, never via the default `Certificates` selection. Rationale, verified in research: edges such as Cloudflare send a TLS `CertificateRequest` advertising their own CA distinguished names; Go's default certificate selection finds no chain match, reports "chain is not signed by an acceptable CA", and silently sends no certificate. `GetClientCertificate` returns the HDTP identity certificate unconditionally, so the peer (or a passthrough path) always sees it. Server-certificate validation on outbound calls follows HDTP §2: pinned contact fingerprint, else WebPKI for the hostname.

### 10.4 Reachability probe and doctor

The node MUST be able to verify that the address its leaves name actually reaches this instance. The reachability probe dials the public URL and validates what is served there as a peer does: the chain, leaf then root, to the root of an identity this node serves AT that identity's address (HDTP §14.2 — so a leaf that names some other address fails here, by rule 5, before any peer meets it), or the edge's WebPKI certificate in edge mode; and confirms the connection lands on this instance by round-tripping a fresh nonce through a probe handler; the portal's tunnel settings page surfaces the result (§8). Hairpin NAT can make a self-originated probe pass or fail unrepresentatively; the probe reports that possibility as a caveat, never as a clean pass. The `doctor` CLI command (§12) runs the probe together with configuration, store, and tunnel-state checks and reports a single diagnosis. Probe failures are the expected first stop when a peer reports `unavailable`.

### 10.6 Ingress role

An owner with a domain can run hdtp-gateway in the **ingress role** on a public host: a front door that holds DNS and certificates for the domain and fronts one or more nodes on subdomains. Each subdomain is served in one of two modes:

- **passthrough** — the ingress routes on SNI and forwards the raw TLS bytes to the paired node over the data plane. The caller's TLS session terminates at the node, end-to-end mTLS is preserved, and the fronted node derives **direct mode**. The node presents its own server certificate (WebPKI or pinned self-signed, per HDTP §2); the ingress never holds a certificate for a passthrough subdomain.
- **terminate** — the ingress holds a public ACME certificate for the subdomain, terminates the public TLS session, and opens a fresh **mutually-pinned mTLS** connection to the node: the "TLS→mTLS conversion". Mutual means both halves: the ingress pins the node's key from pairing, and the node pins the ingress's, refusing any other client on that leg. That pin is a TRANSPORT check only — caller identity in terminate mode comes from the sealed envelope, and the ingress certificate never reaches caller identification, so it can never be promoted into a caller. The fronted node derives **edge mode** (client_cert forced off toward callers, seal forced required). The ingress is a trusted edge the owner chose; it can read terminated traffic apart from sealed payloads (§13).

**Both modes share the public port.** One front door reads the ClientHello, routes by SNI, and hands passthrough connections to the data plane with their bytes untouched while terminate connections go to the terminating listener. A fronted node is therefore reachable at plain `https://<sub>.<domain>` in either mode — which is what a peer's card can carry.

**What the card advertises.** A fronted node has no inbound port of its own, so the leaf on its card names the ingress-fronted hostname; the root that leaf names is the NODE owner's, never the ingress's. In terminate mode a peer therefore cannot pin the node at the transport layer — its TLS ends at the ingress — which is precisely why `seal` is forced `required` there: the caller's identity and the content both ride in the envelope, past the edge (§4, §10.1).

**Pairing** uses a one-time token: the owner mints a pairing token on the ingress, enters it on the node (portal settings, §8), and the node connects outbound, authenticates with the token once, and registers its subdomain and serving mode. Pairing establishes the mutual key pins used by the data plane and by terminate-mode onward connections. Because the node connects outbound, a fronted node needs no inbound port of its own.

**DNS and ACME.** With a Cloudflare token the ingress uses **DNS-01** and manages a single **wildcard** certificate for `*.<domain>`, which covers every subdomain: the owner points that wildcard record at the ingress once, and no per-pairing DNS write ever happens — the ingress needs the DNS-01 solver, not a zone-write credential for records. Without a token it falls back to **HTTP-01 per subdomain**, which requires each name to already resolve to the ingress and port 80 to be reachable, and it says so at startup. Certificates are obtained for terminate-mode subdomains only; a passthrough subdomain's TLS terminates at the node, so the ingress holds no certificate for it.

**Data plane.** Node-to-ingress transport embeds frp; a minimal yamux-over-TLS multiplexer is the fallback when frp is unsuitable.

The pairing and registry protocol is deliberately the same one a hosted platform would speak: a provider running the ingress role at scale can front customer nodes with no protocol change. This is the hosted-platform seam.

### 10.7 Cloudflare Client-Cert header path (optional, later, never load-bearing)

Research verified a documented, all-plans Cloudflare configuration that can deliver a caller's certificate to an edge-mode node despite edge termination: enable mTLS on the hostname under SSL/TLS Client Certificates (the edge then completes the handshake with any presented certificate, valid or not), and use Request Header Transform rules (Free plan: 10) to first remove inbound `Client-Cert`/`Client-Cert-Chain` headers and then set `Client-Cert` from `cf.tls_client_auth.cert_rfc9440`, which is populated regardless of the validation result. A tunnel-only listener would parse the RFC 9440 DER and compute the SPKI fingerprint itself.

This path is documented here as an **optional later feature** for the `cloudflare` adapter and MUST never be load-bearing: v1 edge-mode identity is envelope-signature only, and edge mode MUST remain fully correct with this feature absent or broken. It remains edge-terminated — Cloudflare reads the traffic apart from sealed payloads — and it stays documentation-only until two empirical caveats from the research are validated against a live zone:

1. Cloudflare's `CertificateRequest` advertises its CA distinguished names, and it is untested whether arbitrary client TLS stacks will present a self-signed certificate under that advertisement (Go callers using `GetClientCertificate` per §10.3 will; other stacks may silently send nothing). Cloudflare's own overview text ("requires connecting clients to present a valid certificate") contradicts its field documentation, and the field documentation is the operative reading.
2. Whether a hostname can be mTLS-enabled without minting at least one Cloudflare-managed client certificate is undocumented.

---

## 11. Data model and audit

### 11.1 Store interface and engines

All persistence goes through a single Go `Store` interface. No SQL exists outside the store package, and none is written by hand inside it: every statement is a method **sqlc** generates from `queries/{sqlite,postgres}/*.sql`, and nothing outside the store may import `database/sql`, a driver, or goose — a caller that needs to know a row was absent asks `store.ErrNotFound`. There is no exception: the one there was — `SQLite.Snapshot`'s `VACUUM INTO`, which sqlc's grammar rejects — went when `backup` did, because an export is written through the store and copies no file. Tests may write SQL; a fixture has that privilege and the code under test does not. The first sentence of this paragraph was here, and untrue, until 2026-09-19 — `backup` opened the database and wrote its own statements — and `TestNoHandWrittenSQLOutsideTheStore` is what keeps it true. Migrations run with **goose**, with the schema maintained per engine. Two engines are supported:

- **SQLite** via modernc.org/sqlite — the default; pure Go, which preserves the static `CGO_ENABLED=0` build (§12).
- **PostgreSQL** via pgx — enabled by the `postgres` compose profile (§12).

A store conformance suite — one test suite exercising the complete `Store` contract — MUST pass against both engines in the gate every push runs (§14).

**More than one process.** Both engines are shared by more than one `serve` process, each with its own listeners:

- **SQLite:** many processes on **one host**, sharing one data dir. The database is opened in WAL mode with `busy_timeout` 5 s, and every transaction takes the write lock at `BEGIN` (`BEGIN IMMEDIATE`), so a writer waits for another process's lock rather than failing and a read-then-write transaction is never refused its upgrade. SQLite's locking is not safe over a network filesystem, so SQLite across hosts is not supported.
- **PostgreSQL:** many processes on many hosts, each with a data dir of its own.

The data-dir lock (§12.1) is held **shared** by every `serve`. The first to start on an idle data dir holds it alone, migrates, and only then shares it; a `serve` starting beside others does not migrate, and refuses to serve unless the schema is exactly the version it was built for. On Postgres, where every host's process is alone on its own data dir, migrations take turns under a session-level advisory lock, and each process checks the schema after. The admin socket (§12.1) is served by one of the processes on a data dir: the first to hold its lock file.

What one process changes about what it serves, every other applies from the change log (§7.8): a caller's composed surface dropped (an approval, a redemption, a switchboard or exposure change) is dropped on every process, and an account adopted, re-leafed, retired, re-sealed or gone is reloaded from the store by every process — its seal as the row says, which the process that changed it wrote; and a setting saved in one process's portal is read back from the store and applied by every other (the seal new accounts are built with, the LAN flag, the public URL, the contact cap that sizes each account's call budget), audited once, by the process that saved it. An integration's OAuth token (§6.3) is the store's: every process serves the token on file, and an expired one is refreshed by the one process holding that integration's refresh lease — a provider that rotates refresh tokens refuses a second use of one — while the others wait up to 30 s for the token it seals. Background work that must run once — the outbound retries (§7.1) and the hourly retention pass (§7.9) — runs on the process holding its lease, a `leases` row each process tries to take, and its holder renews, every 10 s for 30 s: a holder that stops lets go at once, one that crashes is replaced within 30 s. Across hosts on PostgreSQL every process needs the same master key (`HDTP_MASTER_KEY`, §3.7) and one blob directory every host mounts (`blob_dir`, §7.4). What each process still keeps to itself is listed in docs/operations.md, *More than one process*.

### 11.2 Tables

| Table | Holds |
|---|---|
| `owners` | Owner principals (§3) |
| `credentials` | Owner authentication credentials — passkeys now; schema pre-shaped for oauth and email/password later (§3) |
| `sessions` | Portal sessions (§8) |
| `tokens` | Named revocable owner-MCP bearer tokens (§3, §8) |
| `accounts` | Accounts on this node (§3) |
| `memberships` | Owner-to-account membership with role attribute (§3) |
| `contacts` | Pinned contacts per account: fingerprint, card, relationship state (§9.1), permissions, trust flag (§9) |
| `invites` | Invite state — expiry, uses, auto_accept, preset, label; stores the token **hash only**, never the token (§9) |
| `threads` | Conversation threads (§7) |
| `messages` | Messages, idempotent on `(account, contact, msg_id)` (§7) |
| `idempotency` | Recorded acknowledgments for `msg_id`-bearing calls that append no `messages` row: envelope-level `sealed_call` dedup (HDTP §13.3) and `book_slot` replays (§6.7), keyed `(account, caller fingerprint, msg_id)` with a reference to the recorded result; an envelope's is kept until the envelope can no longer be accepted — `exp`, or the second after `ts + 300`, whichever comes first (HDTP §13.3's `min(exp, ts + 300 s)`; `ts + 300` itself still passes the skew check) — and a `book_slot` replay's for 30 days; the hourly sweep removes a record after that, since one past its window protects nothing |
| `blobs` | Content-addressed media store (§7) |
| `integrations` | Configured upstream integrations (§6) |
| `catalogs` | Versioned catalog snapshots (catalog snapshot vN) with per-tool content hashes (§6) |
| `exposures` | Versioned exposure sets (exposure set vM) (§6) |
| `pending_requests` | Agent-answered requests awaiting the owner's agent (§6) |
| `settings` | Owner-set configuration the portal writes (§8.2, §12.2), including `tunnel.<adapter>.*` adapter state and sealed values |
| `move_fanout` | Per-contact completion of the move campaign's `update_contact` walk (§9.1, HDTP §5.3): which contact, the kid of the leaf being announced, whether it was reached, how many attempts, the last error. A re-run resumes by matching on the leaf, so a second move is a second campaign. |
| `leaves` | HDTP 1.0 (HDTP §2, §14): every leaf certificate this host holds for an account — `pending` while a CSR awaits the wallet, `current`, `superseded` with its key kept until `not_after`, `former` with the key destroyed and the key id kept so an envelope sealed to it is answered `certificate_renewed`. A pending request also keeps the SHA-256 of the `state` a web wallet's answer must carry, and the wallet it went to (migration 0041, §3.12) |
| `tombstones` | HDTP 1.0 (HDTP §5.3): a removed root and the leaf that removed it, kept 30 days so a returning root is asked about whatever `accept_new_hosts` says |
| `former_endpoints` | HDTP 1.0 (HDTP §5, §6.1): where a pinned root used to answer, for the address-claim rule |
| `vacated_addresses` | An address an identity left when it left this node (HDTP §9, §3.11): the endpoint, its slug and the last leaf's `notAfter`, and nothing that names the identity. While live it refuses the slug to a new account and the endpoint to a signing request; the hourly sweep drops it once its date has passed |
| `changes` | The change log (§7.8): one row per event the node publishes — account, kind, thread, contact, a reference (the tool of a call) and when — whose id is the cursor `wait_for_updates` answers with; every node process sharing the store reads it. Kept a week, and erased with an identity that leaves (§3.11) |
| `owner_presence` | One row: when the owner's agent last asked the owner MCP anything, so every node process answers "is the agent attached" the same (§6.8) |
| `leases` | Background work only one node process may run at a time — its name, the process holding it, when it last renewed it and when it runs out (§11.1) |
| `pending_addresses` | HDTP 1.0 (HDTP §5.3): a contact at a new address awaiting the owner under `accept_new_hosts = ask` |
| `audit_anchor` | The terminal hash of the archived audit segment the retained chain must extend (§11.6) |
| `audit_archive_rows` | The rows an identity's archive is removing from the chain, by seq and hash, the only rows past the anchor the prune guard lets go; empty outside the one transaction that removes them (§3.11, §11.6) |
| `audit_events` | The append-only audit chain (§11.4) |

### 11.3 Encrypted secret columns

Columns that hold secrets — upstream OAuth tokens, tunnel credentials, and the like — are encrypted at rest under the keyring master key of §3.7, supplied via environment variable, a `0600` key file, or the OS keyring where one is available (§12.2). Possession of the database file alone MUST NOT suffice to recover them.

### 11.4 The audit hash chain

`audit_events` is append-only. Every row carries `prev_hash` and its own hash, computed as SHA-256 over `prev_hash ‖ canonical row` — the previous row's hash concatenated with the canonical serialization of this row's fields. The canonical row is precisely defined and versioned: each row carries a chain-format version (`1` in this revision) naming the enumerated field list included in the hash, and those fields are serialized as canonical JSON — UTF-8, keys sorted lexicographically, no insignificant whitespace — the same canonicalization as the envelope's protected header (HDTP §13.1). The genesis `prev_hash` is 32 zero bytes, and hashes are stored lowercase-hex. A future change to the row fields bumps the chain-format version and re-anchors the chain (§11.6) instead of silently breaking historical verification. Any retroactive edit or reordering breaks the chain and is detected by `audit verify`. **Deletion has exactly two sanctioned forms, both archiving (§11.6):** the head of the chain, and the trail of an identity that has left the node (§3.11). Archiving the head writes the removed segment to a file, verifies that file, records its terminal hash as a durable anchor, and only then removes those rows — so the retained chain is measured against the anchor rather than against its own first row, and a head removed WITHOUT archiving is therefore visible rather than self-consistent. An identity's archive takes rows from the middle of the chain, each still carrying the `prev_hash` it was sealed with, so a row missing from both the table and the files breaks the link of the row after it. Verification spans the archive files and the live table as one chain. An archive run interrupted between recording the anchor and removing the rows leaves the two disagreeing; that state is reported as unfinished, not as tampering, and `audit repair` completes it (§12.1).

**One chain, any number of writers.** A row is appended in one transaction that reads the chain's head — the last row's seq and hash — and writes the row sealed on it, and that transaction holds the head until it commits: on SQLite it takes the write lock at `BEGIN`, on PostgreSQL an advisory lock before it reads. No process keeps the head in memory between appends, so every writer in a process and every process sharing the store (§11.1) extends the one chain, and no two rows are sealed on one head.

### 11.5 What is audited, and where the writes live

The audited event classes are:

- every public-surface call — caller fingerprint, tier, tool, decision, timing; bodies are **referenced by id, never copied** into audit rows;
- every internal mutation;
- authentication events, including refused LAN connection attempts (§10.1);
- integration lifecycle events (§6);

Audit writes live in exactly three places: the public dispatch path (§5), the internal dispatch path (§8), and the store mutation layer. The offline `audit erase-archive` (§12.1) writes its one row through a writer of its own, which is the chain's only writer while it holds the node's lock. Because every call flows through one of the two dispatchers and every state change through the store mutation layer, nothing can execute or mutate unaudited.

HDTP §12 limits (sizes, rates, slot caps) are enforced twice: at the dispatch boundary and again in the store layer.

### 11.6 Archive, verification, visibility

Old audit rows are archived to append-only **JSONL** files under `<data_dir>/audit/`, named by the sequence range they cover so lexical order is chain order; the trail of an identity that left goes to files of its own under `<data_dir>/audit-archive/` (§3.11, and below). Archiving re-anchors the chain: the first row retained in the database records the terminal hash of the archived segment, so verification spans archive files plus the live table as one chain. `hdtp-gateway audit verify` (§12) recomputes the entire chain and reports the first break, if any.

**Where the anchor lives.** The retained rows' own `prev_hash` is not sufficient: a chain whose oldest rows were removed is internally consistent, so verifying it against its own first row cannot tell pruning from a short history. The expected anchor is therefore recorded **durably in the store**, in a single-row `audit_anchor` table (§11.2) holding the archived-through sequence, the segment's terminal hash, and the archive path. A chain that has never been archived MUST verify against `GenesisHash`; once archived, the retained rows MUST extend the recorded terminal hash. Verification without an expected anchor is not conformant.

**Archiving is ordered so that a failure is safe.** The segment is written, read back and verified *before* anything is deleted; the anchor is recorded *before* the rows are removed; and the entire chain must verify before an archive run starts, so a break is never baked into an archive. Archiving MUST NOT remove every row — the retained chain is what carries the anchor forward. The store enforces the same rule rather than trusting the caller: `audit_events` refuses UPDATE outright, and refuses DELETE for any row the anchor does not already cover and that an identity's archive has not listed, by its seq and its hash, in `audit_archive_rows` (migration 0045). The guard cannot see a file, so the code holds the rest: the store's two deletes are called only by the archive code, which writes and reads back the rows before either (`TestOnlyTheArchiveDeletesFromTheChain`).

**An identity's archive** (§3.11) holds rows from the middle of the chain, so verification puts every archived row back in its place by seq and walks one chain from genesis (or from the anchor): a file that is missing, cut short or edited leaves a row that does not link or does not hash, and the chain is reported broken; a seq held twice with different content is broken too. The move is ordered so that a failure at any point loses no row and duplicates none: the file is written under a temporary name, synced, renamed into place and read back — every row must be the live row, field for field, and hash to its own hash; the `audit_archive` row is appended next, so the rows about to go are never the chain's newest (a writer that starts afresh takes its next seq from the newest row); then ONE transaction lists the rows with their hashes in `audit_archive_rows`, deletes them, and empties the list, and a row whose hash is not the one listed stops the whole transaction. A run stopped before that transaction leaves every row in the table and perhaps a copy in the file: the same row held twice is reported as a run that has not finished, not as a break, and the next sweep finishes it, reusing the file and the `audit_archive` row it finds (the row names the segment's first seq) rather than writing another. The files are kept; `audit erase-archive` is the one way their content goes, leaving the seq, `prev_hash` and hash of each row, which verification checks for the link alone and reports as erased.

Audit data is **owner-visible only**: it is reachable through the portal (§8), the owner MCP's `audit_query` (§8), and the CLI — never through the public surface (§5).

---

## 12. CLI, configuration, container, first run

### 12.1 CLI

One binary, subcommand-per-concern:

| Command | Purpose |
|---|---|
| `serve` | Run the node, per configuration (§10) |
| `ingress` | `serve` \| `token` — the ingress role: an own-domain front door for paired nodes (§10.6) |
| `migrate` | Run store migrations; the node must be stopped (§11) |
| `doctor` | Diagnostics: configuration, data dir, store, lock (§10.4), each identity's leaf, and any identity whose imported contacts wait for its next leaf (§3.10) |
| `healthcheck` | Probe the internal `/healthz`; the container HEALTHCHECK uses it (§12.3) |
| `account` | `create` \| `list` — the node's identities; `csr` \| `install-leaf` \| `certificate` \| `address` \| `announce` \| `leave` — the leaf: a signing request for the wallet (`-purpose signup\|renew\|move`), the install of the chain it answers, the certificate state, the owner's answer to a contact at a new address and the choice between `auto` and `ask` (`-policy`), and the campaign that tells every contact of a move, and every contact an import brought of the next leaf (§3.10, HDTP §9.2) — durable, walked in the background one identity at a time, and both reported and resumed by `announce`, which answers from the ledger at once and never waits for the walk (HDTP §5.3, §9). `leave` shows what it would erase, and with `-yes` erases an identity that has left this node and reserves its address until its last leaf expires; an identity served here at this node's own address for it is refused without `-force-current` (§3.11). Runs over the admin socket, so the node must be running |
| `passkey` | `list` \| `remove` \| `reset-wizard` — owner passkeys; `reset-wizard` mints a one-time setup URL (§3.1, §8.6) |
| `token` | `create` \| `list` \| `revoke` — named owner-MCP bearer tokens (§3, §8.4) |
| `audit` | `verify` \| `export` \| `archive` \| `repair` \| `erase-archive` — the hash chain, offline; the node must be stopped (§11.4, §11.6). `verify` walks the head archives, the identity archives under `<data_dir>/audit-archive/` and the live table as one chain; `erase-archive -file NAME` reduces one identity archive's rows to their seq and hashes when law requires (§3.11) |
| `export` | `-slug S -out FILE.zip`: one identity's contacts, chats and files — and nothing else — in one unencrypted zip, offline (§3.10). No key, no settings, no credentials |
| `import` | `FILE.zip -slug S [-yes]`: check a whole export, show what it would write, and with `-yes` write it, offline: into a new keyless identity, or merged into the one it belongs to. It then waits for a new leaf from its wallet (§3.10) |
| `check` | `store` — every card and certificate the store holds (each account's root and leaves, each contact's card, leaf and root certificate, each tombstone's and pending address's), read by the identity core's rule — a card as every write to that contact reads it (`contacts.SealOf`), a certificate as the core parses it — and each that does not read named by table, row and field with the reason, and each contact whose status is neither a state a pin has nor `pending_in` — a row the node hands the core no pin for (§5.4), one the schema does not admit — counted and named by row and status (`NO PIN`); exit 1 when there is one of either. Read-only, no lock: it runs beside a serving node, as `doctor` does. `serve` prints the same lines in its banner and serves whatever they say (`internal/storecheck`). It exists because the core's reading gets stricter — the identity core 0.4.2 refuses a character outside base64url that 0.4.1 skipped — and what intake accepted under the old reading is still on file after the bump |
| `version` | Print the version |

Against a running node, CLI commands operate through an **admin unix socket**, gated by filesystem permissions. Commands that touch the database directly — offline operations such as `migrate`, `export`, `import` and the `audit` commands — MUST run only with the node stopped: they take the data-dir lock exclusively and refuse to proceed while any `serve` holds it. `serve` holds it shared, so several may run on one data dir (§11.1). `doctor` and `check store` read the store and write nothing, and take no lock.

### 12.2 Configuration

Configuration precedence is **environment > file > store > defaults**. Secrets never live in the configuration file: they are encrypted in the store under the keyring master key of §3.7, itself supplied via environment variable, a `0600` key file, or the OS keyring where one is available (§11.3).

**Owner-set configuration.** The knobs the portal exposes — `public_url`, `tunnel`, `seal`, `client_cert`, and the LAN flag — persist in the store's `settings` table and slot in *below* the file and the environment. That ordering is normative and has a reason: an operator who pins `HDTP_SEAL` in a deployment must not have it overridden by a row in a database they may not be looking at. A knob the environment pinned MUST render **locked, naming the variable**, rather than offering a control whose value would be discarded; the same applies to a knob a deployment mode forces (§2.5). Everything else — data directory, binds, store engine, master-key location — is **bootstrap** and is never owner-settable: it decides where the node's state lives, so it cannot come from that state.

**`wallet_url` is bootstrap** (`HDTP_WALLET_URL`, default `https://ceremony.batondeck.com`). It is the one foreign origin the portal's `form-action` admits, on the signing-request page alone (§3.12), so it cannot come from data the authenticated surface writes. It must be an origin in a strict grammar — a lower-case `https://`, a host that is a DNS name (letters, digits, hyphens, dots), a dotted quad or a bracketed IPv6 literal, an optional port of 1 to 65535, at most a trailing slash; or `http://` to a loopback host for a wallet on the same machine — because it is written into a Content-Security-Policy, where a `;` or a `'` would begin a directive or a source of its own; anything else is refused when the configuration is read (`wallet_url_is_an_https_origin`).

**`limits_socket` is bootstrap** (`HDTP_LIMITS_SOCKET`, default `<data_dir>/limits.sock`): the unix socket of the limits sidecar that decides every call budget (§5.7). It decides who may refuse every caller, so it cannot come from data the authenticated surface writes. Every node process on a host names the same one.

**`proxy_address` is bootstrap** (`HDTP_PROXY_ADDRESS`, default none): the IP address of the one proxy whose `X-Forwarded-Client-Cert` and `X-HDTP-Client-Address` the listener reads (§5.1). It decides who may assert a caller's identity and address, so it cannot come from data the authenticated surface writes. A value that is not an IP address is refused when the configuration is read (`proxy_address_is_an_ip`).

**`audit_archive_after` is bootstrap** (`HDTP_AUDIT_ARCHIVE_AFTER`, default `90d`): how long the audit rows naming an identity that left stay in the live trail before the hourly sweep archives them (§3.11). It is a whole number of days with a `d` or a Go duration (`36h`, `0s`); a negative or unreadable value is refused when the configuration is read (`value_out_of_range`). It decides what the node keeps of a person who has gone, so it cannot come from data the authenticated surface writes.

**`internal_host` is bootstrap.** The hostname the portal is served at is the only non-loopback name a WebAuthn ceremony may bind a credential to, and `Host` is attacker-controlled — a spoofed header must not be able to register a credential for a domain the owner does not control. It is therefore configured at startup and never owner-settable: it gates authentication, so it cannot come from data the authenticated surface writes. A consequence worth stating plainly: a passkey registered while the portal was on `localhost` will NOT work once it moves to a domain, because the browser binds each credential to the relying party it was created for. That is WebAuthn, not a defect; `passkey reset-wizard` (§12) is the recovery path. It must also be a name a passkey can be bound to at all, and the passkey library is the judge of that: an IP address, a single label other than `localhost`, a name with a trailing dot or a label that begins or ends with a hyphen is refused (`internal_host_is_a_passkey_relying_party`) when the configuration is READ, by every command — not at the first ceremony, which is when a node that had started cleanly and served its portal used to discover that nobody could ever sign in to it. A Tailscale name (`node.tailnet.ts.net`) is fine; a bare `nas` is not.

Owner-set values go through the same derivation as any other layer (§10.1): choosing an edge adapter in the portal forces `seal: required` and `client_cert: off` exactly as setting it in the environment would. Secret values (adapter credentials, ingress tokens) are sealed with the keyring before they are stored and are never rendered back — the page shows whether a value is set, never what it is.

**A `public_url` a wallet certifies no address under** — `localhost`, a loopback, link-local or private address, by HDTP's address rule (`hdtpidentity.AddressGuard`) — is accepted for local use: a node run for development, or never meant to be reached from outside, is a legitimate configuration. What the node does not do is ask for a certificate there: a signing request for an endpoint under such an address is refused in the core's words before a key is made (`account csr`, the portal, the import's request; `account_csr` `refused`, reason `address`), since every wallet refuses to certify it; and `doctor` names such a `public_url` as a failure, with the reason.

**When a change takes effect.** `seal`, `public_url` and the LAN flag apply to the next call with no restart; the node's advertised card and its envelope gate read the same live value, so a card can never advertise a policy the gate does not enforce (HDTP §13.4). Knobs that own a socket or a goroutine — the tunnel adapter and the `client_cert` TLS posture — take effect on the next start, and the portal MUST say so next to the control. Changing `public_url` changes the address the NEXT leaf will name and moves nobody: an address is inside a leaf, so every account goes on answering at the endpoint its wallet signed until the wallet signs another. Saving it therefore MUST NOT call any contact. What it does is name — on the audit chain (`account_move_needed`), and afterwards on `doctor` and the `serve` banner — each account whose leaf was issued for the old derived address, since that account now needs a **move**: the person issues a leaf for the new endpoint (`account csr -purpose move`), and installing it is what starts the `update_contact` campaign to every active contact (§9.1, HDTP §5.3). An account certified for a hostname of its own is not named.

### 12.3 Container image

The release image contains a static binary built with `CGO_ENABLED=0` on a **distroless** base, published multi-arch, and beside it the limits sidecar, `hdtp-limitd`, a static Rust binary, with its shipped configuration at `/etc/hdtp-limitd/limits.json` (socket `/data/limits.sock`, the node's default `limits_socket` under `/data`). The sidecar runs as a process of its own, from the same image (§12.4). The default image is slim; the **`-full` tag** adds the node and uv runtimes so supervised stdio integration children can run in-container (§6). State lives on a single `/data` volume (store, blobs, tunnel state). The image defines a healthcheck that reports readiness of the node process.

### 12.4 Compose and first run

The shipped compose file runs the node and its limits sidecar (§5.7), the same image with `hdtp-limitd` as its entrypoint, sharing the `/data` volume the socket is in; the node refuses every sealed call until the sidecar answers. It defines two profiles: `postgres` (run PostgreSQL and point the store at it, §11.1) and `cloudflared` (run the cloudflared sidecar for the `cloudflare` edge adapter, §10.2). `deploy/envoy/compose.yaml` is the same node and sidecar behind Envoy (§5.1, §5.7), with Envoy the only service that publishes a port.

First run is `docker compose up`: the node starts, and the logs print the **portal URL and a one-time setup token**. The token gates the setup wizard for non-loopback browsers (§8): it carries at least 128 bits of entropy, expires after 24 hours, and is invalidated the moment any passkey is registered; it is not burned on first use (§3.1) — `passkey reset-wizard` mints a fresh one (§3.1, §12.1); from there the owner registers a passkey and completes setup. No step requires editing files inside the container.

### 12.5 Releases and telemetry

Releases (binaries and images) are built with **goreleaser** from tags. hdtp-gateway contains **no telemetry** of any kind: it makes no network connections other than those the owner configures — peers, upstream integrations, tunnel, ingress, and DNS/ACME when the ingress role is enabled. This is stated in the documentation, not merely implied.


---

## 13. Security posture and accepted trade-offs

This section states what hdtp-gateway defends and — with equal weight — what it deliberately does not. The limits in §13.2 are decisions, not backlog. HDTP's founding rule applies to this implementation as it does to the protocol: honest trade-offs stay documented, in the spec and in UX copy, never papered over.

### 13.1 What the design defends

**Caller authentication through any pipe.** The identity rule of §3.5 makes caller identity independent of whichever transport happened to carry the call: a caller *is* the root of a chain that validated (HDTP §14.2), proven either by presenting that chain as the TLS client certificate or by carrying it inside a sealed envelope. When both proofs are present their leaf keys MUST match; a node MUST reject the call otherwise. A single certificate is neither proof: it names no root, and anyone can mint one. Three knobs bind this rule to deployment reality (§10): `seal` (`none|optional|required`, default `required`, forced `required` in edge mode; advertised on the card as `X-PACT-SEAL`), `client_cert` (`required|preferred|off`, default `preferred` in direct mode, forced `off` in edge mode, where the edge strips certificates), and the LAN connections flag (default off in edge mode; every refused LAN connection is audited). The consequence: there is no deployment mode in which a caller is trusted on transport position alone — behind an edge, identity rides the envelope; direct, it rides mTLS; when both are available they must corroborate. Outbound, a node MUST present its chain via `GetClientCertificate`, so it is sent even when the far end's CertificateRequest advertises a CA list a self-signed root cannot satisfy (§10).

**Content confidentiality past an edge.** A sealed envelope (HDTP §13) is HPKE Base mode to the recipient's leaf key plus a detached signature by the sender's leaf key over `protected‖enc‖ct`, with the sender's own chain — or, after the first exchange, its leaf's fingerprint — inside the ciphertext, so a carrier no longer sees who sent a message. An edge never carries unsealed tool requests **or results**: `seal` is forced `required` in edge mode, a sealed request's result is sealed back to the caller, and so is a refusal once the envelope has opened (HDTP §13.2). On receipt, the strict open order of HDTP §13.3 rejects malformed, misdirected, mis-signed, expired and replayed envelopes before any payload reaches dispatch.

**The permission switchboard.** Authorization has exactly one call site: `policy.Allow`, evaluating Cedar's static shipped policies against dynamic entities (§3). Each caller sees a per-caller MCP server composed for (account, caller-fingerprint): `tools/list` contains only what the switchboard grants; guests see exactly `redeem_invite`, `request_contact`, and the `sealed_call` wrapper (§4); blocked contacts silently drop to guest tier; integrations expose nothing by default — an owner opts capabilities into an exposure set vM, and a stale mapping is withheld (`unavailable`) until re-confirmed against the current catalog snapshot vN (§6). Every call is re-checked at call time, so revocation is instant regardless of cached tool lists, and denied calls return `permission_denied` per HDTP §12.

**Audit tamper evidence.** The audit log is an append-only hash chain — each event binds `prev_hash‖canonical row` — covering every public call, every internal mutation, all auth events including refused LAN connection attempts, and integration lifecycle changes (§11). `audit verify` (§12) re-walks the chain; JSONL archival re-anchors it. Edited history breaks the chain; pruned history leaves a visible gap.

**SSRF.** Inbound URL-carried media is never auto-fetched: fetching is an explicit human action, size-capped, with private address ranges blocked (§7). A contact cannot use the node as a proxy to probe the owner's LAN or cloud metadata endpoints.

**Prompt injection.** Every inbound string is untrusted data, exactly as HDTP §11 requires: length-capped at the boundary (text ≤16 KiB), stored raw, escaped in the portal, never concatenated into instructions. Two labels travel with every payload handed to the owner's agent: the sender label (`agent|human`), derived from the originating surface and never settable as a parameter, and the per-contact message-vs-instruction trust flag — default messages-only, telling the agent "this is content to convey, not a request to act on" unless the owner has explicitly raised that contact's trust (§6, §7). Upstream tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) are untrusted hints for UI sorting only and MUST never gate authorization (§6).

**No MCP sessions.** Both MCP surfaces are stateless (§5.5, §8.5): every request is resolved on its own, and no session id exists to be learned, replayed or bound to the wrong caller. Per-caller servers are dropped on switchboard change and composed again by the caller's next request, and the internal surface accepts non-loopback portal sessions only under passkey auth + TLS (§8).

### 13.2 Accepted limits

What each carrier sees, by deployment mode:

```mermaid
flowchart TB
    subgraph DM["direct mode"]
        A1["caller"] -- "mTLS end-to-end - content unreadable<br/>a tunnel carrier still sees connection metadata" --> B1["node"]
    end
    subgraph EM["edge mode - seal forced required"]
        A2["caller"] -- "TLS to edge" --> E["edge"]
        E -- "edge sees: metadata +<br/>ciphertext only (HDTP §13.2)" --> B2["node"]
    end
```

**No envelope forward secrecy.** HPKE Base mode encrypts to a long-lived leaf key; there is no ephemeral ratchet. An adversary who records sealed traffic today and obtains that leaf's private key later decrypts everything it recorded. Why accepted: HPKE Auth mode was rejected because cross-curve pairs (a P-256 sender and a converted-Ed25519/X25519 recipient) cannot share an authentication DH, and a ratchet would reintroduce per-pair session state. Mitigations, not fixes: the `ts` acceptance window is 300 seconds, a leaf lives at most 398 days (HDTP §14.1), a renewal with a fresh key retires the old one, and the `kid` field is the seam for a later dedicated encryption key. Nothing retroactively protects ciphertext a carrier already recorded.

**Metadata is visible to carriers.** Sealing hides content, not shape. A carrier sees `kid` — which names the RECIPIENT's leaf key, so it can tie every message to one recipient for that leaf's life — along with `msg_id`, timestamps, sizes and frequency, plus the HTTP exchange an edge terminates. What it no longer sees is **who sent** a message: the sender's chain rides inside the ciphertext, and after the first exchange only its fingerprint does (HDTP §13.2, §13.5). HDTP claims no anonymity or traffic-analysis resistance (HDTP §11), and neither does this spec. Direct mode over a tunnel carrier (tailscale, frp, ngrok) is no exception: the carrier cannot read content, but it still sees endpoints, SNI, ciphertext sizes, and timing. Where who-talks-to-whom is itself sensitive, use the `direct` adapter — your own port forward or VPS — since direct mode over a tunnel carrier still exposes connection metadata to that carrier.

**One keypair across TLS, envelope signatures, and HPKE.** The same **leaf** keypair authenticates TLS handshakes, signs envelopes, and receives HPKE decryption (directly for P-256; converted to X25519 for Ed25519 leaves). HDTP §13.5 is explicit that this key signs exactly four structures — a TLS handshake, a certificate signing request, a card, an envelope — each distinguishable by its first bytes, and that an implementation MUST NOT sign anything else with it. Cross-protocol key reuse is generally disfavoured; it is accepted because a second key would need its own place in the leaf, its own pinning and its own renewal story. What bounds it is that this is a LEAF: it expires within 398 days, a renewal retires it, and the identity — the root — is not in play. The `kid` field is the deliberate escape hatch for a later separate encryption key.

**Edge trust.** In edge mode the provider terminates the public TLS session and can read what it carries. The containment is structural and bidirectional: `seal` is forced `required`, a node MUST refuse to serve unsealed tool requests through an edge, and every sealed request's result is sealed back to the caller — including an error, once the envelope has opened (HDTP §13.2) — so the edge carries ciphertext in both directions and cannot tell a refusal from a reply. What remains in the edge's hands is the metadata limit above, plus availability: an edge can drop, delay, replay, and **answer**. Replays die at the 300-second `ts` window and `msg_id` idempotency; a forged plaintext answer is refused by the caller unless it carries one of the few codes a node can legitimately reach before opening an envelope. Delivery through an edge is only as reliable as the edge.

**A stolen leaf key is bounded; a stolen root is not.** A leaf key taken from a host speaks as that identity until the leaf expires or the person renews — at which point the newer leaf outranks it with every contact it reaches (HDTP §14.3), and the thief cannot issue itself another. A stolen ROOT is the identity, fought over by two holders, and HDTP §14.5 records that as residual rather than solved: the defence is a root that is never at rest — in a hardware key, or derived from a passkey on each use — which is the wallet's business and not this node's.

**Lost root = new identity; a lost leaf key is a renewal.** The root is the identity and it is in the person's wallet (HDTP §2, §9): there is deliberately no recovery ceremony for it and no third party holds a copy, so a destroyed root means a new identity — re-share a card and re-pair with every contact. What this node holds is a leaf's key, and losing that costs a renewal and nothing else (§3.9): the wallet signs a new leaf under the same root, and every contact's pin — which is to the root — still holds.

**What leaves a host is contacts and chats, never a credential.** An export carries no key of any kind and nothing of the host's own (§3.10), so a file that leaks costs the owner the confidentiality of their address book and their conversations and not their voice: nobody can speak as this host, or reach into it, from one. The price is paid on arrival, where every identity waits for a fresh leaf and the host's own configuration is made again; the first is one wallet ceremony per identity, and it is the same ceremony a renewal is.

**Loopback internal surface = physical trust.** On a loopback bind, the portal and owner MCP run without authentication (CSRF protection stays on); any other bind refuses to start without passkey auth + TLS (§8). The accepted meaning: whoever can originate a loopback connection on the host is the owner, as far as the node is concerned. Isolation between local users and processes on a shared host is host administration, outside this spec.

---

## 14. Testing and conformance

### 14.1 Test strategy

**Envelope test vectors.** Vectors for both suites (`PACT-SEAL-P256`, `PACT-SEAL-X25519`) and for the certificate profile live in HDTP Appendix B, generated by `hdtp-spec/vectors/gen.mjs`. hdtp-gateway's envelope implementation MUST pass them, and any independent implementation can interoperate by doing the same.

**Fuzzing.** What this project itself does with attacker-controlled bytes carries a fuzz target, and `make fuzz` runs each: the envelope's decode and the whole open (`FuzzSealedEnvelope`), the vCard parser (`FuzzVCardParse`), an invite offer fetched from a remote host (`FuzzInviteOffer`), and the redaction of an upstream's error text before it reaches the audit trail (`FuzzRedact`). MCP/JSON framing and HTTP parsing are delegated to the go-sdk and the standard library rather than fuzzed here.

**Cedar table tests.** Because `policy.Allow` is the single authorization call site (§3), it is testable as one table: table-driven cases assert allow/deny across tiers (guest, pending, contact, blocked), permission grants, presets, and switchboard changes, including the always-available contact-tier tools of HDTP §6.2.

**Store conformance on both engines.** One conformance suite runs against the `Store` interface (§11) on both shipped engines — modernc SQLite (default) and pgx PostgreSQL — covering every table of §11 and the boundary limits of HDTP §12 enforced at the store layer.

**Gate hardening.** The pre-push gate (`githooks/pre-push`) runs `govulncheck` and the Go race detector on every push.

**Integration scenarios.** Four end-to-end scenarios, run in-process by `make check`:

1. **Pairing, messaging and booking** — two in-process nodes: an invite, its redemption, and messages both ways, at `seal=optional` and at `seal=required` (`TestP1ExitTwoNodesPairAndMessage`); and a contact's agent checking availability and booking a slot on the owner's public surface, served through a mapped recipe by a fake calendar upstream (`TestP3ExitContactBooksCalendarSlot`).
2. **Edge + seal** — through an in-test terminating proxy, exercising edge mode: client certificates ignored, plaintext substantive calls refused `seal_required`, identity carried by the envelope (§3, §10) (`TestEdgeModeSealedSucceedsPlaintextRefusedCertsIgnored`).
3. **A move under a partition** — the move campaign (§9.1) with one contact reachable and one cut off by an injected fault: the reachable contact follows, the other is recorded as waiting with the reason, and a resume after the link heals tells only the one that was missed (`TestAMoveCampaignSurvivesAPartitionAndResumes`).
4. **Agent-answered** — a fake owner-agent serves a `pending_request` through the agent-answered serving mode, including the fallback chain (§6) (`TestConnectedAgentAnswerIsRelayed`, `TestBudgetExpiryRunsFallbackAndLateAnswerIsNotRelayed`).

The scenario harness (`docs/harness-design.md`) runs the same ground and more against the shipped image in containers; `make harness` is its hermetic tier.

**Conformance map.** Every clause of the HDTP §12 checklist, every error code and every limit is mapped to the tests that hold it in `docs/conformance.md`, and `TestConformanceDocCitesRealTests` fails the build when a cited test does not exist. These run in process; none takes a URL. A suite runnable against any HDTP node from outside does not exist.

### 14.2 Phases and exit demos

| Phase | Ships | Exit demo |
|---|---|---|
| P0 | repo, config, store + migrations + conformance, audit core, CLI frame, CI, container image | `compose up` → wizard-gated portal shell |
| P1 | accounts/keyring, public mTLS listener, tiers, guest + pending tools, contacts, invites, card, envelope | two local nodes pair and message |
| P2 | messaging, passkeys, tokens, Cedar, switchboard, owner MCP | browser pairing demo; agent reads inbox |
| P3 | upstream transports + OAuth, catalogs, exposures, three serving modes, providers, recipes, warnings | contact books a real Google Calendar slot |
| P4 | outbound hardening, tunnel adapters, LAN flag, doctor | NAT-crossing via tailscale; sealed cloudflared edge |
| P5 | ingress role, export and import, docs | own-domain VPS passthrough + terminate front |
| P6 | HDTP 1.0: root and leaf, chains on the wire, the move campaign, 1.x removed | two nodes pair through Cloudflare under chains they never share a key for |
