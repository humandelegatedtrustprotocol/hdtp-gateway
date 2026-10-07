# Two users, two Cloudflare tunnels, one domain

The only demo where the product meets a **third-party edge it does not control**.
Two nodes, each behind its own Cloudflare tunnel on a subdomain of a real zone,
pairing and messaging across the public internet.

Executed against `hdtp.dev` — `Last manual run: 2026-09-18`; the first run, on `hdtp.io`, was 2026-08-26. It found
E17 on its first attempt, and F9 through F11 on the run of 2026-09-18 (see
`batondeck/docs/release/findings-2026-09-18-rig.md`, in the BatonDeck repository, which is not public).

It is worth the setup because edge mode cannot be faked convincingly. Cloudflare
terminates TLS, so the node never sees a caller's certificate and identity comes
from sealed envelopes alone; the connector delivers from inside the node's own
network namespace; and the peer a node dials presents *Cloudflare's* certificate,
not the peer's. Each of those has broken this product at least once, and none of
them break locally.

## What you need

- A domain on Cloudflare, and its zone id
- An API token with **Zone.DNS:Edit** on that zone
- `cloudflared` logged in (`cloudflared tunnel login`)
- Docker, and `make harness-image`
- **A wallet**: `cargo build --release -p hdtp` in a checkout of the hdtp-identity repository, or `HDTP_WALLET=<path>`.
  An HDTP 1.0 account holds a key and no certificate until a person's root issues a leaf for
  it, so a rig whose nodes never meet a wallet has no identity to pin and the scenario stops
  at *"has no certificate yet"*. Alice and bob are fictional, so the script keeps their vaults
  in its work directory; a real owner runs those three commands themselves.

## Run it

```
export HDTP_CF_DOMAIN=example.com
export CF_ZONE_ID=<the zone id>
export CF_API_TOKEN=<a token with Zone.DNS:Edit>

./docs/demos/cloudflare-two-users.sh
```

That creates two tunnels (`hdtp-alice`, `hdtp-bob`), two proxied CNAMEs
(`alice.` and `bob.`), six containers — a node, a connector and a portal bridge each — and
then **certifies both identities**: a vault per user, `account csr` out of the container,
`hdtp id issue`, `install-leaf` back in. It prints the installed leaf for each, and skips the
whole step for an identity that already has a certificate, so a re-run against a kept volume
changes nothing. Then:

```
cd harness
HDTP_HARNESS_LIVE=1 HDTP_CF_DOMAIN=example.com \
  go test ./scenario/ -run TestTwoUsersOverRealCloudflare -v -count=1
```

`-count=1` matters: Go caches a passing live test, and a cached pass against a rig you have
since rebuilt reports the *previous* rig's fingerprints.

And the black-box battery, which is the other half of a run:

```
hdtp vectors intrude --against https://alice.example.com/a/alice/mcp --card alice.vcf
```

It needs `--card` because the node serves **no card at a URL of its own**: SPEC §9 puts a
host's card on its invite landing page, and the public surface is three routes —
`/a/{slug}/mcp`, `/i/{token}`, `/mcp`. Save the card from the landing page (or from a peer
that has already paired). A good run says `11 scenarios: 11 blocked, 0 reproduce`; anything
it cannot classify prints as `unknown:` and counts as a REPRODUCTION, on purpose.

The test registers a passkey on each node through a real browser, connects to
each owner MCP, has alice issue an invite, has **bob redeem it across the
internet**, grants bob permission, sends a message edge to edge, and checks that
neither connector ever logged the plaintext.

## Three things this demo exists to catch

**The connector arrives over loopback.** It shares the node's network namespace,
so it reaches `localhost:8443`. Edge mode defaults `lan_connections` **off**, and
until the §12.2 carve-out for the carrier's own delivery, the node refused its own
connector — every edge deployment served nothing at all. Run the connector in its
*own* container instead and it arrives from an RFC 1918 address, which is still
refused by design; that deployment must turn `lan_connections` on.

**The Host header is public while the socket is local.** The MCP SDK enables DNS
-rebinding protection for exactly that combination, so every tunnelled call was
answered `Forbidden: invalid Host header`. Disabled on the public surface only —
it is always TLS and presents the node's own certificate, so a rebinding page
cannot complete a handshake for its own name. The owner MCP keeps the protection.

**The peer presents Cloudflare's certificate.** HDTP §2 accepts a server on the
pinned fingerprint *or* WebPKI validity for the hostname; behind an edge only the
second can apply. Every production caller built its outbound client with
`Roots: x509.NewCertPool()` — an empty, non-nil pool, which Go reads as "trust
nothing" rather than "use the system roots". So the WebPKI branch could never
succeed and no node could send to any contact behind an edge. Found here, on the
first real run.

## Bringing it back up later

Docker Desktop restarting — or the host sleeping long enough for the tunnel's
QUIC connections to die — leaves the containers "healthy" while nothing works.
**Re-run the script.** It is idempotent: the tunnels and DNS records already
exist, and the named data volumes carry the accounts, passkeys, contacts and
message history through.

Do *not* restart them by copying environment out of the running container:

```
# DON'T
ENVS=$(docker inspect hdtpcf-alice --format '{{json .Config.Env}}' | ...)
docker rm -f hdtpcf-alice && docker run -d $ENVS ...
```

One restart where that capture comes back empty and every later restart inherits
the emptiness — the node then starts with no `HDTP_PUBLIC_URL` and no tunnel
token, reports `mode=direct`, and serves a public surface the tunnel points at
but the card no longer advertises. It looks like a Cloudflare problem. It is not.
The configuration belongs in the script, not in the thing being restarted.

## Cleaning up

```
./docs/demos/cloudflare-two-users.sh --down    # containers only
cloudflared tunnel delete hdtp-alice && cloudflared tunnel delete hdtp-bob
```

The two DNS records stay until you remove them in the dashboard or by API; they
are harmless once the tunnels are gone, but they are yours to clear.
