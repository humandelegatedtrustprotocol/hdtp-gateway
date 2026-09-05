# Demo: crossing NAT — three ways a node behind a router stays reachable

The P4 exit demo. A home machine has no public IP and no port you can forward.
PACT does not care where a node lives, only that a caller can open a TLS session
to it — so there are three shapes of answer, and this walks all three on real
infrastructure.

The automated half already passes in CI:
`TestP4ExitNATCrossingViaEdgeAndRelay` drives a sealed call through a
terminating edge and an offline recipient through a relay, and
`TestRelayRoleAndGatewayOnTheCard` does the relay half against two real
`pact-gateway serve` processes. What CI cannot do is talk to Tailscale's or
Cloudflare's actual network. That is what this page is for.

**Verification status:** the live run below has **not yet been executed** —
record it here when done: `Last manual run: —`.

## The three shapes, and what each costs you

| Path | Who terminates TLS | Client certificates | Seal | When to pick it |
|---|---|---|---|---|
| `tailscale` (Funnel) | your node | visible end to end | your choice | you want end-to-end mTLS and a `*.ts.net` name is fine |
| `cloudflare` (edge) | Cloudflare | **stripped** — never arrive | forced `required` | you want your own domain and a CDN in front |
| relay | the relay, for queued traffic | n/a for the queue | forced `required` | your node is often off, or has no inbound path at all |

The middle row is the honest cost of an edge: identity arrives only as an
envelope signature, so sealing stops being optional (SPEC §2.5, §10.1). The
third row's cost is metadata — a relay sees who queues for whom, and how much,
though never the plaintext (SPEC §10.5, PACT §13).

## Path A — Tailscale Funnel (direct mode)

Full setup, limits and the tailnet prerequisites are in
[tailscale-funnel.md](tailscale-funnel.md). In short:

```json
{
  "tunnel": "tailscale",
  "public_bind": "127.0.0.1:8443"
}
```

```
PACT_TUNNEL_HOSTNAME=pact PACT_TUNNEL_AUTH_KEY=tskey-… pact-gateway serve
```

Adapter settings come from the portal (*Settings → Adapter credentials*) or
from the environment with a `PACT_TUNNEL_` prefix: `PACT_TUNNEL_AUTH_KEY`
reaches the adapter as `auth_key`. The startup banner
names the derived mode:

```
pact-gateway serving: data=./data internal=127.0.0.1:8080 public=127.0.0.1:8443 mode=direct tunnel=tailscale
public:  https://pact.<tailnet>.ts.net
```

Confirm from another machine that **your node's own key** answers, not a proxy's:

```
openssl s_client -connect pact.<tailnet>.ts.net:443 -servername pact.<tailnet>.ts.net </dev/null 2>/dev/null \
  | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64 | tr '+/' '-_' | tr -d '='
```

That value, prefixed `sha256:`, is what your card carries as `X-PACT-KEY`
(portal → Card). If they match, TLS ran end to end.

## Path B — cloudflared (edge mode)

Cloudflare terminates public TLS, so the node forces `seal: required` and
`client_cert: off`. It does not take your word for the mode — it derives it from
the adapter (SPEC §10.1), and refuses a config that claims otherwise.

Prerequisites: a zone on Cloudflare, a tunnel created in Zero Trust → Networks →
Tunnels with a public hostname routed to `https://localhost:8443`, and its
token.

```json
{
  "tunnel": "cloudflare",
  "public_bind": "127.0.0.1:8443",
  "public_url": "https://pact.example.com"
}
```

```
TUNNEL_TOKEN=eyJ… PACT_TUNNEL_HOSTNAME=pact.example.com pact-gateway serve
```

If `cloudflared` is on `PATH` the node supervises it as a child; if not, it
prints the compose service to run yourself and carries on:

```
tunnel:  cloudflared not found on PATH — run the connector yourself:
services:
  cloudflared:
    image: cloudflare/cloudflared:latest
    restart: unless-stopped
    command: tunnel --no-autoupdate run
    environment:
      TUNNEL_TOKEN: ${TUNNEL_TOKEN}
```

Verify the derived posture and the refusals:

```
pact-gateway doctor
```

Expect `ok tunnel cloudflare (mode edge, seal required, client_cert off)`. Then,
from a peer, check that the edge really is a wall for anything unsealed: a
plaintext `send_message` comes back `seal_required`, and a client certificate
presented on that connection is simply not there when the node looks (SPEC
§5.1). Rate limits fall back to `CF-Connecting-IP` — the only forwarded-IP
header this adapter honors, and never generic `X-Forwarded-For` (SPEC §5.7).

Two things that are **not** possible in this mode, by construction:

- `client_cert: required` — no certificate can arrive, so the knob would refuse
  every call.
- relay mode on the same listener — a relay verifies a sender's signature with
  the key from that sender's certificate, which the edge strips. `serve` refuses
  the combination by name (`relay_role_needs_client_certificates`).

## Path C — a relay, for a node that is often off

A relay is another `pact-gateway`, run by you or by someone you trust, that
holds sealed envelopes until you fetch them. It never holds a key that opens
them.

On the relay machine:

```json
{
  "relay": true,
  "public_bind": ":8443",
  "public_url": "https://relay.example.com"
}
```

These knobs are also in the portal under *Settings → Relay*.

On your node, publish that relay and pin it:

```json
{
  "gateway_url": "https://relay.example.com",
  "gateway_fingerprint": "sha256:…"
}
```

The fingerprint is the relay's `X-PACT-KEY`. Leave it empty **only** if the
relay has a real WebPKI certificate; a self-signed relay left unpinned would
trust anyone who can answer at that address.

Your node then does three things on its own:

1. puts `X-PACT-GATEWAY: https://relay.example.com` on its card, which is how a
   peer whose direct call failed knows where to queue instead (PACT §9);
2. syncs its allow-list — its **active contacts, nobody else** — to the relay,
   and re-syncs whenever that set changes;
3. polls the relay (15 s, backing off to 10 min), and runs every fetched
   envelope through the same open order a direct call takes, with one
   documented relaxation: relay-delivered envelopes are exempt from the 300 s
   freshness window and bounded by `exp` (≤30 days) instead.

To watch it work, stop your node, have a contact send you a message, then start
it again. The message arrives on the next poll. On the relay, `pact-gateway
audit export` shows `relay_call … queued` rows carrying sender, recipient,
`msg_id` and size — and no text. That is the trade-off, stated rather than
hidden.

## What to record here after a live run

Replace the placeholder above with the date, and note for each path:

- the public URL that answered and, for path A, the fingerprint comparison;
- `pact-gateway doctor`'s tunnel line verbatim;
- for path B, the `seal_required` refusal you got for an unsealed call;
- for path C, the wall-clock gap between "sent while the node was down" and
  "appeared in the inbox".
