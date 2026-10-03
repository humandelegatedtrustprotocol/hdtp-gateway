# Demo: crossing NAT — two ways a node behind a router stays reachable

A home machine has no public IP and no port you can forward. HDTP does not care where a
node lives, only that a caller can open a TLS session to it — so there are two shapes of
answer, and this walks both on real infrastructure. (There was a third, a store-and-forward
relay for a node that is often off. The relay role went with pre-HDTP 1.x: it would see every
sender, recipient and timestamp for its trouble, and what 2.x makes safe instead is being
hosted — HDTP §9.)

The automated half runs in `make check`:
`TestEdgeModeSealedSucceedsPlaintextRefusedCertsIgnored` drives a sealed call through a
terminating edge, and `TestTerminatingIngressIsPinnedOnTheOnwardLeg` the onward leg. Two
live harness scenarios do it with real containers — an `frps` tunnel and an own-domain
ingress (`docs/harness-design.md` §5a). What none of them can do is talk to Tailscale's
or Cloudflare's actual network. That is what this page is for.

**Verification status:** the live run below has **not yet been executed** —
record it here when done: `Last manual run: —`.

## The two shapes, and what each costs you

| Path | Who terminates TLS | Client certificates | Seal | When to pick it |
|---|---|---|---|---|
| `tailscale` (Funnel) | your node | visible end to end | your choice | you want end-to-end mTLS and a `*.ts.net` name is fine |
| `cloudflare` (edge) | Cloudflare | **stripped** — never arrive | forced `required` | you want your own domain and a CDN in front |

The second row is the honest cost of an edge: identity arrives only inside a sealed
envelope, so sealing stops being optional (SPEC §2.5, §10.1).

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
hdtp-limitd -config limits.json &   # the limits sidecar (SPEC §5.7): deploy/limitd/limits.json with "socket" set to <data_dir>/limits.sock
HDTP_TUNNEL_HOSTNAME=hdtp HDTP_TUNNEL_AUTH_KEY=tskey-… hdtp-gateway serve
```

Adapter settings come from the portal (*Settings → Adapter credentials*) or
from the environment with a `HDTP_TUNNEL_` prefix: `HDTP_TUNNEL_AUTH_KEY`
reaches the adapter as `auth_key`. The startup banner
names the derived mode:

```
hdtp-gateway serving: data=./data internal=127.0.0.1:8080 public=127.0.0.1:8443 mode=direct tunnel=tailscale
public:  https://hdtp.<tailnet>.ts.net
```

Confirm that **your node's own chain** answers, not a proxy's. The node does it the way a
peer would — the chain served at the public URL, validated to your root at the address your
leaf names (HDTP §14.2):

```
hdtp-gateway doctor
```

`ok probe … reachable` means TLS ran end to end and the leaf names this address. `wrong_cert
… rule 5` means it names another one: issue a leaf for the address you are actually reached
at (`account csr -purpose move`).

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
  "public_url": "https://hdtp.example.com"
}
```

```
hdtp-limitd -config limits.json &   # the limits sidecar, as above
TUNNEL_TOKEN=eyJ… HDTP_TUNNEL_HOSTNAME=hdtp.example.com hdtp-gateway serve
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
hdtp-gateway doctor
```

Expect `ok tunnel cloudflare (mode edge, seal required, client_cert off)`. Then,
from a peer, check that the edge really is a wall for anything unsealed: a
plaintext `request_contact` comes back `identity_required` — behind an edge no
certificate arrives, so an unsealed call establishes nobody, and identity precedes
sealing (SPEC §5.3, §10) — and a client certificate presented on that connection is
simply not there when the node looks (SPEC §5.1). Rate limits fall back to `CF-Connecting-IP` — the only forwarded-IP
header this adapter honors, and never generic `X-Forwarded-For` (SPEC §5.7).

One thing is **not** possible in this mode, by construction: `client_cert: required`.
No certificate can arrive, so the knob would refuse every call.

## What to record here after a live run

Replace the placeholder above with the date, and note for each path:

- the public URL that answered and, for path A, `doctor`'s probe line;
- `hdtp-gateway doctor`'s tunnel line verbatim;
- for path B, the `identity_required` refusal you got for an unsealed call.
