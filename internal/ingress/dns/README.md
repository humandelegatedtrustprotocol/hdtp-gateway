# internal/ingress/dns

The DNS adapter of the ingress role (SPEC.md §10.6). It exists so the ingress can answer ACME DNS-01 for its wildcard certificate; no per-pairing record is ever written, because the owner points the wildcard at the ingress once. The only caller is `internal/cli/ingresscmd.go`, which, when `--terminate` is given with the Cloudflare DNS choice, builds the adapter from the API token and the domain and passes `Solver()` to `ingress.NewACME` as `ACMEOptions.DNS`. The package calls only the libdns Cloudflare provider; it imports nothing from the node (rank 0 in `internal/integrationtest/layering_test.go`).

## What it holds

- `Cloudflare`: the adapter. `Provider` is the libdns provider; `Zone` and `TTL` are recorded by the constructor.
- `NewCloudflare(apiToken, zone)`: builds it. The zone gets a trailing dot if it lacks one; the TTL is set to five minutes.
- `(*Cloudflare).Solver()`: returns the provider, which is what certmagic's `DNS01Solver` consumes.

## What it refuses, and how

`NewCloudflare` returns an error for an empty API token ("cloudflare needs an API token with Zone.DNS:Write") and for an empty zone name. Nothing else is checked here, and no network call is made: a token without the right permission is found when certmagic first solves a challenge.

## Invariants

- The adapter writes no record of its own. The only DNS writes are the ones certmagic makes through the provider for DNS-01 challenges.
- The zone held always ends in a dot.

## Held by

No test in this directory. The only rule that holds the package is `internal/integrationtest/layering_test.go`, `TestImportsPointDownTheLayers`, which ranks it 0. `internal/ingress`'s ACME tests use a stub DNS resolver and Pebble, not this adapter.

## What it does not do

- It does not register or update an A/AAAA record for the wildcard; the owner does that once.
- It does not read `Zone` or `TTL` after construction: only `Provider` is used, through `Solver`.
- It is the only DNS adapter: the ingress command's `--dns` flag names "cloudflare" and nothing else, and the adapter is built only when that flag is set together with `--terminate`.
