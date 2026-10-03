# Open items carried from finished plans

At the HDTP rename the node's finished plans and reviews were frozen (the owner's decision): the
build plan (`PLAN.md`) and fourteen dated records under `docs/release/`, listed with their hashes
in `docs/records.sha256`, keep the bytes they had on 2026-10-03 and are not edited again. They say what
was true on their day, under the names of their day. This file carries what was still open in them,
each item with its source and date. Nothing else in those files was open.

## Owner's decisions

### B2c: the cloud carries the node's retired columns and relay tables

From `docs/release/audit-2026-09-19-plan.md` (2026-09-19), whose status was `BLOCKED — owner's
decision`. The cloud's identity store, in `gateway/migrations/identity/` of the cloud repository,
was a harvested copy of the node's SQLite migrations as they stood then. The node went on to drop
the relay tables, the key-rotation columns and the coexistence flag. The cloud's copy did not. The record gave four reasons this was not a side effect of the node's change:
- `scripts/harvest.sh` also overwrites the portal;
- the cloud records some migrations without applying them (`src/identity/migrate.ts`), so whether
  a column exists in a deployed object has to be established;
- the files are byte-locked (`migration-locks.json`);
- the change runs forward-only against production objects.

Where it stood on 2026-10-03, read from the cloud's `main` at 43209541:
- the harvested copies `0014_rotation.sql` and `0015_relay.sql` are still in that directory;
- the cloud's own `cloud/1001_base.sql`, which runs after them, renames the fan-out table and drops
  the relay table and its indexes.

Whether the deployed schema still holds any of the dropped columns was not checked here. That
check, and removing the harvested copies, are what is left.

## Deferred engineering

From `docs/release/refactor-2026-09-26.md` (2026-09-26), section "Deferred (named, not done here)":

- `ceremony.js` to TypeScript. Any edit to it touches the build and the pin.
- The admin console's Cedar policy, from shadow mode to enforcing. This is a policy decision.

Both are in the cloud repository.

## Live runs only the owner can make

From `PLAN.md` (the build plan, 2026-08-24 onwards), tasks P10-12e to P10-12j. Each is
`blocked (owner-only)` because it needs a resource only the owner has. Each run is written up as a
demo, and the demo is the procedure:

| Task | Run | Needs | Procedure |
|---|---|---|---|
| P10-12e | the README quickstart, verbatim, on a clean machine | a clean machine | [`README.md`](../../README.md) |
| P10-12f | a contact books a real Google Calendar slot | a Google account and a live calendar MCP server | [`docs/demos/real-gcal.md`](../demos/real-gcal.md) |
| P10-12g | reachable through Tailscale Funnel | a tailnet with Funnel enabled | [`docs/demos/tailscale-funnel.md`](../demos/tailscale-funnel.md) |
| P10-12h | reachable through a paid ngrok TLS endpoint | a paid ngrok plan (TLS endpoints are not on the free tier) | [`docs/demos/ngrok.md`](../demos/ngrok.md) |
| P10-12i | NAT crossing, every path | a second machine behind real NAT | [`docs/demos/nat-crossing.md`](../demos/nat-crossing.md) |
| P10-12j | own-domain VPS ingress, passthrough and terminate | a public VPS and a Cloudflare domain | [`docs/demos/own-domain.md`](../demos/own-domain.md) |

The scenario harness ([`docs/harness-design.md`](../harness-design.md)) covers part of these runs
without the owner's resources. The Funnel and ngrok runs need the owner's own account.
