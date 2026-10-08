# services/presence

Answers one question: is the owner's agent attached to the owner MCP right now? The answer decides how long a contact's call to an agent-answered capability is held (SPEC §6.8). `internal/cli/serve.go:294` builds it with `NewAgentAnswered`; `internal/cli/compose.go` passes the `*Tracker` on to the owner MCP, which calls `Seen` on each authenticated request. It calls `internal/integrations` (to build `AgentAnswered`) and the store.

## What it holds

- `NewAgentAnswered(st, audit)`: builds an `*integrations.AgentAnswered` together with the `*Tracker` whose `Any()` is its `Connected` function. They are made together so that `Connected` is never nil during boot (the defect the comment names, P12-11). The `Connected` function ignores its account argument and answers for the whole node.
- `Tracker`: `Store` (a `PresenceStore`), `Now` (injectable clock; nil is `time.Now`).
  - `Seen()` records an authenticated owner-MCP request. At most one store write per `SeenEvery` per process (`presence.go:78-88`); a failed write is dropped and not retried before the next interval.
  - `Any()` reads the last-seen time from the store and reports whether it is younger than `Window`.
- `PresenceStore`: `TouchOwnerPresence(ctx, at)` and `OwnerPresenceSeenAt(ctx)`. The last request is kept in the store so every node process sharing it answers the same.
- `Window` = 1 minute; `SeenEvery` = 5 seconds.

## What it refuses, and how

It returns no errors. `Any()` is false when the store read fails or nothing was ever recorded (`at == 0`); `Seen()` discards a store write error.

## Invariants

- Presence is a request-recency hint, never an authorization (comment on `Seen`). The owner MCP is stateless (SPEC §8.5), so "attached" means "asked within `Window`".
- `Window` exceeds the longest `wait_for_updates` hold plus `SeenEvery`, so an agent in a wait loop does not drop out between two calls. `ownermcp.WaitMaxSec` is 25 (`internal/internalui/ownermcp/watch.go:49`).
- A request seen by one process makes the agent present on every process using the same store.
- The tracker and the agent-answered service are never separable: `NewAgentAnswered` is the only constructor pairing them.

## Held by

`presence_test.go`:

- `TestAgentAnsweredKnowsAboutPresenceFromConstruction`: `Connected` is non-nil from construction, false before any request, and true after the returned tracker sees one.
- `TestOwnerPresenceIsARecentRequestOnAnyProcess`: two trackers on one database file; present for `Window - 1s`, absent at `Window`.
- `TestPresenceIsWrittenAtMostOncePerInterval`: a `Seen` within `SeenEvery` does not rewrite; one after it does.
- `TestPresenceOutlastsTheLongestWait`: `Window > ownermcp.WaitMaxSec*time.Second + SeenEvery`.

## What it does not do

It does not scope presence to an account or an identity (the account id is ignored), does not authenticate anyone, and does not compensate for clock skew between hosts sharing a store: `Window`'s comment says processes whose clocks differ by more than the room left in it disagree.
