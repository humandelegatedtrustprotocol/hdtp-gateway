# internal/limits/limitstest

Runs the real limits sidecar (`cmd/hdtp-limitd`) for a test, the way `internal/testid` mints real
identities: a test of the node's budgets that ran against a stand-in would pass for the stand-in's
reasons. It is a test-support package over [`internal/limits`](../README.md) (rank 1 in
`internal/integrationtest/layering_test.go`, above `internal/limits`).

Callers, all in `_test.go` files: `internal/limits`, `internal/cli` (`main_test.go` starts one
sidecar for the whole package's tests and points `HDTP_LIMITS_SOCKET` at it), `internal/node`,
`internal/public`, `internal/services/settings`, `harness/multiprocess` and `harness/scenario`
(`internal/integrationtest/layering_test.go` names it in its rank table but does not import it). No non-test file in the module imports it today.

## What it holds

- `Binary(t)`: the sidecar binary a test runs, `$HDTP_LIMITD` (`BinaryEnv`) or
  `cmd/hdtp-limitd/target/release/hdtp-limitd`, which `make limitd` builds.
- `DefaultConfig()` and `DefaultRules(t)`: the shipped `deploy/limitd/limits.json` and the rules in
  it, read from the file so there is no second copy of the numbers.
- `Start(t, rules)`, `StartDefault(t)`: start the sidecar on a socket of its own, return once it
  answers, stop it when the test ends. `LaunchDefault()` is the same for a `TestMain`, returning a
  `stop` function.
- `Sidecar`: embeds `*limits.Client` (so `s.Path` is the socket), and has `Config` (the config
  file's path), `Stop` and `Restart(t)`.
- `WriteConfig(path, socket, rules)`: writes a sidecar configuration file (mode 0600).

## What it refuses, and how

- `Binary` fails the test (`t.Fatal`), it does not skip, when neither `$HDTP_LIMITD` nor the built
  binary exists, naming `make limitd` and the variable. `LaunchDefault` returns that error.
- `Start` fails the test if the sidecar does not answer a `Probe` within 10 seconds, or cannot be
  started; `DefaultRules` fails the test if `limits.json` has a member `limits.Rules` does not
  (the file is decoded with `DisallowUnknownFields`).

## Invariants

- The sidecar is the real one, on a socket in a fresh temp directory (short, because a unix socket
  path is limited to 104 bytes on macOS), removed when it stops.
- `Stop` kills the process but keeps the client, so the test sees what a node sees when its sidecar
  is down. `Restart` starts it again on the same socket with the same rules; every counter is fresh,
  because the counters live in the sidecar's memory.

## Held by

Nothing tests the package directly; it is exercised by every user above. In `internal/limits`,
`TestASidecarThatIsDownIsUnavailableAndOneThatComesBackIsReconnectedTo` uses `Stop` and `Restart`;
`TestTheShippedConfigurationIsEnforceableAndCarriesTheOwnersNumbers` uses `DefaultRules` and
`StartDefault`; `TestASidecarRefusesARulesFileItCannotEnforce` uses `WriteConfig` and `Binary`.

## What it does not do

It is not enforced to be test-only: `layering_test.go` ranks it but does not forbid a production
package from importing it. It does not build the sidecar, and it does not copy the shipped numbers
into Go.
