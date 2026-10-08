# cmd/hdtp-gateway

The `hdtp-gateway` binary. `main.go` is sixteen lines: it calls `cli.Run(os.Args[1:], version,
os.Stdout, os.Stderr)` and exits with the code it returns. Everything the binary does is in
[`internal/cli`](../../internal/cli/README.md); `internal/integrationtest/layering_test.go` ranks this
package 9 and `internal/cli` 8. The limits sidecar the node asks for its
call budgets is a different binary, `cmd/hdtp-limitd` (Rust).

## What it holds

- `main` passes the command line and the process's stdout and stderr to `cli.Run` and calls
  `os.Exit` with its result.
- `version` is the string `version` and `hdtp-gateway version` print. It is `0.0.0-dev` unless the
  build sets it with `-ldflags "-X main.version=..."`, which `make build`, `make dist` and both
  Dockerfiles do (`Makefile`, `Dockerfile`, `Dockerfile.full`).

## What it refuses, and how

Nothing of its own: the exit status is `cli.Run`'s. See the exit statuses in the
[`internal/cli` README](../../internal/cli/README.md#what-it-refuses-and-how).

## Invariants

- `main` hands `cli.Run` the process's own stdout and stderr and nothing else; the usage a
  subcommand's `-h` prints goes to the writers `Run` is given. `TestRunWritesUsageToTheWritersItIsGiven`
  holds that for `serve`, `doctor`, `healthcheck`, `migrate`, `account create`, `passkey list`,
  `token create`, `audit verify`, `export` and `import`; for `check store` and `ingress` it is by
  reading: their flag sets call `SetOutput(stderr)` too.

## Held by

This directory has no tests. The command line is held in `internal/cli`: `TestVersionCommand`
(`version` prints `hdtp-gateway <version>` and exits 0) and `TestUnknownCommand` (an unknown command
exits 2 and says so on stderr) in `cli_test.go`.

## What it does not do

It does not parse flags, read configuration or open anything. `hdtp-gateway --help` is not a help
flag: the first argument is a command name, so `--help` is an unknown command and exits 2 with the
usage on stderr. A command's flags are listed by its own `-h` where the command has a flag set of
its own (`serve -h`, `account create -h`, `check store -h`, `ingress serve -h`: usage on stderr,
exit 2); `account -h`, `passkey -h` and `token -h` print only their one-line usage and exit 2,
`ingress -h` and `check -h` answer `unknown subcommand`, and `audit -h` treats `-h` as the
subcommand and so takes the lock and opens the store first (run in a directory with no data dir it
exits 1 with `audit: lock: ...`).
