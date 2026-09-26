// Package cli implements the command-line interface of SPEC §12.1: one binary,
// subcommand-per-concern, stdlib flag parsing. Against a running node the CLI talks
// over the admin unix socket; offline database commands take the store lock and
// therefore refuse to run while the node is serving.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
)

// Run dispatches os.Args-style arguments; version is the build-stamped version
// string. Returns a process exit code.
func Run(args []string, version string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, "pact-gateway "+version)
		return 0
	case "serve":
		return serve(rest, stdout, stderr)
	case "ingress":
		return ingressCmd(rest, stdout, stderr)
	case "migrate":
		return migrate(rest, stdout, stderr)
	case "doctor":
		return doctor(rest, stdout, stderr)
	case "healthcheck":
		return healthcheck(rest, stderr)
	case "account":
		return account(rest, stdout, stderr)
	case "passkey":
		return passkey(rest, stdout, stderr)
	case "token":
		return token(rest, stdout, stderr)
	case "audit":
		return auditCmd(rest, stdout, stderr)
	case "export":
		return exportCmd(rest, version, stdout, stderr)
	case "import":
		return importCmd(rest, stdout, stderr)
	case "__child":
		// hidden: the resource-cap shim for supervised stdio children (SPEC §6.2)
		if err := integrations.RunChildShim(rest); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "pact-gateway: unknown command %q\n", cmd)
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: pact-gateway <command> [flags]

commands:
  serve     run the node
  ingress   serve|token — the ingress role (own-domain front door for paired nodes)
  migrate   run store migrations (node must be stopped)
  doctor    diagnose configuration, data dir, store, lock
  healthcheck  probe the internal /healthz (container HEALTHCHECK)
  account   create|list accounts and identity keys; csr|install-leaf|certificate|address|announce the leaf a wallet issues and the move it may be (node must be running; talks over the admin socket)
  passkey   list|remove|reset-wizard (node must be running)
  token     create|list|revoke owner-MCP bearer tokens (node must be running)
  audit     verify|export|archive|repair the hash chain (offline; node must be stopped)
  export    write contacts and chats, and nothing else, to a file (offline; node must be stopped)
  import    take an export in; each identity then needs a new certificate from its wallet (offline)
  version   print the version
`)
}

// commonFlags returns a FlagSet with the -config flag every subcommand shares.
//
// It takes the caller's stderr because `Run` is handed writers and must use them.
// Without SetOutput, flag writes usage and parse errors to the process's
// os.Stderr instead: invisible to an embedder capturing output, noisy in tests
// that asked for silence, and — because the documentation lint asks each command
// for its flag set by running it with -h and reading what comes back — it read
// nothing and silently skipped every flag check in every doc.
func commonFlags(name string, cfgPath *string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(cfgPath, "config", os.Getenv("PACT_CONFIG"), "path to config file (JSON)")
	return fs
}

func loadConfig(cfgPath string) (*core.Config, error) {
	cfg, err := core.Load(cfgPath, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	// `internal_host` is the passkey relying party (SPEC §12.2), and the passkey library refuses some
	// names outright — an IP address, a single label other than `localhost`, a trailing dot. The node
	// used to learn that at the first ceremony: it started cleanly, served its portal, and no passkey
	// could be registered or used on it. The judgement here is the library's own, so what is refused
	// now is exactly what a ceremony would have refused later.
	if cfg.InternalHost != "" {
		if err := auth.ValidRelyingPartyID(cfg.InternalHost); err != nil {
			return nil, fmt.Errorf("%s: internal_host %q cannot be a passkey relying party (%v) — use the full domain name the portal is served at, or `localhost`",
				core.RuleInternalHostIsRPID, cfg.InternalHost, err)
		}
	}
	return cfg, nil
}

func runErr(err error, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	return 0
}

func openStore(cfg *core.Config) (store.Store, error) {
	switch cfg.StoreEngine {
	case "postgres":
		return store.OpenPostgres(context.Background(), cfg.PostgresDSN)
	default:
		return store.OpenSQLite(filepath.Join(cfg.DataDir, "pact.db"))
	}
}
