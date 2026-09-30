package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/storecheck"
)

const checkUsage = "usage: pact-gateway check <store> [flags]"

// checkCmd is `check store`: every card and certificate the store holds, read by the identity
// core's rule (storecheck), each refusal named, exit 1 when there is one. It reads and writes
// nothing, so like `doctor` it runs beside a serving node; it takes no lock. A store whose schema
// is not this binary's is not read — the statements would not match its tables — and is refused
// with the command that brings it up.
func checkCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, checkUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	if sub != "store" {
		fmt.Fprintf(stderr, "check: unknown subcommand %q\n%s\n", sub, checkUsage)
		return 2
	}
	var cfgPath string
	fs := commonFlags("check store", &cfgPath, stderr)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "check store:", err)
		return 1
	}
	ctx := context.Background()
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "check store:", err)
		return 1
	}
	defer st.Close()
	if err := st.SchemaCurrent(ctx); err != nil {
		fmt.Fprintf(stderr, "check store: %v; run `pact-gateway migrate` with the node stopped, then check again\n", err)
		return 1
	}
	rep, err := storecheck.Run(ctx, st, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "check store:", err)
		return 1
	}
	for _, line := range rep.Lines() {
		fmt.Fprintln(stdout, line)
	}
	if len(rep.Refusals) > 0 {
		return 1
	}
	return 0
}
