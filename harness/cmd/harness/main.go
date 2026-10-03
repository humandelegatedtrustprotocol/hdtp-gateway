// Command harness drives the hdtp-gateway scenario suite (docs/harness-design.md).
//
// It lives in a separate module from the product on purpose: it orchestrates
// containers and virtual machines and drives a real browser over CDP, and none of
// those dependencies may reach the shipped artifact.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/fabric"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/preflight"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "preflight":
		os.Exit(runPreflight())
	case "shaper":
		os.Exit(runShaper())
	case "list":
		os.Exit(runList(os.Args[2:], os.Stdout))
	case "run":
		os.Exit(runTier(os.Args[2:], os.Stdout))
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "harness: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: harness <command>

commands:
  preflight   report whether this host can run each fabric (container, vm)
  shaper      build the traffic-shaper image if this machine does not have it
  list        print the scenario registry as JSON (-doc: the table in docs/harness-design.md)
  run         run a tier (-tier fabric|pr|nightly) or scenarios (-id S2,S9) and judge it:
              a scenario the tier promised must PASS; one it did not promise says what it needs

run from the harness module's directory: the registry is read from its source.
`)
}

// probeTimeout bounds the whole preflight. Each check shells out to a tool that
// may be missing, wedged, or waiting on a daemon socket; none of that should hang
// a developer's terminal.
const probeTimeout = 20 * time.Second

func runPreflight() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	report := preflight.Probe(ctx, execRunner)
	fmt.Print(report)

	// The container fabric carries five of the six topologies, so it is what
	// decides the exit status. A missing VM fabric is reported, not fatal: it
	// disables one nightly-tier suite.
	if !report.Ready(preflight.FabricContainer) {
		fmt.Fprintln(os.Stderr, "\nharness: the container fabric is not available on this host")
		return 1
	}
	if !report.Ready(preflight.FabricVM) {
		fmt.Fprintln(os.Stderr, "\nharness: the VM fabric is unavailable — the long-horizon suite will be skipped")
	}
	return 0
}

func runShaper() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := fabric.EnsureShaper(ctx, fabric.Local); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		return 1
	}
	fmt.Println("harness: the shaper image is present")
	return 0
}

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
