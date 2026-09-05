// Command harness drives the pact-gateway scenario suite (docs/harness-design.md).
//
// It lives in a separate module from the product on purpose: it orchestrates
// containers and virtual machines and drives a real browser over CDP, and none of
// those dependencies may reach the shipped artifact.
//
// Today it implements `preflight`, which reports whether this host can run each
// fabric. The scenario runner itself lands in later P14 tasks.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/preflight"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "preflight":
		os.Exit(runPreflight())
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

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
