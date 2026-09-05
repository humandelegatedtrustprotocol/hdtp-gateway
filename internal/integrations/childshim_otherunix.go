//go:build unix && !linux

package integrations

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// applyMemoryCap is best-effort off Linux: macOS does not enforce these limits
// reliably. The child still runs (with the CPU cap), and the shortfall is
// printed so an operator sees it — the memory cap is a Linux guarantee.
func applyMemoryCap(limit uint64) error {
	if err := unix.Setrlimit(unix.RLIMIT_DATA, &unix.Rlimit{Cur: limit, Max: limit}); err != nil {
		fmt.Fprintf(os.Stderr, "child shim: memory cap not enforceable on this platform (%v); running without it\n", err)
	}
	return nil
}
