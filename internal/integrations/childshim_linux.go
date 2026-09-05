//go:build linux

package integrations

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// applyMemoryCap is STRICT on Linux: the cap is enforced by the kernel, so a cap
// that cannot be set is a hard failure (SPEC §6.2 MUST).
//
// RLIMIT_DATA, not RLIMIT_AS. The spec says 512 MiB of RSS; RLIMIT_AS caps the
// ADDRESS SPACE, which is a different quantity, and a runtime that RESERVES far
// more than it uses dies instantly under it. Measured: a Node child needs more
// than 8 GiB of address space to start at all — 1, 2, 4 and 8 GiB all abort with
// "Fatal process out of memory: Zone" before running a line of the server — so at
// any AS value that lets an npx child start, the cap bounds nothing. That made
// SPEC §12.3's -full image, whose only purpose is running npx and uvx children,
// unable to run one.
//
// RLIMIT_DATA bounds the data segment — the memory actually allocated — which is
// the enforceable approximation of RSS, the same way RLIMIT_CPU approximates
// "1 CPU". The same child starts under it at 256 MiB.
func applyMemoryCap(limit uint64) error {
	if err := unix.Setrlimit(unix.RLIMIT_DATA, &unix.Rlimit{Cur: limit, Max: limit}); err != nil {
		return fmt.Errorf("child shim: RLIMIT_DATA: %w", err)
	}
	return nil
}
