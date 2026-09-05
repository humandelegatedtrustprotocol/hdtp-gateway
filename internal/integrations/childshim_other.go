//go:build !unix

package integrations

import "fmt"

// ShimSupported: no setrlimit here — children run uncapped and the supervisor
// logs a warning (SPEC §6.2 caps are a Linux/macOS guarantee only).
const ShimSupported = false

func RunChildShim(args []string) error {
	return fmt.Errorf("child shim: resource caps are unsupported on this platform")
}
