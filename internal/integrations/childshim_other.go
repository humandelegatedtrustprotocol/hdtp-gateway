//go:build !unix

package integrations

import "fmt"

// ShimSupported: no setrlimit here — children run uncapped and the supervisor
// logs a warning (SPEC §6.2 caps are a Linux/macOS guarantee only).
const ShimSupported = false

// RunChildShim always fails on this platform: there is no setrlimit, so the
// `__child` mode cannot apply caps (ShimSupported is false and the supervisor
// does not route through it).
func RunChildShim(args []string) error {
	return fmt.Errorf("child shim: resource caps are unsupported on this platform")
}
