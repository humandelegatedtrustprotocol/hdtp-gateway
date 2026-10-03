package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
)

// TestMain gives every `serve` and `doctor` these tests run one limits sidecar, as a host has one
// for every node process on it (SPEC §5.7), named through the environment, which outranks every
// configuration file a test writes. Without one, every sealed call is refused and /healthz answers
// 503, which is what a test of that says for itself (limits_test.go).
func TestMain(m *testing.M) {
	s, stop, err := limitstest.LaunchDefault()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cli tests:", err)
		os.Exit(1)
	}
	if err := os.Setenv("HDTP_LIMITS_SOCKET", s.Path); err != nil {
		stop()
		fmt.Fprintln(os.Stderr, "cli tests:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}
