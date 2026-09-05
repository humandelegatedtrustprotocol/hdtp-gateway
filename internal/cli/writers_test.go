package cli

import (
	"bytes"
	"strings"
	"testing"
)

// `Run(args, version, stdout, stderr)` is the library entry point, and it must
// write everything to the writers it is HANDED. Every shared flag set was built by
// commonFlags, which never called SetOutput, so flag's default applied and usage
// and parse errors went to the process's os.Stderr instead — invisible to any
// caller capturing output, and printed by tests that had asked for silence.
//
// It also silently disabled half the documentation lint:
// TestDocsOnlyQuoteRealCommands asks each command for its flag set by running it
// with -h and reading what comes back, got nothing, and skipped every flag check
// in every doc. An invented flag in a quickstart was therefore never caught.
func TestRunWritesUsageToTheWritersItIsGiven(t *testing.T) {
	for _, cmd := range [][]string{
		{"serve"}, {"doctor"}, {"healthcheck"}, {"migrate"},
		{"account", "create"}, {"passkey", "list"}, {"token", "create"},
		{"audit", "verify"}, {"backup", "create"},
	} {
		t.Run(strings.Join(cmd, " "), func(t *testing.T) {
			var out, errb bytes.Buffer
			Run(append(append([]string{}, cmd...), "-h"), "test", &out, &errb)
			got := out.String() + errb.String()
			if !strings.Contains(got, "Usage of") {
				t.Errorf("`%s -h` wrote no usage to the provided writers; it went to the "+
					"process's stderr instead", strings.Join(cmd, " "))
			}
			if !strings.Contains(got, "-config") {
				t.Errorf("`%s -h` did not list the shared -config flag: %q",
					strings.Join(cmd, " "), got)
			}
		})
	}
}

// And the lint that depends on it must now actually be able to read a flag set.
func TestDocLintCanReadAFlagSet(t *testing.T) {
	accepted, ok := acceptedFlags([]string{"account", "create"})
	if !ok || len(accepted) == 0 {
		t.Fatal("acceptedFlags read no flag set, so TestDocsOnlyQuoteRealCommands " +
			"skips every flag check it makes")
	}
	for _, want := range []string{"config", "slug", "name"} {
		if !accepted[want] {
			t.Errorf("flag set is missing -%s: %v", want, accepted)
		}
	}
}
