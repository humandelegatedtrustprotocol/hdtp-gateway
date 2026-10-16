package limitstest

import (
	"strings"
	"testing"
)

// A sidecar that exits before it binds its socket is reported when it exits, with its exit status
// and what it said, not after the deadline as a socket that is not there.
func TestASidecarThatExitsBeforeItAnswersIsReportedAtOnceWithItsStatusAndStderr(t *testing.T) {
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	rules.PendingInCap = 0
	s, stop, err := launch(rules)
	if err == nil {
		stop()
		t.Fatalf("a sidecar with rules it cannot enforce answered: %s", s.Path)
	}
	for _, want := range []string{"exited before it answered", "exit status 2", "pending_in_cap is at least 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
}
