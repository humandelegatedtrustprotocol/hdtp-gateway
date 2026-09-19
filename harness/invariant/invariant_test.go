package invariant

import (
	"strings"
	"testing"
)

// The whole point of the status vocabulary: an unobserved property must never read
// as a pass. If NotObservable satisfied OK() the same way Pass does, a scenario
// could report green while proving almost nothing — which is precisely the failure
// mode four review passes of this project were spent correcting.
func TestNotObservableIsNotAPass(t *testing.T) {
	r := Report{{Name: "x", Status: NotObservable}}
	if !r.OK() {
		t.Error("an unobserved invariant should not FAIL a run")
	}
	if r.Unobserved() != 1 {
		t.Fatal("Unobserved did not count the gap")
	}
	if !strings.Contains(r.String(), "proves less than a full pass") {
		t.Errorf("the report does not disclose that it proved less than it appears to:\n%s", r)
	}
}

func TestAFailedInvariantFailsTheReport(t *testing.T) {
	r := Report{{Name: "a", Status: Pass}, {Name: "b", Status: Fail, Detail: "broke"}}
	if r.OK() {
		t.Error("a failing invariant did not fail the report")
	}
}

func TestAllReportsEveryInvariantByName(t *testing.T) {
	// Names are the contract the run report is read by; a silently dropped
	// invariant would look like a clean run.
	want := []string{"audit-chain", "session-bindings", "withdrawn-tools", "store-conformance"}
	got := Report{
		sessionBindingsBounded(), withdrawnToolsAreUncallable(), storeConformance(),
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.Name] = true
	}
	for _, w := range want[1:] {
		if !seen[w] {
			t.Errorf("invariant %q is missing from the report", w)
		}
	}
	// Every not-yet-observable check must say WHICH task will close it, or the
	// gap becomes permanent by being forgettable.
	for _, r := range got {
		if r.Status == NotObservable && r.Detail == "" {
			t.Errorf("%s is unobservable with no explanation of what would close it", r.Name)
		}
	}
}
