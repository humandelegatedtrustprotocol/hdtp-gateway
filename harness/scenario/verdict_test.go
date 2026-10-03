package scenario

import (
	"slices"
	"testing"
)

// judge is what turns the conformance battery's `go test -json` into S19's verdict. It is held
// here, with no battery and no node: a leaf that failed is a finding, one that failed saying
// UNREACHED never reached what it tests, a parent that failed only because a child did is not a
// second finding, a skip is counted (S19 fails on any), and the package's own lines are nobody's.
func TestJudgeReadsTheBatterysEvents(t *testing.T) {
	ev := func(action, test, out string) testEvent { return testEvent{Action: action, Test: test, Output: out} }
	v := judge([]testEvent{
		ev("run", "TestLive", ""),
		ev("output", "TestLive/guest/control", "    x_test.go:1: UNREACHED: POST https://n/a: connection refused\n"),
		ev("fail", "TestLive/guest/control", ""),
		ev("output", "TestLive/envelope/expired", "    x_test.go:2: answered ok, want envelope_invalid\n"),
		ev("fail", "TestLive/envelope/expired", ""),
		ev("fail", "TestLive/guest", ""),
		ev("fail", "TestLive/envelope", ""),
		ev("fail", "TestLive", ""),
		ev("pass", "TestLive/surface/probe", ""),
		ev("skip", "TestCert/stale kid", ""),
		ev("pass", "TestCert", ""),
		ev("skip", "", ""),
		ev("fail", "", ""),
	})
	if want := []string{"TestLive/envelope/expired", "TestLive/guest/control"}; !slices.Equal(v.failed, want) {
		t.Errorf("failed %v, want the two leaves %v", v.failed, want)
	}
	if want := []string{"TestLive/guest/control"}; !slices.Equal(v.unreached, want) {
		t.Errorf("unreached %v, want %v", v.unreached, want)
	}
	if want := []string{"TestCert/stale kid"}; !slices.Equal(v.skipped, want) {
		t.Errorf("skipped %v, want %v", v.skipped, want)
	}
	if !v.passedSet["TestCert"] || !v.passedSet["TestLive/surface/probe"] || v.passedSet["TestLive"] {
		t.Errorf("passed %v", v.passed)
	}
}

// The intrusion tool's last line is what S18 reads its counts from.
func TestIntrudeSummaryReadsTheToolsLastLine(t *testing.T) {
	out := "scenarios (judged by the answer's code only)\n  blocked    x: envelope_invalid\n" +
		"28 scenarios: 27 blocked, 0 reproduce, 1 never reached an HDTP answer\n"
	m := intrudeSummary.FindStringSubmatch(out)
	if m == nil || m[1] != "28" || m[2] != "27" || m[3] != "0" || m[4] != "1" {
		t.Fatalf("read %v from %q", m, out)
	}
	if intrudeSummary.FindStringSubmatch("the target's card is not a card: nothing to aim at") != nil {
		t.Error("a run that never started read as a summary")
	}
}
