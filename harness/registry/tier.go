package registry

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Select is the entries a tier runs, or, with ids, exactly those scenarios.
func Select(all []Entry, t Tier, ids []string) ([]Entry, error) {
	var out []Entry
	for _, e := range all {
		if len(ids) > 0 {
			if slices.Contains(ids, e.ID) {
				out = append(out, e)
			}
		} else if t.Includes(e.Tier) {
			out = append(out, e)
		}
	}
	for _, id := range ids {
		if !slices.ContainsFunc(out, func(e Entry) bool { return e.ID == id }) {
			return nil, fmt.Errorf("no scenario %s", id)
		}
	}
	if len(ids) == 0 && !slices.Contains(Tiers, t) {
		return nil, fmt.Errorf("no tier %q; the tiers are %v", t, Tiers)
	}
	return out, nil
}

// TimeoutSlack is added to the per-package sum of scenario timeouts: building the test binary and
// the need probes happen outside any scenario's own context.
const TimeoutSlack = 5 * time.Minute

// GoTest is the `go test` invocation that runs a selection: its packages, a -run expression that
// names exactly its tests, and a -timeout. Go applies -timeout to each test binary, and the tests of
// one package run one after another, so the budget is the largest per-package sum of the
// scenarios' own timeouts, plus TimeoutSlack.
type GoTest struct {
	Packages []string
	Run      string
	Timeout  time.Duration
}

func (g GoTest) Args() []string {
	args := append([]string{"test"}, g.Packages...)
	return append(args, "-run", g.Run, "-count=1", "-v", "-timeout", g.Timeout.String())
}

func GoTestFor(sel []Entry) GoTest {
	sums := map[string]time.Duration{}
	var tests []string
	for _, e := range sel {
		sums["./"+e.Package] += e.Timeout
		if !slices.Contains(tests, e.Test) {
			tests = append(tests, e.Test)
		}
	}
	var g GoTest
	for p, d := range sums {
		g.Packages = append(g.Packages, p)
		g.Timeout = max(g.Timeout, d)
	}
	slices.Sort(g.Packages)
	slices.Sort(tests)
	g.Run = "^(" + strings.Join(tests, "|") + ")$"
	g.Timeout += TimeoutSlack
	return g
}

// Case is one scenario's line in a tier's judgement.
type Case struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Promised bool    `json:"promised"`
	Verdict  Verdict `json:"verdict"`
	Reason   string  `json:"reason,omitempty"`
	MS       int64   `json:"ms"`
	// OK is whether this case lets the tier pass.
	OK bool `json:"ok"`
}

// Judge decides a tier from its results. A scenario the tier PROMISED (every need provided) must
// have PASSED; SKIPPED, FAIL or no result at all fails the tier. A scenario it did not promise may
// skip, and says what it needed; if it ran and FAILED, that still fails the tier.
func Judge(sel []Entry, provided []Need, results map[string]Result) []Case {
	var out []Case
	for _, e := range sel {
		r, ok := results[e.ID]
		missing := e.Missing(provided)
		c := Case{ID: e.ID, Name: e.Name, Promised: len(missing) == 0, Verdict: r.Verdict, Reason: r.Reason, MS: r.MS}
		switch {
		case !ok && c.Promised:
			c.Verdict = Fail
			c.Reason = "no result: " + e.Package + "." + e.Test + " never reached registry.Start, or never ran"
		case !ok:
			c.Verdict = Skipped
			c.Reason = "not run"
		}
		c.OK = c.Verdict == Pass || (!c.Promised && c.Verdict == Skipped)
		if !c.Promised {
			var how []string
			for _, n := range missing {
				how = append(how, string(n)+": "+HowToProvide(n))
			}
			c.Reason = strings.TrimSpace("not promised by this tier (" + strings.Join(how, "; ") + "). " + c.Reason)
		}
		out = append(out, c)
	}
	return out
}

// Passed reports whether every case lets the tier pass.
func Passed(cs []Case) bool {
	return !slices.ContainsFunc(cs, func(c Case) bool { return !c.OK })
}

// SummaryFile is the tier's own record, written beside the per-scenario results.
const SummaryFile = "summary.json"

// Summary is one tier run. It follows the envelope plan item T4 names for every runner
// ({run, repo, tier, cases}), but its cases are provisional: they add name, promised and ok,
// and have no evidence field. T4 settles the shared case shape.
type Summary struct {
	Run   string `json:"run"`
	Repo  string `json:"repo"`
	Tier  string `json:"tier"`
	Cases []Case `json:"cases"`
}

// TableText renders cases for a terminal: a verdict per line, and the ones that fail the tier
// marked.
func TableText(cs []Case) string {
	var b strings.Builder
	for _, c := range cs {
		mark := "  "
		if !c.OK {
			mark = "!!"
		}
		fmt.Fprintf(&b, "%s %-4s %-8s %7.1fs  %s", mark, c.ID, c.Verdict, float64(c.MS)/1000, c.Name)
		if c.Reason != "" {
			fmt.Fprintf(&b, "\n          %s", c.Reason)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// The markers around the generated table in docs/harness-design.md.
const (
	DocBegin = "<!-- registry:begin -->\n"
	DocEnd   = "<!-- registry:end -->"
)

// DocTable renders the registry as the Markdown table docs/harness-design.md carries between its
// registry markers. registry_test.go holds the doc equal to this.
func DocTable(all []Entry) string {
	var b strings.Builder
	b.WriteString("| ID | Scenario | Tier | Needs | Budget | Test |\n|---|---|---|---|---|---|\n")
	for _, e := range all {
		var needs []string
		for _, n := range e.Needs {
			needs = append(needs, string(n))
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | `%s.%s` |\n",
			e.ID, e.Name, e.Tier, strings.Join(needs, ", "), budget(e.Timeout), e.Package, e.Test)
	}
	return b.String()
}

func budget(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return d.String()
}
