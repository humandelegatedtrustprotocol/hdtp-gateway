package registry

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The harness's own registry reads cleanly: every live test has a spec, ids are unique, and every
// spec is well-formed. A floor rather than a count, so adding a scenario does not break it.
func TestTheHarnessRegistryIsReadable(t *testing.T) {
	all, err := Scan("..")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 19 {
		t.Fatalf("the registry lists %d scenarios; on 2026-09-27 it listed 19, and none was removed", len(all))
	}
	for _, tier := range Tiers {
		sel, err := Select(all, tier, nil)
		if err != nil || len(sel) == 0 {
			t.Errorf("tier %s selects nothing (%v)", tier, err)
		}
	}
}

// docs/harness-design.md carries the registry as a table between two markers. It is generated
// (`go run ./cmd/harness list -doc -write`) and held here, so the doc cannot list a scenario that does
// not exist — S1, S3 and S5 were listed for months with no test behind them.
func TestTheDesignDocCarriesTheRegistry(t *testing.T) {
	all, err := Scan("..")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "harness-design.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	i, j := strings.Index(doc, DocBegin), strings.Index(doc, DocEnd)
	if i < 0 || j < i {
		t.Fatalf("docs/harness-design.md has no %q ... %q block", strings.TrimSpace(DocBegin), DocEnd)
	}
	if got, want := doc[i+len(DocBegin):j], DocTable(all); got != want {
		t.Errorf("docs/harness-design.md's scenario table is not the registry; regenerate it with "+
			"`cd harness && go run ./cmd/harness list -doc -write`.\n--- doc\n%s--- registry\n%s", got, want)
	}
}

// The Makefile's tiers run the registry, not a regular expression over test names.
func TestTheMakefileTiersRunTheRegistry(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	mk := string(b)
	for target, run := range map[string]string{
		"harness-live":    "go run ./cmd/harness run -tier fabric",
		"harness-pr":      "go run ./cmd/harness run -tier pr",
		"harness-nightly": "go run ./cmd/harness run -tier nightly",
		"screenshots":     "go run ./cmd/screenshots",
	} {
		recipe := regexp.MustCompile(`(?ms)^` + target + `:[^\n]*\n((?:\t[^\n]*\n)+)`).FindStringSubmatch(mk)
		if recipe == nil {
			t.Errorf("the Makefile has no %s target", target)
			continue
		}
		if !strings.Contains(recipe[1], run) {
			t.Errorf("%s does not run `%s`:\n%s", target, run, recipe[1])
		}
	}
	for _, line := range strings.Split(mk, "\n") {
		if strings.Contains(line, "cd harness") && strings.Contains(line, "go test") && strings.Contains(line, "-run") {
			t.Errorf("a Makefile recipe selects harness tests by name: %s", line)
		}
	}
}

// The spellings Scan accepts are the constants in spec.go, and nothing else.
func TestScanKnowsEveryTierAndNeed(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "spec.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string][]string{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); ok {
				for _, n := range vs.Names {
					consts[id.Name] = append(consts[id.Name], n.Name)
				}
			}
		}
	}
	keys := func(m map[string]Tier) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	nkeys := func(m map[string]Need) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	slices.Sort(consts["Tier"])
	slices.Sort(consts["Need"])
	if !slices.Equal(consts["Tier"], keys(tierNames)) || len(Tiers) != len(tierNames) {
		t.Errorf("tiers in spec.go %v, in Scan %v, in Tiers %v", consts["Tier"], keys(tierNames), Tiers)
	}
	if !slices.Equal(consts["Need"], nkeys(needNames)) || len(Needs) != len(needNames) {
		t.Errorf("needs in spec.go %v, in Scan %v, in Needs %v", consts["Need"], nkeys(needNames), Needs)
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const goodTest = `package demo
func TestGood(t *testing.T) {
	ctx := registry.Start(t, registry.Spec{
		ID: "S1", Name: "good", Tier: registry.PR,
		Needs:   []registry.Need{registry.Docker, registry.Chrome},
		Timeout: 3 * time.Minute,
	})
	_ = ctx
}
`

func TestScanReadsASpec(t *testing.T) {
	all, err := Scan(writeTree(t, map[string]string{"demo/good_live_test.go": goodTest}))
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{Spec: Spec{ID: "S1", Name: "good", Tier: PR, Needs: []Need{Docker, Chrome}, Timeout: 3 * time.Minute},
		Package: "demo", Test: "TestGood", File: "demo/good_live_test.go"}
	if len(all) != 1 || all[0].ID != want.ID || all[0].Tier != want.Tier || !slices.Equal(all[0].Needs, want.Needs) ||
		all[0].Timeout != want.Timeout || all[0].Package != want.Package || all[0].Test != want.Test {
		t.Fatalf("got %+v, want %+v", all, want)
	}
}

// Every way a spec can be wrong is an error that names the file, never a scenario left out.
func TestScanRefusesWhatItCannotTrust(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"a duplicate id": {map[string]string{
			"a/a_live_test.go": goodTest,
			"b/b_live_test.go": strings.Replace(goodTest, "TestGood", "TestOther", 1),
		}, "id S1 is already a.TestGood"},
		"a live test with no spec": {map[string]string{
			"a/a_live_test.go": "package a\nfunc TestBare(t *testing.T) {}\n",
		}, "TestBare is a live test with no registry.Spec"},
		"a spec outside a Test": {map[string]string{
			"a/a_live_test.go": goodTest + "var s = registry.Spec{ID: \"S9\"}\n",
		}, "a registry.Spec outside a Test function"},
		"two specs in one Test": {map[string]string{
			"a/a_live_test.go": strings.Replace(goodTest, "_ = ctx", "_ = registry.Spec{ID: \"S3\"}", 1),
		}, "holds 2 specs"},
		"an unknown tier": {map[string]string{
			"a/a_live_test.go": strings.Replace(goodTest, "registry.PR", "registry.Weekly", 1),
		}, "registry.Weekly is not a tier"},
		"an unknown need": {map[string]string{
			"a/a_live_test.go": strings.Replace(goodTest, "registry.Chrome", "registry.GPU", 1),
		}, "registry.GPU is not a need"},
		"a computed timeout": {map[string]string{
			"a/a_live_test.go": strings.Replace(goodTest, "3 * time.Minute", "budget", 1),
		}, "must be N * time.Minute"},
		"a computed name": {map[string]string{
			"a/a_live_test.go": strings.Replace(goodTest, `"good"`, `name`, 1),
		}, "must be a string literal"},
		"a malformed id": {map[string]string{
			"a/a_live_test.go": strings.Replace(goodTest, `"S1"`, `"s-1"`, 1),
		}, "is not a letter and a number"},
		"no needs": {map[string]string{
			"a/a_live_test.go": strings.Replace(goodTest, "registry.Docker, registry.Chrome", "", 1),
		}, "needs nothing"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Scan(writeTree(t, tc.files))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestTiersNest(t *testing.T) {
	if !Nightly.Includes(PR) || !Nightly.Includes(Fabric) || !PR.Includes(Fabric) {
		t.Error("a larger tier does not include a smaller one")
	}
	if PR.Includes(Nightly) || Fabric.Includes(PR) || Tier("weekly").Includes(Fabric) || PR.Includes(Tier("weekly")) {
		t.Error("a tier includes one larger than itself, or an unknown one")
	}
}

// Nightly promises the kernel and the Cloudflare scenario only when the environment names them,
// so it is honest about what it did not run instead of silently skipping it.
func TestNightlyPromisesKernelAndCloudflareOnlyWhenNamed(t *testing.T) {
	none := func(string) string { return "" }
	all := func(k string) string {
		if k == KernelEnv || k == CFEnv {
			return "set"
		}
		return ""
	}
	if got := Provides(Nightly, none); slices.Contains(got, Kernel) || slices.Contains(got, CF) {
		t.Errorf("nightly with no kernel and no domain provides %v", got)
	}
	if got := Provides(Nightly, all); !slices.Contains(got, Kernel) || !slices.Contains(got, CF) {
		t.Errorf("nightly with both named provides %v", got)
	}
	if got := Provides(PR, all); slices.Contains(got, Kernel) || slices.Contains(got, CaldavImage) {
		t.Errorf("pr provides %v; it builds neither the caldav image nor a kernel", got)
	}
	if got := Provides(Fabric, all); slices.Contains(got, Chrome) {
		t.Errorf("fabric provides %v; it never launches a browser", got)
	}
}

func TestGoTestNamesExactlyTheSelectionAndSumsItsBudget(t *testing.T) {
	sel := []Entry{
		{Spec: Spec{ID: "S1", Timeout: 10 * time.Minute}, Package: "scenario", Test: "TestA"},
		{Spec: Spec{ID: "S2", Timeout: 20 * time.Minute}, Package: "scenario", Test: "TestB"},
		{Spec: Spec{ID: "F1", Timeout: 25 * time.Minute}, Package: "fabric", Test: "TestC"},
	}
	g := GoTestFor(sel)
	if !slices.Equal(g.Packages, []string{"./fabric", "./scenario"}) {
		t.Errorf("packages %v", g.Packages)
	}
	if g.Run != "^(TestA|TestB|TestC)$" {
		t.Errorf("run %q is not anchored to exactly the selection", g.Run)
	}
	// Tests in one package run in sequence under one -timeout: 10+20 is the binding budget.
	if want := 30*time.Minute + TimeoutSlack; g.Timeout != want {
		t.Errorf("timeout %v, want %v", g.Timeout, want)
	}
	if !slices.Contains(g.Args(), "-v") || !slices.Contains(g.Args(), "-count=1") {
		t.Errorf("args %v: a skip must be visible (-v) and a result never cached (-count=1)", g.Args())
	}
}

// The heart of it: a tier fails when a scenario it promised did not pass, including when it
// skipped or left no result at all; a scenario it did not promise may skip, and says what it
// needed. The control is the passing case, so a judge that failed everything would not pass this.
func TestJudgeFailsAPromisedSkipAndNamesAnUnpromisedOne(t *testing.T) {
	sel := []Entry{
		{Spec: Spec{ID: "S1", Name: "passes", Needs: []Need{Docker}}},
		{Spec: Spec{ID: "S2", Name: "skips", Needs: []Need{Docker}}},
		{Spec: Spec{ID: "S3", Name: "never ran", Needs: []Need{Docker}}, Package: "scenario", Test: "TestS3"},
		{Spec: Spec{ID: "S4", Name: "fails", Needs: []Need{Docker}}},
		{Spec: Spec{ID: "S8", Name: "needs a kernel", Needs: []Need{Docker, Kernel}}},
		{Spec: Spec{ID: "T7", Name: "needs cf, failed anyway", Needs: []Need{CF}}},
	}
	res := map[string]Result{
		"S1": {ID: "S1", Verdict: Pass},
		"S2": {ID: "S2", Verdict: Skipped, Reason: "needs chrome"},
		"S4": {ID: "S4", Verdict: Fail},
		"S8": {ID: "S8", Verdict: Skipped, Reason: "HDTP_HARNESS_KERNEL is not set"},
		"T7": {ID: "T7", Verdict: Fail},
	}
	cases := Judge(sel, []Need{Docker}, res)
	ok := map[string]bool{}
	for _, c := range cases {
		ok[c.ID] = c.OK
	}
	want := map[string]bool{"S1": true, "S2": false, "S3": false, "S4": false, "S8": true, "T7": false}
	for id, w := range want {
		if ok[id] != w {
			t.Errorf("%s: ok=%v, want %v (%+v)", id, ok[id], w, cases)
		}
	}
	for _, c := range cases {
		if c.ID == "S3" && (c.Verdict != Fail || !strings.Contains(c.Reason, "scenario.TestS3")) {
			t.Errorf("a promised scenario with no result must FAIL and name its test: %+v", c)
		}
		if c.ID == "S8" && (!strings.Contains(c.Reason, "not promised") || !strings.Contains(c.Reason, "make harness-kernel")) {
			t.Errorf("an unpromised skip must say what would provide it: %+v", c)
		}
	}
	if Passed(cases) {
		t.Error("the tier passed")
	}
	if !Passed(cases[:1]) {
		t.Error("a tier whose only scenario passed did not pass")
	}
}

// Start, in a child process: the verdict is written last, so a failure raised by a teardown
// registered after Start is recorded as FAIL; a missing need is SKIPPED with its reason; and a
// clean run is PASS.
func TestStartRecordsTheVerdictAfterEveryTeardown(t *testing.T) {
	if os.Getenv("HDTP_REGISTRY_CHILD") != "" {
		t.Skip("the child runs its own tests")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild", "-test.count=1")
	cmd.Env = append(os.Environ(), "HDTP_REGISTRY_CHILD=1", LiveEnv+"=1", ResultsEnv+"="+dir, CFEnv+"=harness.example")
	out, _ := cmd.CombinedOutput() // the child fails on purpose
	res, err := ReadResults(dir)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]Verdict{"S91": Pass, "S92": Fail, "S93": Skipped} {
		if res[id].Verdict != want {
			t.Errorf("%s recorded %q, want %s\n%s", id, res[id].Verdict, want, out)
		}
	}
	if !strings.Contains(res["S93"].Reason, "needs cf") || !strings.Contains(res["S93"].Reason, CFEnv) {
		t.Errorf("a skip for a missing need does not say which: %+v", res["S93"])
	}
	b, _ := json.Marshal(res["S91"])
	if !strings.Contains(string(b), `"test":"TestChildPasses"`) {
		t.Errorf("a result does not name its test: %s", b)
	}
}

func childOnly(t *testing.T) {
	if os.Getenv("HDTP_REGISTRY_CHILD") == "" {
		t.Skip("run by TestStartRecordsTheVerdictAfterEveryTeardown")
	}
}

func TestChildPasses(t *testing.T) {
	childOnly(t)
	Start(t, Spec{ID: "S91", Name: "passes", Tier: PR, Needs: []Need{CF}, Timeout: time.Minute})
}

func TestChildFailsInTeardown(t *testing.T) {
	childOnly(t)
	Start(t, Spec{ID: "S92", Name: "fails in teardown", Tier: PR, Needs: []Need{CF}, Timeout: time.Minute})
	t.Cleanup(func() { t.Error("teardown found something wrong") })
}

func TestChildSkipsForAMissingNeed(t *testing.T) {
	childOnly(t)
	t.Setenv(CFEnv, "")
	Start(t, Spec{ID: "S93", Name: "needs cf", Tier: PR, Needs: []Need{CF}, Timeout: time.Minute})
	t.Error("Start returned for a scenario whose need is missing")
}

// A result and a tier's summary are the workspace's one result schema (docs/testing.md, "Results"):
// the envelope, and a case whose why is the first line of `evidence`.
func TestResultsAreInTheOneSchema(t *testing.T) {
	r := Result{ID: "S2", Name: "pairing", Test: "TestPairing", Verdict: Skipped, Reason: "needs chrome", MS: 12}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "name", "verdict", "evidence", "ms"} {
		if _, ok := wire[k]; !ok {
			t.Errorf("a result has no %q: %s", k, b)
		}
	}
	if _, ok := wire["reason"]; ok {
		t.Errorf("a result carries reason outside evidence: %s", b)
	}
	var back Result
	if err := json.Unmarshal(b, &back); err != nil || back != r {
		t.Errorf("a result does not read back as written: %+v (%v)", back, err)
	}
	passed, _ := json.Marshal(Result{ID: "S9", Verdict: Pass})
	if !strings.Contains(string(passed), `"evidence":[]`) {
		t.Errorf("a PASS has an empty evidence list, not none: %s", passed)
	}
	sum, _ := json.Marshal(NewSummary("pr", "2026-09-27T00:00:00Z", "2026-09-27T00:01:00Z", "abc1234", []Case{{ID: "S2", Verdict: Pass, OK: true}, {ID: "S9", Verdict: Fail, Reason: "no"}}))
	var env map[string]any
	if err := json.Unmarshal(sum, &env); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "repo", "suite", "tier", "run", "cases", "counts"} {
		if _, ok := env[k]; !ok {
			t.Errorf("the summary has no %q: %s", k, sum)
		}
	}
	if env["schema"] != "hdtp-results/1" || !strings.Contains(string(sum), `"counts":{"FAIL":1,"PASS":1}`) {
		t.Errorf("the summary's schema or counts: %s", sum)
	}
}
