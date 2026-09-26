package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/images"
	"github.com/tech-sumit/pact-gateway/harness/portal"
	"github.com/tech-sumit/pact-gateway/harness/preflight"
)

// Verdict is how one scenario ended.
type Verdict string

const (
	Pass    Verdict = "PASS"
	Fail    Verdict = "FAIL"
	Skipped Verdict = "SKIPPED"
)

// Result is what Start writes for one scenario, as <ResultsDir>/<id>.json: a case in the one
// result schema of the workspace (docs/testing.md, "Results"), where why is the first line of
// `evidence`, plus the test that ran it.
type Result struct {
	ID      string
	Name    string
	Test    string
	Verdict Verdict
	// Reason is why the scenario did not simply PASS; on the wire it is `evidence[0]`.
	Reason string
	MS     int64
}

type resultJSON struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Test     string   `json:"test"`
	Verdict  Verdict  `json:"verdict"`
	Evidence []string `json:"evidence"`
	MS       int64    `json:"ms"`
}

// MarshalJSON writes the schema's case: `evidence` carries the reason.
func (r Result) MarshalJSON() ([]byte, error) {
	return json.Marshal(resultJSON{ID: r.ID, Name: r.Name, Test: r.Test, Verdict: r.Verdict, Evidence: evidenceOf(r.Reason), MS: r.MS})
}

// UnmarshalJSON reads a result a scenario wrote back, for a tier's judgement.
func (r *Result) UnmarshalJSON(b []byte) error {
	var j resultJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*r = Result{ID: j.ID, Name: j.Name, Test: j.Test, Verdict: j.Verdict, MS: j.MS}
	if len(j.Evidence) > 0 {
		r.Reason = j.Evidence[0]
	}
	return nil
}

func evidenceOf(reason string) []string {
	if reason == "" {
		return []string{}
	}
	return []string{reason}
}

// ResultsDir is where results are written: ResultsEnv, or a fixed directory under the system
// temporary directory. `harness run` always names a fresh one, so a tier never reads a result an
// earlier run left.
func ResultsDir(getenv func(string) string) string {
	if d := getenv(ResultsEnv); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), "pact-harness-results")
}

// Start begins a live scenario and returns its context, bounded by the spec's Timeout.
//
// Without PACT_HARNESS_LIVE it skips and records nothing: that is the hermetic tier. Otherwise it
// validates the spec, checks every need (a missing one SKIPS, with the reason recorded), and
// registers the verdict as the test's FIRST cleanup, so it runs LAST and sees a failure raised by
// any teardown registered after it.
func Start(t *testing.T, s Spec) context.Context {
	t.Helper()
	if os.Getenv(LiveEnv) == "" {
		t.Skipf("set %s=1 to run live scenarios", LiveEnv)
	}
	began := time.Now()
	reason := ""
	t.Cleanup(func() { record(t, s, began, reason) })
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, n := range s.Needs {
		if err := check(n); err != nil {
			reason = fmt.Sprintf("needs %s (%s): %v", n, HowToProvide(n), err)
			t.Skip(reason)
		}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), specKey{}, s), s.Timeout)
	t.Cleanup(cancel)
	return ctx
}

type specKey struct{}

// SpecOf is the spec a scenario's context was started with, so what it builds can be named by
// its id (fabric.PrefixFor) without a second copy of the id.
func SpecOf(ctx context.Context) Spec {
	s, _ := ctx.Value(specKey{}).(Spec)
	return s
}

func record(t *testing.T, s Spec, began time.Time, reason string) {
	r := Result{ID: s.ID, Name: s.Name, Test: t.Name(), MS: time.Since(began).Milliseconds()}
	switch {
	case t.Failed():
		r.Verdict = Fail
		r.Reason = "the test failed; its log says why"
	case t.Skipped():
		r.Verdict, r.Reason = Skipped, reason
		if r.Reason == "" {
			r.Reason = "the scenario skipped itself"
		}
	default:
		r.Verdict = Pass
	}
	if err := WriteResult(ResultsDir(os.Getenv), r); err != nil {
		t.Errorf("recording %s: %v", s.ID, err)
	}
}

// WriteResult writes one result into dir.
func WriteResult(dir string, r Result) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, r.ID+".json"), append(b, '\n'), 0o644)
}

// ReadResults reads every <id>.json in dir, by id.
func ReadResults(dir string) (map[string]Result, error) {
	out := map[string]Result{}
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || e.Name() == SummaryFile {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var r Result
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out[r.ID] = r
	}
	return out, nil
}

// The need probes run once per test binary: a package of ten scenarios asks Docker once. The key
// carries the environment variable a need reads, so changing it asks again.
var (
	probeMu sync.Mutex
	probed  = map[string]error{}
)

func check(n Need) error {
	key := string(n)
	switch n {
	case Kernel:
		key += "|" + os.Getenv(KernelEnv)
	case CF:
		key += "|" + os.Getenv(CFEnv)
	}
	probeMu.Lock()
	defer probeMu.Unlock()
	if err, ok := probed[key]; ok {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := probe(ctx, n)
	probed[key] = err
	return err
}

func local(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func probe(ctx context.Context, n Need) error {
	switch n {
	case Docker:
		return fabricReady(ctx, preflight.FabricContainer)
	case NodeImage:
		return imagePresent(ctx, images.Node)
	case CaldavImage:
		return imagePresent(ctx, images.Caldav)
	case Chrome:
		br, err := portal.Open(ctx)
		if err != nil {
			return err
		}
		br.Close()
		return nil
	case Kernel:
		k := os.Getenv(KernelEnv)
		if k == "" {
			return fmt.Errorf("%s is not set", KernelEnv)
		}
		if _, err := os.Stat(k); err != nil {
			return err
		}
		return fabricReady(ctx, preflight.FabricVM)
	case CF:
		if os.Getenv(CFEnv) == "" {
			return fmt.Errorf("%s is not set", CFEnv)
		}
		return nil
	}
	return fmt.Errorf("no probe for %q", n)
}

// fabricReady asks preflight, the one place that knows how to tell whether Docker or an
// accelerated QEMU is usable.
func fabricReady(ctx context.Context, f preflight.Fabric) error {
	rep := preflight.Probe(ctx, local)
	if rep.Ready(f) {
		return nil
	}
	var why []string
	for _, c := range rep.Checks {
		if c.Fabric == f && !c.OK {
			why = append(why, c.Name+": "+c.Detail)
		}
	}
	return fmt.Errorf("%s", strings.Join(why, "; "))
}

func imagePresent(ctx context.Context, ref string) error {
	if out, err := local(ctx, "docker", "image", "inspect", ref); err != nil {
		return fmt.Errorf("%s is not built: %s", ref, strings.TrimSpace(firstLine(string(out))))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
