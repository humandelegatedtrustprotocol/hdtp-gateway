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

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/images"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/portal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/preflight"
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
	return filepath.Join(os.TempDir(), "hdtp-harness-results")
}

// Start begins a live scenario and returns its context, bounded by the spec's Timeout.
//
// Without HDTP_HARNESS_LIVE it skips and records nothing: that is the hermetic tier. Otherwise it
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
	case HDTPCLI:
		key += "|" + os.Getenv(HDTPCLIEnv)
	case CloudBattery:
		key += "|" + os.Getenv(CloudBatteryEnv)
	case LocalCloud:
		key += "|" + os.Getenv(LocalCloudEnv)
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
	case HDTPCLI:
		cli := os.Getenv(HDTPCLIEnv)
		if cli == "" {
			return fmt.Errorf("%s is not set", HDTPCLIEnv)
		}
		if out, err := local(ctx, cli, "--version"); err != nil {
			return fmt.Errorf("%s --version: %v %s", cli, err, firstLine(string(out)))
		}
		return nil
	case LocalCloud:
		dir := os.Getenv(LocalCloudEnv)
		if dir == "" {
			return fmt.Errorf("%s is not set", LocalCloudEnv)
		}
		if _, err := os.Stat(filepath.Join(dir, "e2e/local-run.mjs")); err != nil {
			return fmt.Errorf("%s has no e2e/local-run.mjs: %v", dir, err)
		}
		if err := localCloudBuilt(ctx, dir); err != nil {
			return err
		}
		for _, v := range []string{"WORKOS_TEST_CLIENT_ID", "WORKOS_TEST_API_KEY"} {
			if os.Getenv(v) == "" {
				return fmt.Errorf("%s is not set: the local cloud's session injection verifies a WorkOS token", v)
			}
		}
		if out, err := local(ctx, "node", "--version"); err != nil {
			return fmt.Errorf("node --version: %v %s", err, firstLine(string(out)))
		}
		return nil
	case CloudBattery:
		dir := os.Getenv(CloudBatteryEnv)
		if dir == "" {
			return fmt.Errorf("%s is not set", CloudBatteryEnv)
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
			return fmt.Errorf("%s names no Go module: %v", CloudBatteryEnv, err)
		}
		// A checkout from before the battery took a target can only be aimed at the cloud: aimed
		// at a node it fails a dozen cases for reasons that are its own. Such a checkout does not
		// provide the need, and says why.
		if src, err := os.ReadFile(filepath.Join(dir, "target_test.go")); err != nil || !strings.Contains(string(src), "HDTP_LIVE_TARGET") {
			return fmt.Errorf("%s is a battery that cannot be aimed at a node (no HDTP_LIVE_TARGET in its target_test.go): update that batondeck checkout", dir)
		}
		return nil
	}
	return fmt.Errorf("no probe for %q", n)
}

// localCloudScript asks the cloud's own runner what it links into its run's worktree from the
// checkout (`treeLinks` in e2e/local-run.mjs: the installed packages and every build the local
// cloud refuses to start without) and prints one per line. The list is the cloud's, read from it,
// so a build the cloud comes to need is a need here the same day. The runner starts a run when
// process.argv[1] is itself, which `node -e <script> <path>` would make it, so the path is handed
// over in the environment and argv[1] stays empty: importing it then starts nothing.
const localCloudScript = `const { pathToFileURL } = await import('node:url')
const m = await import(pathToFileURL(process.env.HDTP_LOCAL_RUN).href)
if (typeof m.treeLinks !== 'function') { console.error('no treeLinks export'); process.exit(3) }
for (const p of m.treeLinks()) console.log(p)`

// localCloudBuilt holds the checkout behind dir (batondeck's gateway/) to what its runner links
// into the run's worktree: each must be there, or the local cloud stops before it starts and S20
// was promised a scenario that could not begin.
func localCloudBuilt(ctx context.Context, dir string) error {
	ask := exec.CommandContext(ctx, "node", "--input-type=module", "-e", localCloudScript)
	ask.Env = append(os.Environ(), "HDTP_LOCAL_RUN="+filepath.Join(dir, "e2e/local-run.mjs"))
	out, err := ask.Output()
	if err != nil {
		return fmt.Errorf("%s/e2e/local-run.mjs could not be asked what its run needs (a checkout from before treeLinks needs updating): %v %s", dir, err, firstLine(string(out)))
	}
	repo := filepath.Dir(filepath.Clean(dir))
	for _, p := range strings.Fields(string(out)) {
		if _, err := os.Stat(filepath.Join(repo, p)); err != nil {
			return fmt.Errorf("%s has no %s, which the local cloud needs: build it (cd %s && npm run portal:build)", repo, p, dir)
		}
	}
	return nil
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
