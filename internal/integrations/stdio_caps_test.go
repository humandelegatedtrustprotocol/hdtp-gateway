package integrations

import (
	"flag"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestChildShimHelper is not a test: the test binary re-executes itself with
// `-test.run=^TestChildShimHelper$ -- <shim args>` to act as the `__child`
// shim (the real binary's hidden subcommand). Marker is positional, never an
// env var — the child environment is exactly the allow-list.
func TestChildShimHelper(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 {
		t.Skip("helper mode only")
	}
	if err := RunChildShim(args); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(3)
	}
	os.Exit(0)
}

func testShim() []string {
	return []string{os.Args[0], "-test.run=^TestChildShimHelper$", "--"}
}

func needPython(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	return p
}

// AC: caps are configurable and actually applied — the child reports its own
// rlimits back through an env-free python one-liner.
func TestChildRlimitsAreApplied(t *testing.T) {
	if !ShimSupported {
		t.Skip("no setrlimit on this platform")
	}
	py := needPython(t)
	sup := &Supervisor{Config: StdioConfig{
		Command: py + ` -c "import resource;print(resource.getrlimit(resource.RLIMIT_DATA)[0],resource.getrlimit(resource.RLIMIT_CPU)[0])"`,
		Env:     map[string]string{"PATH": os.Getenv("PATH")},
		Shim:    testShim(), MaxMemoryBytes: 256 << 20, MaxCPUSeconds: 7,
	}}
	cmd, err := sup.BuildCmd()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(cmd.Args, " "), "--mem 268435456 --cpu 7 --") {
		t.Fatalf("shim args: %v", cmd.Args)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v (%s)", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[1] != "7" {
		t.Fatalf("child rlimits = %q, want CPU cap 7", out)
	}
	// RLIMIT_DATA, not RLIMIT_AS. The spec's cap is 512 MiB of RSS; capping the
	// ADDRESS SPACE instead killed every runtime that reserves more than it uses.
	// Measured: a Node child aborts at 1, 2, 4 and 8 GiB of AS and starts only
	// above that, so no AS value both admits an npx child and bounds anything —
	// and npx children are what SPEC §12.3's -full image exists to run. The cap
	// is a Linux guarantee; macOS does not enforce these reliably.
	if runtime.GOOS == "linux" && fields[0] != strconv.Itoa(256<<20) {
		t.Fatalf("RLIMIT_DATA = %s, want 268435456", fields[0])
	}
}

func TestDefaultCapAndExplicitUncap(t *testing.T) {
	sup := &Supervisor{Config: StdioConfig{Command: "/usr/bin/env", Shim: testShim()}}
	cmd, _ := sup.BuildCmd()
	if ShimSupported && !strings.Contains(strings.Join(cmd.Args, " "), "--mem "+strconv.FormatInt(DefaultMaxMemoryBytes, 10)) {
		t.Fatalf("default 512 MiB cap missing: %v", cmd.Args)
	}
	// explicit owner opt-out: negative = uncapped, warned
	var warned string
	old := Warn
	Warn = func(m string) { warned = m }
	defer func() { Warn = old }()
	sup2 := &Supervisor{Config: StdioConfig{Command: "/usr/bin/env", MaxMemoryBytes: -1, Shim: testShim()}}
	cmd2, _ := sup2.BuildCmd()
	if cmd2.Args[0] != "/usr/bin/env" || !strings.Contains(warned, "WITHOUT resource caps") {
		t.Fatalf("uncapped path: args=%v warned=%q", cmd2.Args, warned)
	}
}

// AC (Linux): a child exceeding the memory cap is killed — the allocation
// fails under RLIMIT_AS and the process exits non-zero, which the supervisor's
// existing crash path audits (integration_child_crash).
func TestChildExceedingMemoryCapIsKilled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("RLIMIT_AS is only reliably enforced on Linux")
	}
	py := needPython(t)
	sup := &Supervisor{Config: StdioConfig{
		Command: py + ` -c "b=bytearray(400*1024*1024);print(len(b))"`,
		Env:     map[string]string{"PATH": os.Getenv("PATH")},
		Shim:    testShim(), MaxMemoryBytes: 128 << 20,
	}}
	cmd, err := sup.BuildCmd()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("child allocated past the cap: %s", out)
	}
	// and the same command runs fine uncapped
	sup.Config.MaxMemoryBytes = -1
	cmd2, _ := sup.BuildCmd()
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("uncapped run failed: %v %s", err, out)
	}
}
