package cli

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
)

// `serve` joins what it starts.
//
// It used not to. The retention sweep, the outbound retry loop and the integration dialler were
// each started with a bare `go` and never waited for, so `serve` could return — and its deferred
// `st.Close()` run — while one of them was mid-pass. What that pass did next was use a closed store,
// read a cancelled context as a failure, try to AUDIT that failure ("leaf_retirement_pass … error",
// "integration_connect … retrying": a node that was stopping, recorded as a node that was broken),
// and write the refusal to a stderr its caller had stopped reading. On 2026-09-21 CI's race detector
// caught the last of those: the sweeper writing into a test's output buffer after the test that owned
// it had finished.
//
// A goroutine that outlives `serve` cannot be seen by a test of `serve` except by luck, which is how
// it lasted. So the rule is structural and this holds it: in this package a `go` statement is an
// error. Background work goes through `serveWith`'s WaitGroup (`background.Go`), which is joined
// before it returns; the functions it runs are ordinary blocking functions.
func TestNoGoroutineInThisPackageIsStartedAndAbandoned(t *testing.T) {
	// file → function → why this one is not abandoned.
	allowed := map[string]map[string]string{
		"ingresscmd.go": {
			// READ on 2026-09-21, not assumed. The control plane's server is Shutdown, which waits for
			// its handlers. The terminator's and the front door's Close stop ACCEPTING and do not wait
			// for connections in flight, so such a connection can outlive the command by a moment. What
			// made that a defect in `serve` is absent here: there is no store closed under them (a file
			// registry, written at pairing) and their audit sink is a line on stdout, not the audit
			// chain, so nothing false is recorded. Draining connections is a feature the ingress lacks.
			"ingressServe": "three accept loops; the control plane is Shutdown (waits), the other two are " +
				"closed without draining — harmless here: no store under them, and audit is a stdout line",
		},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := gotoken.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				g, ok := n.(*ast.GoStmt)
				if !ok {
					return true
				}
				if _, ok := allowed[name][fn.Name.Name]; !ok {
					t.Errorf("%s: a bare `go` statement in %s. Nothing waits for it, so it can outlive "+
						"the command that started it. Make the work a blocking function and run it with "+
						"serveWith's background.Go — or add it to this test's list with the reason it is "+
						"not abandoned.", fset.Position(g.Pos()), fn.Name.Name)
				}
				return true
			})
		}
	}
	// A guard that reads no files passes everything.
	if seen < 10 {
		t.Fatalf("read %d source files of this package; the guard is not looking at it", seen)
	}
}

// The sweeper is a blocking function: it does not return while a pass is running, which is what
// lets `serve` wait for it. And a pass cut short by the node stopping has not failed, so it says
// nothing — before this, every interrupted pass printed a store error for a store that was fine.
func TestTheSweeperReturnsOnlyWhenItsPassHasAndAStoppingNodeIsNotAFailure(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	var stderr lockedTestBuf
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		runRetentionSweeper(ctx, nil, st, &core.Config{DataDir: dir}, func(string, string, string) {}, &stderr,
			func(context.Context) { close(entered); <-release })
	}()

	<-entered // the startup pass is running, inside the leaf-retirement step
	cancel()  // …and the node is told to stop
	select {
	case <-returned:
		t.Fatal("the sweeper returned while its pass was still running: serve would close the store under it")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweeper did not return after its pass finished and its context had ended")
	}
	// The rest of that pass ran against a cancelled context. Every store call in it failed, and none
	// of those failures is news.
	if got := stderr.String(); got != "" {
		t.Fatalf("a pass interrupted by shutdown reported errors:\n%s", got)
	}
}

// The integration dialler, stopped mid-dial, used to record "integration_connect … retrying" and
// print "(will retry)" — for a node that was stopping and would do neither.
func TestAnIntegrationDialCutShortByShutdownIsNotRecordedAsRetrying(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()
	ctx := context.Background()
	acct, err := (&identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}).CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "calendar", Transport: "streamable-http",
		Endpoint: "http://127.0.0.1:1/mcp", AuthKind: "none", Status: "ok",
	}); err != nil {
		t.Fatal(err)
	}

	// The node is told to stop exactly as the dial begins. (A context that has ALREADY ended never
	// reaches the dial — the loop checks before each one — so that case was never the defect, and a
	// first draft of this test that cancelled up front passed against the code as it was.)
	stopping, cancel := context.WithCancel(ctx)
	defer cancel()
	var rows []string
	var stderr bytes.Buffer
	connectStoredIntegrations(stopping, &integrations.Manager{Store: stopsAsTheDialBegins{st, cancel}}, st,
		func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" "+outcome) }, &stderr)

	if stopping.Err() == nil {
		t.Fatal("the dial was never reached, so this test has shown nothing")
	}
	if len(rows) != 0 || stderr.Len() != 0 {
		t.Fatalf("a dial cut short by shutdown was reported as a failure to retry:\naudit: %v\nstderr: %s", rows, stderr.String())
	}
}

// stopsAsTheDialBegins ends the serving context at the first thing Connect does.
type stopsAsTheDialBegins struct {
	store.Store
	stop context.CancelFunc
}

func (s stopsAsTheDialBegins) GetIntegrationByID(ctx context.Context, id string) (store.Integration, error) {
	s.stop()
	return s.Store.GetIntegrationByID(ctx, id)
}

type lockedTestBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedTestBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedTestBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
