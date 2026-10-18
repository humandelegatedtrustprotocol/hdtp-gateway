package webhooks

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// now is the clock every test here starts from (unix milliseconds 1_800_000_000_000, the cloud
// test's NOW).
var now = time.UnixMilli(1_800_000_000_000)

// audited is what a service wrote to its audit log, one "action resource outcome" line each.
type audited struct {
	mu    sync.Mutex
	lines []string
}

func (a *audited) audit(action, resource, outcome string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lines = append(a.lines, action+" "+resource+" "+outcome)
}

func (a *audited) take() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.lines
	a.lines = nil
	return out
}

// fixture is a service over a real store (SQLite unless a test names another) and a real keyring,
// with two accounts.
type fixture struct {
	svc    *Service
	st     store.Store
	kr     *core.Keyring
	log    *audited
	clock  *time.Time
	mine   string
	theirs string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return newFixtureOn(t, st, newKeyring(t))
}

// newKeyring is a real keyring under a new master key.
func newKeyring(t *testing.T) *core.Keyring {
	t.Helper()
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// newFixtureOn is the fixture over a migrated store st and the keyring kr, with two accounts made
// in it.
func newFixtureOn(t *testing.T, st store.Store, kr *core.Keyring) *fixture {
	t.Helper()
	ctx := context.Background()
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alice", DisplayName: "Alice", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "bob", DisplayName: "Bob", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	log := &audited{}
	clock := now
	svc := New(st, kr, log.audit)
	svc.now = func() time.Time { return clock }
	return &fixture{svc: svc, st: st, kr: kr, log: log, clock: &clock, mine: a.ID, theirs: b.ID}
}

// create registers an endpoint for the fixture's own account, failing the test if it is refused.
func (f *fixture) create(t *testing.T, url string, events ...string) (EndpointView, string) {
	t.Helper()
	v, secret, err := f.svc.Create(context.Background(), f.mine, url, events)
	if err != nil {
		t.Fatalf("create %s: %v", url, err)
	}
	return v, secret
}

// find is one endpoint of the fixture's own account as List shows it.
func (f *fixture) find(t *testing.T, id string) EndpointView {
	t.Helper()
	l, err := f.svc.List(context.Background(), f.mine)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("endpoint %s is not listed", id)
	return EndpointView{}
}

func joined(lines []string) string { return strings.Join(lines, "\n") }
