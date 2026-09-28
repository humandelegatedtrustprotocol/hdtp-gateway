package node

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
)

// running starts n's bus reader and its follower, as serve does, until the test ends.
func running(t *testing.T, n *Node) *Node {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { n.opts.Bus.Run(ctx) })
	wg.Go(func() { n.Follow(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return n
}

// secondProcess is another node process on e's data dir: its own store handle on the same file,
// the same keyring, its own bus and follower.
func (e *env) secondProcess(t *testing.T) (*Node, store.Store) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(e.cfg.DataDir, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	n, err := New(context.Background(), Options{Config: e.cfg, Store: st, Keyring: e.kr, Landing: testLanding})
	if err != nil {
		t.Fatal(err)
	}
	return running(t, n), st
}

// toolsFor is one stateless request's tools/list for a caller, on one process.
func toolsFor(t *testing.T, n *Node, accountID, fpr string) []string {
	t.Helper()
	ctx := context.Background()
	srv, err := n.Pool(accountID).ServerFor(ctx, accountID, fpr)
	if err != nil {
		t.Fatal(err)
	}
	ct, stt := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, stt, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cs.Close(); ss.Wait() }()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	sort.Strings(names)
	return names
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s did not happen within 30 s", what)
}

// A change one node process makes to what it serves reaches another process on the same store
// (SPEC §11.1): a caller's surface composed on B before A approved them is dropped on B; an account
// A adopts is served by B; a seal A changes is B's; an account A forgets, B forgets.
func TestAChangeOneProcessMakesToWhatItServesReachesAnother(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "alice")
	alice := accts[0]
	a := running(t, mustNew(t, e.options()))
	b, _ := e.secondProcess(t)

	// B composes the stranger's surface: the guest one.
	const fpr = "sha256:stranger"
	if got := toolsFor(t, b, alice.ID, fpr); contains(got, "send_message") {
		t.Fatalf("a stranger was served %v", got)
	}
	// A makes them a contact, and drops their surface, as an approval does.
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: alice.ID, Fingerprint: fpr, SPKI: []byte{1},
		Status: "active", Permissions: []string{"message.text"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Invalidate(ctx, alice.ID, fpr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "B serving the approved contact their contact tools", func() bool {
		return contains(toolsFor(t, b, alice.ID, fpr), "send_message")
	})

	// A adopts a new account.
	bob, err := e.idm.CreateAccount(ctx, "bob", "BOB", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	e.issueLeaf(bob)
	if err := a.AdoptAccount(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "B serving the account A adopted", func() bool { return contains(b.Slugs(), "bob") })

	// A changes alice's seal.
	if err := a.SetSeal(ctx, alice.ID, core.SealRequired); err != nil {
		t.Fatal(err)
	}
	eventually(t, "B serving alice under the seal A set", func() bool {
		b.mu.RLock()
		defer b.mu.RUnlock()
		acct := b.accounts[alice.ID]
		return acct != nil && acct.sealValue() == core.SealRequired
	})

	// A forgets bob (the identity left).
	if _, err := e.st.DeleteAccount(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	a.ForgetAccount(bob.ID, "bob")
	eventually(t, "B forgetting the account A forgot", func() bool { return !contains(b.Slugs(), "bob") })
}

func mustNew(t *testing.T, o Options) *Node {
	t.Helper()
	n, err := New(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// The seal an account is built with is the owner's as it is NOW (Options.SealPolicy): an account
// adopted after the owner changed the seal serves the new one and its row says so, and so does an
// account re-leafed (adopted again) after it. It was the node's boot value, so an adoption after a
// portal change served, and wrote back, the seal the owner had replaced.
func TestAnAccountAdoptedAfterASealChangeServesTheNewSeal(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "alice")
	policy := core.SealOptional
	o := e.options()
	o.SealPolicy = func() core.Seal { return policy }
	n := mustNew(t, o)

	// The owner requires sealing: the settings service writes its config and re-seals each
	// account, as settings.apply does.
	policy = core.SealRequired
	if err := n.SetSeal(ctx, accts[0].ID, policy); err != nil {
		t.Fatal(err)
	}
	served := func(accountID string) core.Seal {
		n.mu.RLock()
		defer n.mu.RUnlock()
		return n.accounts[accountID].sealValue()
	}
	// Re-leafed: adopted again.
	if err := n.AdoptAccount(ctx, accts[0].ID); err != nil {
		t.Fatal(err)
	}
	// A new account.
	bob, err := e.idm.CreateAccount(ctx, "bob", "BOB", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	e.issueLeaf(bob)
	if err := n.AdoptAccount(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{accts[0].ID, bob.ID} {
		row, err := e.st.GetAccountByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got := served(id); got != core.SealRequired || row.Seal != string(core.SealRequired) {
			t.Fatalf("an account adopted after the seal became required serves %s and its row says %s", got, row.Seal)
		}
	}
}
