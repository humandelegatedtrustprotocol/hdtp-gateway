package cli

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/node"
	"github.com/tech-sumit/pact-gateway/internal/services/settings"
	"github.com/tech-sumit/pact-gateway/internal/testid"
)

// An address is inside a leaf. Saving a new `public_url` changes what the NEXT certificate request
// will name and moves nobody, so it has nothing to tell a contact — and it used to tell all of
// them: `update_contact{card, sig}` to every contact of every account, the signature over the
// account's own fingerprint. That was 1.x's endpoint announcement. Under 2.0 the card it sent was
// the card the contact already held, and the thing that does move an address was not started.
//
// Two things are asserted, and the first is the one the old code fails: a contact that is really
// pinned, at an address that really listens, hears NOTHING. Then: the account certified for the
// old derived address is named as needing a move, and the account certified for an address of its
// own is left alone.
func TestSavingANewPublicURLCallsNobodyAndNamesWhoMustMove(t *testing.T) {
	const oldURL, newURL = "https://old.example", "https://new.example"
	n := newIDNode(t, "node")
	ctx := context.Background()
	st := openStoreAt(t, n.dir)
	kr := openKeyringAt(t, n.dir)
	idm := &identity.Manager{Store: st, Keyring: kr}
	alice, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := idm.CreateAccount(ctx, "bob", "Bob", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	now := time.Now()
	// alice answers at the address the node derives for her; bob at a hostname of his own.
	newTestWallet(t, "Alice").certifyUnder(t, n, "alice", identity.PurposeSignup, identity.EndpointFor(oldURL, "alice"), now)
	newTestWallet(t, "Bob").certifyUnder(t, n, "bob", identity.PurposeSignup, "https://bob.own.example/mcp", now)

	// A contact of alice's that is properly pinned, at an address that accepts connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var heard atomic.Int64
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			heard.Add(1)
			_ = c.Close()
		}
	}()
	st = openStoreAt(t, n.dir)
	peer := testid.NewWallet(t, "Peer")
	ph := peer.Issue(t, "https://"+ln.Addr().String()+"/mcp")
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: alice.ID, Fingerprint: peer.Fpr, SPKI: ph.Key.Public.SPKI,
		Status: "active", Endpoint: ph.Endpoint, Leaf: ph.LeafDER, Card: ph.Card("Peer", "optional"),
	}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var rows []string
	audit := func(action, resource, outcome string) {
		mu.Lock()
		defer mu.Unlock()
		rows = append(rows, action+" "+resource+" → "+outcome)
	}
	cfg := &core.Config{DataDir: n.dir, PublicURL: oldURL, Mode: core.ModeDirect, Seal: core.SealOptional, ClientCert: core.ClientCertPreferred, LANConnections: true}
	nd, err := node.New(ctx, node.Options{Config: *cfg, Store: st, Keyring: kr, Audit: audit, Landing: landingPage})
	if err != nil {
		t.Fatal(err)
	}
	svc := settings.New(st, kr, cfg, audit)
	svc.AttachNode(nd)

	if err := svc.Deps().Save(ctx, "public_url", newURL); err != nil {
		t.Fatal(err)
	}
	// The old announcement ran detached, so give it the time it would have needed to dial.
	time.Sleep(400 * time.Millisecond)
	if got := heard.Load(); got != 0 {
		t.Fatalf("saving a setting made %d connection(s) to a contact: nothing has moved, so there is nothing to tell anybody", got)
	}
	if nd.PublicURL() != newURL {
		t.Fatalf("the node advertises %q", nd.PublicURL())
	}

	mu.Lock()
	all := strings.Join(rows, "\n")
	mu.Unlock()
	want := "account_move_needed account:" + alice.ID + " slug:alice from:" + identity.EndpointFor(oldURL, "alice") + " to:" + identity.EndpointFor(newURL, "alice") + " → ok"
	if !strings.Contains(all, want) {
		t.Fatalf("alice is certified for an address this node no longer advertises, and nothing says so.\nwant: %s\ngot:\n%s", want, all)
	}
	if strings.Contains(all, "account:"+bob.ID+" slug:bob from:") {
		t.Fatalf("bob answers at a hostname of his own, which the setting never derived, and was told to move:\n%s", all)
	}
	for _, gone := range []string{"endpoint_announce", "update_contact"} {
		if strings.Contains(all, gone) {
			t.Fatalf("the audit trail still shows %q:\n%s", gone, all)
		}
	}
	// And what `doctor` and the `serve` banner say of each.
	if line := addressDriftLine(newURL, "alice", identity.EndpointFor(oldURL, "alice")); !strings.Contains(line, "-purpose move") {
		t.Fatalf("no advice for an account at an address the node no longer advertises: %q", line)
	}
	if line := addressDriftLine(newURL, "alice", identity.EndpointFor(newURL, "alice")); line != "" {
		t.Fatalf("an account at the advertised address was reported as drifted: %q", line)
	}
}
