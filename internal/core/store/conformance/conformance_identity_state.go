package conformance

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// identityState is the suite for the HDTP 1.0 state: the root, the leaf ledger and the side tables.
func identityState(t *testing.T, newStore Factory) {
	// HDTP 1.0: the root beside the account, the leaf ledger,
	// 2.0 pins that move without the root moving, and the §5.3 side tables.
	t.Run("IdentityStateRoundTrips", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ids", DisplayName: "P", Algo: "ed25519"})
		// A new account holds a key and no leaf: it is protocol 1 in the row until
		// `install-leaf` writes 2, and it serves nothing until then.
		if a.AcceptNewHosts != "auto" {
			t.Fatalf("account defaults wrong: %+v", a)
		}
		// An account with no key reads as NO KEY, in both engines, and not as an
		// error: that is the shape a data-only archive arrives in, and the node,
		// `csr -purpose signup` and `install-leaf` all decide from an empty slice
		// (HDTP §9). An error here made every one of those branches unreachable.
		if k, kerr := s.GetAccountSealedKey(ctx, a.ID); kerr != nil || len(k) != 0 {
			t.Fatalf("an account with no key must read as empty, not as an error: %q %v", k, kerr)
		}
		if err := s.SetAccountKey(ctx, a.ID, "sha256:leaf1", []byte("sealed1")); err != nil {
			t.Fatal(err)
		}
		if err := s.SetAccountRoot(ctx, a.ID, "sha256:root", []byte("root-der")); err != nil {
			t.Fatal(err)
		}
		if err := s.SetAccountHostPolicy(ctx, a.ID, "ask"); err != nil {
			t.Fatal(err)
		}
		// A leaf install moves the key SetAccountKey bound once.
		if err := s.SetAccountLeafKey(ctx, a.ID, "sha256:leaf2", []byte("sealed2"), "p256"); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetAccountByID(ctx, a.ID)
		if !got.HasRoot() || got.RootFingerprint != "sha256:root" || string(got.RootCert) != "root-der" || got.AcceptNewHosts != "ask" || got.Fingerprint != "sha256:leaf2" || got.Algo != "p256" {
			t.Fatalf("2.0 account fields lost: %+v", got)
		}
		if k, _ := s.GetAccountSealedKey(ctx, a.ID); string(k) != "sealed2" {
			t.Fatalf("leaf key not moved: %q", k)
		}
		for _, l := range []store.Leaf{
			{AccountID: a.ID, Kid: "sha256:leaf1", Leaf: []byte("l1"), KeySealed: []byte("k1"), NotBefore: 1, NotAfter: 10, State: "superseded", Endpoint: "https://a.example/mcp"},
			{AccountID: a.ID, Kid: "sha256:leaf2", Leaf: []byte("l2"), KeySealed: []byte("k2"), NotBefore: 2, NotAfter: 20, State: "current", Endpoint: "https://a.example/mcp"},
			{AccountID: a.ID, Kid: "sha256:leaf3", State: "pending", Endpoint: "https://b.example/mcp", KeySealed: []byte("k3")},
		} {
			if err := s.InsertLeaf(ctx, l); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:leaf3", State: "current", Endpoint: "x"}); err == nil {
			t.Fatal("duplicate (account, kid) accepted")
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:bad", State: "live", Endpoint: "x"}); err == nil {
			t.Fatal("invalid leaf state accepted")
		}
		if err := s.RetireLeafKey(ctx, a.ID, "sha256:leaf1"); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:leaf3", Leaf: []byte("l3"), NotBefore: 3, NotAfter: 30, State: "current", Endpoint: "https://b.example/mcp"}); err != nil {
			t.Fatal(err)
		}
		leaves, _ := s.ListLeaves(ctx, a.ID)
		if len(leaves) != 3 {
			t.Fatalf("leaves: %d", len(leaves))
		}
		byKid := map[string]store.Leaf{}
		for _, l := range leaves {
			byKid[l.Kid] = l
		}
		if l := byKid["sha256:leaf1"]; l.State != "former" || l.KeySealed != nil {
			t.Fatalf("retire did not destroy the key: %+v", l)
		}
		if l := byKid["sha256:leaf3"]; l.State != "current" || string(l.Leaf) != "l3" || l.NotAfter != 30 || string(l.KeySealed) != "k3" {
			t.Fatalf("update lost: %+v", l)
		}
		// The account's own copy of its current leaf's key goes the same way, and the fingerprint
		// stays: it is how pins, routes and audit rows name the account.
		if err := s.SetAccountLeafKey(ctx, a.ID, "sha256:leaf3", []byte("k3"), "p256"); err != nil {
			t.Fatal(err)
		}
		if err := s.ClearAccountKey(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		if k, err := s.GetAccountSealedKey(ctx, a.ID); err != nil || len(k) != 0 {
			t.Fatalf("the account's key survived being cleared: %d bytes, %v", len(k), err)
		}
		if got, _ := s.GetAccountByID(ctx, a.ID); got.Fingerprint != "sha256:leaf3" {
			t.Fatalf("clearing the key must keep the fingerprint: %q", got.Fingerprint)
		}
		if err := s.ClearAccountKey(ctx, "no-such-account"); err == nil {
			t.Fatal("clearing an unknown account's key reported success")
		}
		// The sibling kids: what another identity on this node holds. One inbound
		// envelope asks for this to tell a kid held elsewhere on the node from one
		// this endpoint never held (HDTP §13.3, §14.4), so it must never answer
		// with the asking account's own kids, and must see every other account's.
		other, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "sibling", DisplayName: "Sibling", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: other.ID, Kid: "sha256:sibling-leaf", State: "current", Endpoint: "https://s.example/mcp"}); err != nil {
			t.Fatal(err)
		}
		mine, err := s.ListKidsExcept(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(mine) != 1 || mine[0] != "sha256:sibling-leaf" {
			t.Fatalf("the siblings' kids and nothing of our own: %v", mine)
		}
		theirs, err := s.ListKidsExcept(ctx, other.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(theirs) != 3 {
			t.Fatalf("every kid of the other account: %v", theirs)
		}
		if n, _ := s.DeleteLeavesByState(ctx, a.ID, "former"); n != 1 {
			t.Fatalf("delete former: %d", n)
		}
		// A 2.0 pin: the fingerprint column is the root and never moves; the
		// endpoint, the leaf and its key do (HDTP §14.3, §5.3).
		c, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:peer-root", SPKI: []byte{1}, Status: "active",
			Endpoint: "https://p.example/mcp", Leaf: []byte("pl1"), ChainSentKid: "sha256:leaf2"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Endpoint != "https://p.example/mcp" || string(c.Leaf) != "pl1" || c.ChainSentKid != "sha256:leaf2" {
			t.Fatalf("2.0 pin fields lost: %+v", c)
		}
		// The ROOT's certificate is kept beside the pin: the chain
		// travels once, so a host that keeps only the fingerprint cannot prove a
		// stored leaf afterwards, here or in an archive taken here. It fills in when
		// a chain arrives and is never overwritten - a pin's root cannot change.
		if len(c.RootCert) != 0 {
			t.Fatalf("a pin made with no root certificate must read back empty: %q", c.RootCert)
		}
		if err := s.SetContactRootCert(ctx, a.ID, "sha256:peer-root", []byte("peer-root-der")); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:peer-root"); string(got.RootCert) != "peer-root-der" {
			t.Fatalf("the root certificate did not persist: %q", got.RootCert)
		}
		if err := s.SetContactRootCert(ctx, a.ID, "sha256:peer-root", []byte("someone-elses-der")); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:peer-root"); string(got.RootCert) != "peer-root-der" {
			t.Fatalf("a stored root certificate was overwritten: %q", got.RootCert)
		}
		if withCert, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:pinned-with-cert", SPKI: []byte{3}, Status: "active",
			Endpoint: "https://w.example/mcp", Leaf: []byte("wl1"), RootCert: []byte("w-root-der")}); err != nil || string(withCert.RootCert) != "w-root-der" {
			t.Fatalf("a pin made WITH a root certificate lost it: %+v %v", withCert, err)
		}
		if err := s.RepinContactAddress(ctx, a.ID, "sha256:peer-root", "https://q.example/mcp", []byte("pl2"), []byte{9}, 77); err != nil {
			t.Fatal(err)
		}
		// A move does not touch the root or its certificate.
		if got, _ := s.GetContact(ctx, a.ID, "sha256:peer-root"); string(got.RootCert) != "peer-root-der" {
			t.Fatalf("a move lost the root certificate: %q", got.RootCert)
		}
		if err := s.ClearChainSentKids(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		c, _ = s.GetContact(ctx, a.ID, "sha256:peer-root")
		if c.Endpoint != "https://q.example/mcp" || string(c.Leaf) != "pl2" || c.SPKI[0] != 9 || c.PinnedAt != 77 || c.ChainSentKid != "" {
			t.Fatalf("repin lost: %+v", c)
		}
		if err := s.SetContactChainSentKid(ctx, a.ID, "sha256:peer-root", "sha256:leaf3"); err != nil {
			t.Fatal(err)
		}
		if err := s.RepinContactAddress(ctx, a.ID, "sha256:nobody", "x", nil, nil, 1); err == nil {
			t.Fatal("repin of a missing contact reported success")
		}
		// The §5.3 side tables.
		if err := s.UpsertTombstone(ctx, store.Tombstone{AccountID: a.ID, Root: "sha256:gone", Leaf: []byte("gl"), At: 5}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertTombstone(ctx, store.Tombstone{AccountID: a.ID, Root: "sha256:gone", Leaf: []byte("gl2"), At: 6}); err != nil {
			t.Fatal(err)
		}
		if ts, _ := s.ListTombstones(ctx, a.ID); len(ts) != 1 || string(ts[0].Leaf) != "gl2" || ts[0].At != 6 {
			t.Fatalf("tombstone upsert: %+v", ts)
		}
		if err := s.DeleteTombstone(ctx, a.ID, "sha256:gone"); err != nil {
			t.Fatal(err)
		}
		if ts, _ := s.ListTombstones(ctx, a.ID); len(ts) != 0 {
			t.Fatalf("tombstone not deleted: %+v", ts)
		}
		for _, f := range []store.FormerEndpoint{{AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://p.example/mcp", At: 1}, {AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://p.example/mcp", At: 2}} {
			if err := s.InsertFormerEndpoint(ctx, f); err != nil {
				t.Fatal(err)
			}
		}
		if fs, _ := s.ListFormerEndpoints(ctx, a.ID); len(fs) != 2 {
			t.Fatalf("former endpoints: %+v", fs)
		}
		if err := s.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://r.example/mcp", Leaf: []byte("pl3"), Why: "ask", At: 9, RootCert: []byte("root-der")}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://s.example/mcp", Leaf: []byte("pl4"), Why: "returned after removal", At: 10}); err != nil {
			t.Fatal(err)
		}
		if p, err := s.GetPendingAddress(ctx, a.ID, "sha256:peer-root"); err != nil || p.Endpoint != "https://s.example/mcp" || p.Why != "returned after removal" {
			t.Fatalf("pending upsert: %+v %v", p, err)
		}
		// A pending address keeps the root's certificate too: the owner may sit on the
		// decision for days, and the chain that carried it does not come back.
		if ps, _ := s.ListPendingAddresses(ctx, a.ID); len(ps) != 1 || string(ps[0].RootCert) != "root-der" {
			t.Fatalf("pending address lost its root certificate: %+v", ps)
		}
		if ps, _ := s.ListPendingAddresses(ctx, a.ID); len(ps) != 1 {
			t.Fatalf("pending list: %+v", ps)
		}
		if err := s.DeletePendingAddress(ctx, a.ID, "sha256:peer-root"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetPendingAddress(ctx, a.ID, "sha256:peer-root"); err == nil {
			t.Fatal("pending address still readable after delete")
		}
	})

	// One pending signing request per account, and replacing it is one step on
	// either engine: three writers replacing the pending request together, round after round,
	// leave exactly one and none of them fails. On Postgres it is LockAccount that makes them
	// wait for each other; without it they meet the unique index instead.
	t.Run("OnePendingRequestAndReplacingItIsOneStep", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "pend", DisplayName: "P", Algo: "ed25519"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "pend2", DisplayName: "Q", Algo: "ed25519"})
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:p1", State: "pending", CreatedAt: 1}); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:p2", State: "pending", CreatedAt: 2}); err == nil {
			t.Fatal("a second pending request for one account was written")
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: b.ID, Kid: "sha256:q1", State: "pending", CreatedAt: 1}); err != nil {
			t.Fatalf("another account's pending request: %v", err)
		}
		var seq atomic.Int64
		for round := 0; round < 10; round++ {
			var wg sync.WaitGroup
			errs := make(chan error, 3)
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					kid := fmt.Sprintf("sha256:r%d", seq.Add(1))
					errs <- s.Atomically(ctx, func(tx store.Store) error {
						if err := tx.LockAccount(ctx, a.ID); err != nil {
							return err
						}
						if _, err := tx.DeleteLeavesByState(ctx, a.ID, "pending"); err != nil {
							return err
						}
						if err := tx.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: kid, State: "pending", CreatedAt: 3}); err != nil {
							return err
						}
						return tx.SetLeafRequest(ctx, a.ID, kid, []byte("hash"), "")
					})
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("round %d: a replacement failed: %v", round, err)
				}
			}
			leaves, _ := s.ListLeaves(ctx, a.ID)
			pending := 0
			for _, l := range leaves {
				if l.State == "pending" {
					pending++
				}
			}
			if pending != 1 {
				t.Fatalf("round %d: %d pending requests", round, pending)
			}
		}
	})
}
