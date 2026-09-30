package storecheck

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// A store with every field a certificate or a card lives in, planted through the store's own
// API: one row of each that reads, one of each that does not. The run names each refusal by its
// table, its row and its field, with the reader's reason, counts what it read, and changes
// nothing. The card is the field pact-identity 0.4.2's reading changed: a stray character before
// its certificate, which 0.4.1 skipped, is `not base64url` now.
//
// Shown red with the card's reading removed from the run (the mutation): the card's refusal is not
// named and the count of cards read is nought.
func TestTheRunNamesEveryCardAndCertificateThatDoesNotRead(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	alina, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	me := testid.NewWallet(t, "Alina")
	mine := me.Issue(t, "https://alina.example/mcp")
	if err := st.SetAccountRoot(ctx, alina.ID, me.Fpr, me.RootDER); err != nil {
		t.Fatal(err)
	}
	broken, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "broken", DisplayName: "Broken", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountRoot(ctx, broken.ID, "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", []byte("not a certificate")); err != nil {
		t.Fatal(err)
	}
	notDER := []byte{0x30, 0x03, 0x02, 0x01}
	for _, l := range []store.Leaf{
		{AccountID: alina.ID, Kid: mine.Kid, Leaf: mine.LeafDER, State: "current", Endpoint: mine.Endpoint, NotBefore: now.Unix(), NotAfter: now.AddDate(1, 0, 0).Unix(), CreatedAt: now.Unix()},
		{AccountID: alina.ID, Kid: "sha256:former", Leaf: notDER, State: "former", Endpoint: mine.Endpoint, CreatedAt: now.Unix()},
	} {
		if err := st.InsertLeaf(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	// Four contacts with something to read, and one written without a card or a leaf (an import's
	// row before its pin arrives), which holds no field to read.
	type planted struct {
		name string
		card func(h *testid.Host) string
		leaf func(h *testid.Host) []byte
		root func(w *testid.Wallet) []byte
	}
	good := func(h *testid.Host) string { return h.Card(h.RootFpr, "required") }
	fprs := map[string]string{}
	for _, p := range []planted{
		{"good", good, func(h *testid.Host) []byte { return h.LeafDER }, func(w *testid.Wallet) []byte { return w.RootDER }},
		{"badcard", func(h *testid.Host) string { return strings.Replace(good(h), "X-PACT-CERT:", "X-PACT-CERT:!", 1) }, func(h *testid.Host) []byte { return h.LeafDER }, func(w *testid.Wallet) []byte { return w.RootDER }},
		{"badleaf", func(*testid.Host) string { return "" }, func(*testid.Host) []byte { return notDER }, func(w *testid.Wallet) []byte { return w.RootDER }},
		{"badroot", good, func(h *testid.Host) []byte { return h.LeafDER }, func(*testid.Wallet) []byte { return notDER }},
		{"bare", func(*testid.Host) string { return "" }, func(*testid.Host) []byte { return nil }, func(*testid.Wallet) []byte { return nil }},
	} {
		w := testid.NewWallet(t, p.name)
		h := w.Issue(t, "https://"+p.name+".example/mcp")
		leaf, _ := pactidentity.Parse(h.LeafDER)
		fprs[p.name] = w.Fpr
		if _, err := st.InsertContact(ctx, store.Contact{
			AccountID: alina.ID, Fingerprint: w.Fpr, SPKI: leaf.SPKI, Status: "active", Permissions: []string{"message.text"},
			Endpoint: h.Endpoint, Card: p.card(h), Leaf: p.leaf(h), RootCert: p.root(w),
		}); err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
	}
	gone := testid.NewWallet(t, "gone")
	if err := st.UpsertTombstone(ctx, store.Tombstone{AccountID: alina.ID, Root: gone.Fpr, Leaf: notDER, At: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	moved := testid.NewWallet(t, "moved")
	movedHost := moved.Issue(t, "https://moved.example/mcp")
	if err := st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: alina.ID, Root: moved.Fpr, Endpoint: movedHost.Endpoint, Leaf: movedHost.LeafDER, Why: "new_address", At: now.Unix(), RootCert: notDER}); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(ctx, st, now)
	if err != nil {
		t.Fatal(err)
	}
	wantRead := map[string]int{
		"accounts.root_cert": 2, "leaves.leaf": 2,
		"contacts.card": 3, "contacts.leaf": 4, "contacts.root_cert": 4,
		"tombstones.leaf": 1, "pending_addresses.leaf": 1, "pending_addresses.root_cert": 1,
	}
	if len(rep.Read) != len(wantRead) {
		t.Fatalf("fields read: %v, want %v", rep.Read, wantRead)
	}
	for k, n := range wantRead {
		if rep.Read[k] != n {
			t.Errorf("%s: read %d, want %d", k, rep.Read[k], n)
		}
	}
	if rep.Fields() != 18 {
		t.Errorf("Fields() = %d, want 18", rep.Fields())
	}
	var got []string
	for _, f := range rep.Refusals {
		got = append(got, f.Table+" "+f.Row+" "+f.Field)
		switch f.Field {
		case "card":
			if !strings.Contains(f.Why, "not base64url") {
				t.Errorf("the card's refusal does not say why: %q", f.Why)
			}
		default:
			if !strings.HasPrefix(f.Why, "certificate does not parse: ") {
				t.Errorf("%s %s %s: %q", f.Table, f.Row, f.Field, f.Why)
			}
		}
	}
	sort.Strings(got)
	want := []string{
		"accounts account:broken root_cert",
		"contacts account:alina contact:" + fprs["badcard"] + " card",
		"contacts account:alina contact:" + fprs["badleaf"] + " leaf",
		"contacts account:alina contact:" + fprs["badroot"] + " root_cert",
		"leaves account:alina kid:sha256:former leaf",
		"pending_addresses account:alina root:" + moved.Fpr + " root_cert",
		"tombstones account:alina root:" + gone.Fpr + " leaf",
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("refusals:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The lines both doors print: the count by field, the verdict, and one line per refusal that
	// names the row before the reason.
	lines := rep.Lines()
	if len(lines) != 1+len(want) {
		t.Fatalf("lines: %q", lines)
	}
	if !strings.HasPrefix(lines[0], "store:   18 cards and certificates read by the identity core's rule (accounts.root_cert 2, contacts.card 3, ") || !strings.HasSuffix(lines[0], "; 7 do NOT read") {
		t.Fatalf("the summary line: %q", lines[0])
	}
	found := false
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, "NOT READ contacts account:alina contact:"+fprs["badcard"]+" card: the card on file does not read (certificate does not parse: not base64url)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no line names the card that does not read:\n%s", strings.Join(lines, "\n"))
	}
	// Nothing was changed: the card that does not read is still on file as it was planted.
	c, err := st.GetContact(ctx, alina.ID, fprs["badcard"])
	if err != nil || !strings.Contains(c.Card, "X-PACT-CERT:!") {
		t.Fatalf("the run changed the store: %v %q", err, c.Card)
	}
}

// The control: a store where everything reads says so, and a store with nothing to read says that.
func TestAStoreWhoseFieldsAllReadSaysSo(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(ctx, st, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fields() != 0 || len(rep.Refusals) != 0 || rep.Lines()[0] != "store:   0 cards and certificates read by the identity core's rule (none held); all read" {
		t.Fatalf("an empty store: %+v %q", rep, rep.Lines())
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	w := testid.NewWallet(t, "Me")
	if err := st.SetAccountRoot(ctx, a.ID, w.Fpr, w.RootDER); err != nil {
		t.Fatal(err)
	}
	peer := testid.NewWallet(t, "Peer")
	h := peer.Issue(t, "https://peer.example/mcp")
	leaf, _ := pactidentity.Parse(h.LeafDER)
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: a.ID, Fingerprint: peer.Fpr, SPKI: leaf.SPKI, Status: "pending_in", Permissions: []string{"message.text"},
		Endpoint: h.Endpoint, Card: h.Card("Peer", "required"), Leaf: h.LeafDER, RootCert: peer.RootDER,
	}); err != nil {
		t.Fatal(err)
	}
	rep, err = Run(ctx, st, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fields() != 4 || len(rep.Refusals) != 0 || !strings.HasSuffix(rep.Lines()[0], "; all read") {
		t.Fatalf("a store that reads: %+v %q", rep, rep.Lines())
	}
}
