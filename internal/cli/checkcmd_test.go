package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// plantContactCards writes two contacts into the store at dir: one whose card reads, and one whose
// card carries a character before its certificate that the identity core 0.4.1 skipped and 0.4.2
// refuses. It answers the root of the one that does not read.
func plantContactCards(t *testing.T, dir string) (accountSlug, badRoot string) {
	t.Helper()
	ctx := context.Background()
	st := openStoreAt(t, dir)
	defer st.Close()
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	a, err := idm.CreateAccount(ctx, "me", "Me", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		name string
		bad  bool
	}{{"reads", false}, {"stray", true}} {
		w := testid.NewWallet(t, p.name)
		h := w.Issue(t, "https://"+p.name+".example/mcp")
		leaf, _ := hdtpidentity.Parse(h.LeafDER)
		card := h.Card(p.name, "required")
		if p.bad {
			card = strings.Replace(card, "X-HDTP-CERT:", "X-HDTP-CERT:!", 1)
			badRoot = w.Fpr
		}
		if _, err := st.InsertContact(ctx, store.Contact{
			AccountID: a.ID, Fingerprint: w.Fpr, SPKI: leaf.SPKI, Status: "active", Permissions: []string{"message.text"},
			Endpoint: h.Endpoint, Card: card, Leaf: h.LeafDER, RootCert: w.RootDER,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return a.Slug, badRoot
}

// `check store` reads every card and certificate the store holds by the identity core's rule and
// names each that does not, exit 1; once the card is replaced by one that reads, exit 0 and "all
// read". It writes nothing: the card it named is on file as it was.
//
// Shown red with the exit status held at 0 whatever the report says (the mutation).
func TestCheckStoreNamesTheCardThatDoesNotReadAndExitsOne(t *testing.T) {
	n := newIDNode(t, "n")
	slug, badRoot := plantContactCards(t, n.dir)
	var out, errb bytes.Buffer
	code := Run([]string{"check", "store", "-config", n.cfg}, "test", &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s%s", code, out.String(), errb.String())
	}
	want := "NOT READ contacts account:" + slug + " contact:" + badRoot + " card: the card on file does not read (certificate does not parse: not base64url)"
	if !strings.Contains(out.String(), "store:   6 cards and certificates read by the identity core's rule (contacts.card 2, contacts.leaf 2, contacts.root_cert 2); 1 does NOT read\n") || !strings.Contains(out.String(), want) {
		t.Fatalf("the report:\n%s%s", out.String(), errb.String())
	}
	ctx := context.Background()
	st := openStoreAt(t, n.dir)
	c, err := st.GetContact(ctx, accountIDOf(t, st, slug), badRoot)
	if err != nil || !strings.Contains(c.Card, "X-HDTP-CERT:!") {
		t.Fatalf("the check changed the store: %v %q", err, c.Card)
	}
	// The owner mends it: a card of that contact's that reads arrives (UpdateContactCard is what
	// a refresh or a redemption writes through), and the check is clean.
	w := testid.NewWallet(t, "stray")
	fixed := w.Issue(t, "https://stray.example/mcp").Card("stray", "required")
	if err := st.UpdateContactCard(ctx, c.AccountID, badRoot, fixed, "stray"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	out.Reset()
	errb.Reset()
	if code := Run([]string{"check", "store", "-config", n.cfg}, "test", &out, &errb); code != 0 || !strings.HasSuffix(strings.TrimSpace(out.String()), "; all read") || errb.Len() != 0 {
		t.Fatalf("after the card was replaced: exit %d\n%s%s", code, out.String(), errb.String())
	}
}

// plantContactInAStateNoPinHas writes one contact of the account at slug — created when the store
// holds none — whose card, leaf and root certificate read, then puts it in a state the store's own
// API cannot write (the schema's CHECK refuses the move: shown first), as a
// hand-edited store would: raw SQL, in a test only, with the constraint switched off for the one
// connection that writes it. It answers the contact's root.
func plantContactInAStateNoPinHas(t *testing.T, dir, slug string) (root string) {
	t.Helper()
	ctx := context.Background()
	st := openStoreAt(t, dir)
	defer st.Close()
	a, err := st.GetAccountBySlug(ctx, slug)
	if errors.Is(err, store.ErrNotFound) {
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		a, err = idm.CreateAccount(ctx, slug, "Me", identity.AlgoEd25519)
	}
	if err != nil {
		t.Fatal(err)
	}
	w := testid.NewWallet(t, "frozen")
	h := w.Issue(t, "https://frozen.example/mcp")
	leaf, _ := hdtpidentity.Parse(h.LeafDER)
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: a.ID, Fingerprint: w.Fpr, SPKI: leaf.SPKI, Status: "active", Permissions: []string{"message.text"},
		Endpoint: h.Endpoint, Card: h.Card("frozen", "required"), Leaf: h.LeafDER, RootCert: w.RootDER,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateContactStatus(ctx, a.ID, w.Fpr, "frozen"); err == nil {
		t.Fatal("the store moved a contact to state frozen; the schema's CHECK admits only the four")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "hdtp.db")+"?_pragma=busy_timeout(5000)&_pragma=ignore_check_constraints(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE contacts SET status = ? WHERE account_id = ? AND fingerprint = ?`, "frozen", a.ID, w.Fpr); err != nil {
		t.Fatal(err)
	}
	return w.Fpr
}

// `check store` names a contact in a state neither a pin nor a request has — a row the store's
// own API cannot write, so a hand-edited store's or a later binary's — and exits 1 though every
// card and certificate reads; once the owner removes the contact (what `remove_contact` writes),
// exit 0 and the clause is gone. It writes nothing: the row is in the state it was found in.
//
// Shown red with the exit status held at 0 for such a row (the mutation).
func TestCheckStoreNamesTheContactInAStateNoPinHasAndExitsOne(t *testing.T) {
	n := newIDNode(t, "n")
	root := plantContactInAStateNoPinHas(t, n.dir, "me")
	var out, errb bytes.Buffer
	code := Run([]string{"check", "store", "-config", n.cfg}, "test", &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s%s", code, out.String(), errb.String())
	}
	want := "NO PIN contacts account:me contact:" + root + ` status: "frozen" is neither a state a pin has (active, pending_out, blocked) nor a request awaiting the owner (pending_in); the identity core is handed no pin for this row`
	if !strings.Contains(out.String(), "store:   3 cards and certificates read by the identity core's rule (contacts.card 1, contacts.leaf 1, contacts.root_cert 1); all read; 1 contact in a state neither a pin nor a request has\n") || !strings.Contains(out.String(), want+"\n") {
		t.Fatalf("the report:\n%s%s", out.String(), errb.String())
	}
	ctx := context.Background()
	st := openStoreAt(t, n.dir)
	id := accountIDOf(t, st, "me")
	if c, err := st.GetContact(ctx, id, root); err != nil || c.Status != "frozen" {
		t.Fatalf("the check changed the store: %v %+v", err, c)
	}
	if err := st.DeleteContact(ctx, id, root); err != nil {
		t.Fatal(err)
	}
	st.Close()
	out.Reset()
	errb.Reset()
	if code := Run([]string{"check", "store", "-config", n.cfg}, "test", &out, &errb); code != 0 || !strings.HasSuffix(strings.TrimSpace(out.String()), "; all read") || errb.Len() != 0 {
		t.Fatalf("after the contact was removed: exit %d\n%s%s", code, out.String(), errb.String())
	}
}

func accountIDOf(t *testing.T, st store.Store, slug string) string {
	t.Helper()
	a, err := st.GetAccountBySlug(context.Background(), slug)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// The refusals of the door (build rule 3): no subcommand and an unknown one are usage (2); a config
// that does not load, and a store whose schema is not this binary's — not read, since the
// statements would not match its tables — are 1 with the reason, the latter naming `migrate`.
func TestCheckStoreRefusals(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"check"}, "test", &out, &errb); code != 2 || !strings.Contains(errb.String(), checkUsage) {
		t.Fatalf("no subcommand: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := Run([]string{"check", "cards"}, "test", &out, &errb); code != 2 || !strings.Contains(errb.String(), `unknown subcommand "cards"`) {
		t.Fatalf("an unknown subcommand: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := Run([]string{"check", "store", "-config", filepath.Join(t.TempDir(), "none.json")}, "test", &out, &errb); code != 1 || !strings.HasPrefix(errb.String(), "check store: ") {
		t.Fatalf("a config that does not load: %d %q", code, errb.String())
	}
	errb.Reset()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"data_dir":"`+dir+`","internal_bind":"127.0.0.1:0","public_bind":"127.0.0.1:0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	empty, err := store.OpenSQLite(filepath.Join(dir, "hdtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	empty.Close()
	if code := Run([]string{"check", "store", "-config", cfg}, "test", &out, &errb); code != 1 || !strings.Contains(errb.String(), "it has not been migrated; run `hdtp-gateway migrate` with the node stopped") {
		t.Fatalf("a store behind this binary's schema: %d %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("a refused check reported something: %q", out.String())
	}
}

// `serve` prints the same report in its banner and serves whatever it says: the node whose store
// holds a card that does not read and a contact in a state neither a pin nor a request has comes
// up, and its banner names the card and the contact.
func TestServeNamesTheCardThatDoesNotReadInItsBannerAndServes(t *testing.T) {
	var slug, badRoot, frozenRoot string
	r := runServe(t, func(t *testing.T, dir string) {
		st := migrated(t, dir)
		st.Close()
		slug, badRoot = plantContactCards(t, dir)
		frozenRoot = plantContactInAStateNoPinHas(t, dir, slug)
	})
	r.stop()
	out := r.out.String()
	if !strings.Contains(out, "hdtp-gateway serving:") || !strings.Contains(out, "store:   9 cards and certificates read by the identity core's rule (contacts.card 3, contacts.leaf 3, contacts.root_cert 3); 1 does NOT read; 1 contact in a state neither a pin nor a request has\n") || !strings.Contains(out, "NOT READ contacts account:"+slug+" contact:"+badRoot+" card: ") || !strings.Contains(out, "NO PIN contacts account:"+slug+" contact:"+frozenRoot+` status: "frozen" is neither`) {
		t.Fatalf("the banner:\n%s", out)
	}
}
