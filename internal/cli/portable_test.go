package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// The two verbs end to end, and the recovery they are for. A node that has lost its master key
// cannot start: every leaf key is sealed under it. Under HDTP that loses no identity — the root is
// in the wallet — and the way back is the same as moving house: take the contacts and the chats,
// leave everything else, and have the wallet certify the new home.
//
// This used to be `backup create -without-master-key` then `backup restore -data-only`, over a
// copy of the whole database with the keys NULLed out of it. What travels now never held a key.
func TestALostMasterKeyIsRecoveredByExportingAndImporting(t *testing.T) {
	old := newIDNode(t, "old")
	ctx := context.Background()
	const endpoint = "https://agent.alice.example/a/alice/mcp"
	st := openStoreAt(t, old.dir)
	if _, err := (&identity.Manager{Store: st, Keyring: openKeyringAt(t, old.dir)}).CreateAccount(ctx, "alice", "Alice", identity.AlgoEd25519); err != nil {
		t.Fatal(err)
	}
	st.Close()
	wallet := newTestWallet(t, "Alice")
	now := time.Now()
	wallet.certifyUnder(t, old, "alice", identity.PurposeSignup, endpoint, now)

	st = openStoreAt(t, old.dir)
	a, _ := st.GetAccountBySlug(ctx, "alice")
	peer := testid.NewWallet(t, "Bharat")
	ph := peer.Issue(t, "https://bharat.example/a/bharat/mcp")
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: peer.Fpr, SPKI: ph.Key.Public().SPKI, Status: "active",
		Endpoint: ph.Endpoint, Leaf: ph.LeafDER, RootCert: peer.RootDER, DisplayName: "Bharat", Card: ph.Card("Bharat", "optional")}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// The master key is gone for good.
	if err := os.Remove(filepath.Join(old.dir, "keyring.key")); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "alice.zip")
	code, out, errb := run(t, "export", "-config", old.cfg, "-slug", "alice", "-out", file)
	if code != 0 || !strings.Contains(out, "1 contact(s)") {
		t.Fatalf("export: code=%d out=%q err=%q", code, out, errb)
	}
	// The person is told, before the file is written, what an unencrypted file means (§9.2).
	if !strings.HasPrefix(out, "This file is not encrypted. Anyone who gets it can read your contact list") {
		t.Fatalf("export must say what the file is before it writes it: %q", out)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("an export is somebody's address book and mail, and must be 0600: %v %v", fi, err)
	}
	// It never replaces a file.
	if code, _, errb := run(t, "export", "-config", old.cfg, "-slug", "alice", "-out", file); code == 0 {
		t.Fatalf("a second export overwrote the first: %q", errb)
	}

	fresh := newIDNode(t, "fresh")
	// Without -yes it is a review: what would be written, and nothing written.
	code, out, errb = run(t, "import", file, "-config", fresh.cfg, "-slug", "alice")
	if code != 0 || !strings.Contains(out, "write "+peer.Fpr) || !strings.Contains(out, "nothing was written") {
		t.Fatalf("import review: code=%d out=%q err=%q", code, out, errb)
	}
	got := openStoreAt(t, fresh.dir)
	if _, err := got.GetAccountBySlug(ctx, "alice"); err == nil {
		t.Fatal("the review wrote the identity")
	}
	got.Close()
	code, out, errb = run(t, "import", file, "-config", fresh.cfg, "-slug", "alice", "-yes")
	if code != 0 || !strings.Contains(out, "not served yet: alice") || !strings.Contains(out, "account csr -slug alice -purpose move") {
		t.Fatalf("import: code=%d out=%q err=%q", code, out, errb)
	}
	got = openStoreAt(t, fresh.dir)
	b, err := got.GetAccountBySlug(ctx, "alice")
	if err != nil || b.RootFingerprint != wallet.fingerprint() {
		t.Fatalf("the identity did not arrive as itself: %+v %v", b, err)
	}
	if sealed, _ := got.GetAccountSealedKey(ctx, b.ID); len(sealed) != 0 {
		t.Fatalf("an imported identity arrived holding %d bytes of key", len(sealed))
	}
	if c, err := got.GetContact(ctx, b.ID, peer.Fpr); err != nil || c.Endpoint != ph.Endpoint || !c.HandshakeDue {
		t.Fatalf("the contact did not arrive owed the handshake: %+v %v", c, err)
	}
	// One audit row for the import, naming the identity it made.
	rows, err := got.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	imports := 0
	for _, r := range rows {
		if r.Action == "account_import" && r.Outcome == "ok" && strings.Contains(r.Resource, "account:"+b.ID) {
			imports++
		}
	}
	if imports != 1 {
		t.Fatalf("the import wrote %d account_import rows naming %s, want 1", imports, b.ID)
	}
	got.Close()
	// And the SAME wallet certifies the new home. It has no ledger, so it is a move.
	res := wallet.certifyUnder(t, fresh, "alice", identity.PurposeMove, endpoint, now.Add(time.Minute))
	if res.RootFingerprint != wallet.fingerprint() || !res.Moved {
		t.Fatalf("the first leaf on the new host: %+v", res)
	}
	// The same file into the same identity merges: nothing new, and it ends with a renewal.
	code, out, errb = run(t, "import", file, "-config", fresh.cfg, "-slug", "alice", "-yes")
	if code != 0 || !strings.Contains(out, "keep  "+peer.Fpr) || !strings.Contains(out, "0 contact(s)") || !strings.Contains(out, "a request for a new leaf is waiting: renew at "+endpoint) {
		t.Fatalf("a second import into the same identity: code=%d out=%q err=%q", code, out, errb)
	}
	// A root this identity holds as a stranger's request is not a contact: the review says the file
	// does not decide it, and keeps nothing and reports no conflict for it.
	got = openStoreAt(t, fresh.dir)
	if ok, err := got.MoveContactStatus(ctx, b.ID, peer.Fpr, "active", "pending_in"); err != nil || !ok {
		t.Fatalf("making the contact a request: %v %v", ok, err)
	}
	got.Close()
	code, out, errb = run(t, "import", file, "-config", fresh.cfg, "-slug", "alice")
	if code != 0 || !strings.Contains(out, "skip  "+peer.Fpr) || strings.Contains(out, "keep  "+peer.Fpr) || strings.Contains(out, "the file says "+peer.Fpr) {
		t.Fatalf("the review of a file naming a held request: code=%d out=%q err=%q", code, out, errb)
	}
	got = openStoreAt(t, fresh.dir)
	if ok, err := got.MoveContactStatus(ctx, b.ID, peer.Fpr, "pending_in", "active"); err != nil || !ok {
		t.Fatalf("making the request a contact again: %v %v", ok, err)
	}
	got.Close()
	// Into a slug that is somebody else: refused, audited, nothing written.
	code, _, errb = run(t, "import", file, "-config", fresh.cfg, "-slug", "alice-two", "-yes")
	if code == 0 || !strings.Contains(errb, `already on this node as "alice"`) || !strings.Contains(errb, "nothing was written") {
		t.Fatalf("the same root under another slug: code=%d err=%q", code, errb)
	}
	got = openStoreAt(t, fresh.dir)
	rows, _ = got.ListAuditEvents(ctx, "")
	refusals := 0
	for _, r := range rows {
		if r.Action == "account_import" && r.Outcome == "refused" {
			refusals++
		}
	}
	if refusals != 1 {
		t.Fatalf("a refused import must be audited once as refused: %d", refusals)
	}
}

// `backup` is not a command any more, and neither verb does anything when it is typed bare. The
// documentation lint runs every command bare; the first draft of `export` made the default data
// directory and migrated a store in it before it said what it was missing.
func TestTheExportVerbsCostNothingWhenTypedBare(t *testing.T) {
	if code, _, errb := run(t, "backup", "create"); code != 2 || !strings.Contains(errb, "unknown command") {
		t.Fatalf("backup: code=%d err=%q", code, errb)
	}
	for _, verb := range [][]string{{"export", "-slug", "x"}, {"export", "-out", "x.zip"}, {"import", "-slug", "x"}, {"import", "x.zip"}} {
		dir := filepath.Join(t.TempDir(), "never-made")
		cfg := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(cfg, []byte(`{"data_dir":"`+dir+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		args := append(append([]string{}, verb...), "-config", cfg)
		if verb[0] == "import" && verb[1] == "x.zip" {
			args = []string{"import", "x.zip", "-config", cfg}
		}
		if code, _, errb := run(t, args...); code != 2 || !strings.Contains(errb, "required") {
			t.Fatalf("%v: code=%d err=%q", verb, code, errb)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("%v made the data directory before it refused", verb)
		}
	}
}
