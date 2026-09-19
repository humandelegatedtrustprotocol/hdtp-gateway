package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/testid"
)

// The two verbs end to end, and the recovery they are for. A node that has lost its master key
// cannot start: every leaf key is sealed under it. Under 2.0 that loses no identity — the root is
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
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: peer.Fpr, SPKI: ph.Key.Public.SPKI, Status: "active",
		Endpoint: ph.Endpoint, Leaf: ph.LeafDER, RootCert: peer.RootDER, DisplayName: "Bharat", Card: ph.Card("Bharat", "optional")}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// The master key is gone for good.
	if err := os.Remove(filepath.Join(old.dir, "keyring.key")); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "alice.pact-export")
	code, out, errb := run(t, "export", "-config", old.cfg, "-out", file)
	if code != 0 || !strings.Contains(out, "1 identity, 1 contact") || !strings.Contains(out, "nothing else") {
		t.Fatalf("export: code=%d out=%q err=%q", code, out, errb)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("an export is somebody's address book and mail, and must be 0600: %v %v", fi, err)
	}
	// It never replaces a file.
	if code, _, errb := run(t, "export", "-config", old.cfg, "-out", file); code == 0 {
		t.Fatalf("a second export overwrote the first: %q", errb)
	}

	fresh := newIDNode(t, "fresh")
	code, out, errb = run(t, "import", "-config", fresh.cfg, "-from", file)
	if code != 0 || !strings.Contains(out, "not served yet: alice") {
		t.Fatalf("import: code=%d out=%q err=%q", code, out, errb)
	}
	got := openStoreAt(t, fresh.dir)
	b, err := got.GetAccountBySlug(ctx, "alice")
	if err != nil || b.RootFingerprint != wallet.fingerprint() {
		t.Fatalf("the identity did not arrive as itself: %+v %v", b, err)
	}
	if sealed, _ := got.GetAccountSealedKey(ctx, b.ID); len(sealed) != 0 {
		t.Fatalf("an imported identity arrived holding %d bytes of key", len(sealed))
	}
	if c, err := got.GetContact(ctx, b.ID, peer.Fpr); err != nil || c.Endpoint != ph.Endpoint {
		t.Fatalf("the contact did not arrive: %+v %v", c, err)
	}
	got.Close()
	// And the SAME wallet certifies the new home. It has no ledger, so it is a move.
	res := wallet.certifyUnder(t, fresh, "alice", identity.PurposeMove, endpoint, now.Add(time.Minute))
	if res.RootFingerprint != wallet.fingerprint() || !res.Moved {
		t.Fatalf("the first leaf on the new host: %+v", res)
	}
	// A second import of the same identity is refused, and says nothing was written.
	if code, _, errb := run(t, "import", "-config", fresh.cfg, "-from", file); code == 0 || !strings.Contains(errb, "already on this node") || !strings.Contains(errb, "nothing was written") {
		t.Fatalf("a second import: code=%d err=%q", code, errb)
	}
}

// `backup` is not a command any more, and neither verb does anything when it is typed bare. The
// documentation lint runs every command bare; the first draft of `export` made the default data
// directory and migrated a store in it before it said what it was missing.
func TestTheExportVerbsCostNothingWhenTypedBare(t *testing.T) {
	if code, _, errb := run(t, "backup", "create"); code != 2 || !strings.Contains(errb, "unknown command") {
		t.Fatalf("backup: code=%d err=%q", code, errb)
	}
	for _, verb := range []string{"export", "import"} {
		dir := filepath.Join(t.TempDir(), "never-made")
		cfg := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(cfg, []byte(`{"data_dir":"`+dir+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, errb := run(t, verb, "-config", cfg); code != 2 || !strings.Contains(errb, "is required") {
			t.Fatalf("%s: code=%d err=%q", verb, code, errb)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("%s made the data directory before it refused", verb)
		}
	}
}
