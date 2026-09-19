package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// A leaf is the person's root entrusting THIS host, for one address, until one date. Its private
// key is the host's credential, not the person's data, so it never goes into a bundle: whoever
// held the bundle could otherwise speak as this host, from this address, until the leaf ran out.
//
// `backup create` used to copy the whole database — both `key_sealed` columns — beside the master
// key that unseals them. Every backup was a complete credential.
//
// Two assertions, and the second is the one that matters. Reading the columns back proves the
// UPDATE ran. It does not prove the keys are gone: SQLite leaves a deleted value in the file's
// free pages until the file is rebuilt, and the bundle carries the master key right beside it. So
// the raw bytes of the archived database are searched for the key material itself.
func TestABackupBundleCarriesNoLeafKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "data")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := run(t, "migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate: %s", errb)
	}
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	// Recognisable, and LARGE on purpose. This driver runs with `secure_delete` off, so a value
	// set to NULL stays in the file. A small one is often compacted away when its page is
	// defragmented — an accident, not a guarantee — but one that spills to overflow pages is
	// released to the freelist intact, and only a rebuild drops it. With keys this size the test
	// FAILS if the bundle is made from the stripped copy without rebuilding it (checked by doing
	// exactly that), which is what makes it a test of the rebuild and not only of the UPDATE.
	accountKey := bytes.Repeat([]byte("ACCOUNT-LEAF-KEY-"), 600)
	ledgerKey := bytes.Repeat([]byte("SUPERSEDED-LEAF-KEY-"), 600)
	if err := st.SetAccountKey(ctx, a.ID, "sha256:cur", accountKey); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:old", Leaf: []byte("leaf-der"), KeySealed: ledgerKey,
		NotBefore: 1, NotAfter: 9, State: "superseded", Endpoint: "https://me.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// The master key is part of a same-host bundle — it also seals settings and integration
	// credentials — which is exactly why a leaf key beside it would be recoverable.
	if _, err := core.OpenKeyring(filepath.Join(dataDir, "keyring.key"), func(string) (string, bool) { return "", false }); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(dir, "backup.tar.gz")
	if code, out, errb := run(t, "backup", "create", "-config", cfgPath, "-out", archive); code != 0 {
		t.Fatalf("create: code=%d out=%q err=%q", code, out, errb)
	}

	// Pull the database out of the bundle, exactly as it was archived.
	fh, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var dbBytes []byte
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Clean(h.Name) == backupDB {
			if dbBytes, err = io.ReadAll(tr); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(dbBytes) == 0 {
		t.Fatal("the bundle carries no database")
	}

	// 1. The raw file. This is the assertion a column read cannot stand in for.
	//
	// A FRAGMENT is searched for, not the whole key. A value this size is split across overflow
	// pages, each with its own four-byte header, so the key never appears in the file as one
	// contiguous run even when every byte of it is there — the first draft of this test looked
	// for the whole thing and passed against a bundle that still held the key.
	if bytes.Contains(dbBytes, accountKey[:64]) {
		t.Fatal("the current leaf's private key is in the archived database's bytes")
	}
	if bytes.Contains(dbBytes, ledgerKey[:64]) {
		t.Fatal("a superseded leaf's private key is in the archived database's bytes — NULLed in its column, still on the page")
	}

	// 2. The rows: the ledger travels, as former leaves, and the keys do not.
	extracted := filepath.Join(dir, "extracted.db")
	if err := os.WriteFile(extracted, dbBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := store.OpenSQLite(extracted)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if k, _ := got.GetAccountSealedKey(ctx, a.ID); len(k) != 0 {
		t.Fatalf("the archived account still holds %d bytes of key", len(k))
	}
	leaves, err := got.ListLeaves(ctx, a.ID)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("the ledger row should travel: %d rows, %v", len(leaves), err)
	}
	if len(leaves[0].KeySealed) != 0 || leaves[0].State != "former" {
		t.Fatalf("the archived leaf kept its key or its standing: key=%d bytes, state=%q", len(leaves[0].KeySealed), leaves[0].State)
	}

	// And the LIVE node is untouched: making a backup must not cost it its own keys.
	live, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if k, _ := live.GetAccountSealedKey(ctx, a.ID); !bytes.Equal(k, accountKey) {
		t.Fatal("taking a backup stripped the live node's own key")
	}
}

// The other door. A bundle made before 2026-09-19 — or by hand, or by anything that is not this
// binary — was a copy of the whole database, leaf keys and all, beside the master key that opens
// them. Not making such a bundle is half the rule; not TAKING one is the other half, and it has to
// hold in the mode that trusts the archive most: `-same-node`, where the master key is welcome.
//
// So this builds exactly that bundle — the live database file as it stands, unstripped, with the
// keyring beside it — and restores it as the operator's own.
func TestASameNodeRestoreOfAnOlderBundleStillBringsNoLeafKey(t *testing.T) {
	src := newIDNode(t, "src")
	ctx := context.Background()
	st := openStoreAt(t, src.dir)
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountKey(ctx, a.ID, "sha256:cur", []byte("an-account-key-sealed-by-an-older-build")); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:cur", Leaf: []byte("leaf-der"), KeySealed: []byte("a-leaf-key-sealed-by-an-older-build"),
		NotBefore: 1, NotAfter: 9, State: "current", Endpoint: "https://me.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	_ = openKeyringAt(t, src.dir)

	archive := filepath.Join(src.dir, "older.tar.gz")
	fh, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(fh)
	tw := tar.NewWriter(gz)
	add := func(name string, body []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), ModTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	add(backupManifest, []byte(`{"version":1,"store_engine":"sqlite","has_master_key":true,"tool":"pact-gateway"}`))
	for _, name := range []string{backupDB, backupKey} {
		body, err := os.ReadFile(filepath.Join(src.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		add(name, body)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	fh.Close()

	own := newIDNode(t, "own")
	if code, out, errb := run(t, "backup", "restore", "-config", own.cfg, "-from", archive, "-yes", "-same-node"); code != 0 {
		t.Fatalf("restore: code=%d out=%q err=%q", code, out, errb)
	}
	got := openStoreAt(t, own.dir)
	acct, err := got.GetAccountBySlug(ctx, "me")
	if err != nil {
		t.Fatalf("the account's data must arrive: %v", err)
	}
	if k, _ := got.GetAccountSealedKey(ctx, acct.ID); len(k) != 0 {
		t.Fatalf("an older bundle's account key was taken in: %d bytes", len(k))
	}
	for _, l := range mustLeaves(t, got, acct.ID) {
		if len(l.KeySealed) != 0 || l.State != "former" {
			t.Fatalf("an older bundle's leaf key was taken in, or its row kept its standing: %+v", l)
		}
	}
}
