package ingress

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// AC (P10-06a): a pairing survives a restart.
//
// The registry was in memory, so every paired node became unknown after a
// restart, its subdomain routed nowhere, and the owner had to re-pair by hand.
func TestPairingsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	r1, err := NewFileRegistry(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := Node{
		Fingerprint: "sha256:abc", SPKI: []byte{1, 2, 3}, Subdomain: "alice",
		Mode: ModePassthrough, Secret: "dp-secret", PairedAt: time.Unix(1756000000, 0),
	}
	if err := r1.Put(n); err != nil {
		t.Fatal(err)
	}

	// A fresh process reads the same book.
	r2, err := NewFileRegistry(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.BySubdomain("alice")
	if !ok {
		t.Fatal("the pairing did not survive a restart")
	}
	if got.Fingerprint != n.Fingerprint || got.Secret != n.Secret || string(got.SPKI) != string(n.SPKI) {
		t.Fatalf("the pairing came back changed: %+v", got)
	}
	if _, ok := r2.ByCredential("sha256:abc", "dp-secret"); !ok {
		t.Fatal("fingerprint lookup lost across the restart")
	}

	// The file carries a data-plane credential, so it must not be world-readable.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("the pairing book is readable by others: %v", perm)
	}

	// Tokens are deliberately NOT persisted: a single-use credential that
	// outlives the process is a file someone can steal for no benefit.
	tok, err := r1.MintToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r3, _ := NewFileRegistry(path, nil)
	if r3.ConsumeToken(tok) {
		t.Fatal("a pairing token survived a restart")
	}
}

// A pairing the file registry could not write is refused 503 unavailable, with a JSON body, and is
// not routed: the in-memory book changed before the disk did, so the ingress served a pairing its
// next start would not know, and the handler answered the OS's error text as a conflict. The
// control: a takeover refused as a conflict leaves the book on disk readable at the next start.
func TestAPairingThatCannotBeWrittenIsRefusedAndNotRouted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "book")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nodes.json")
	reg, err := NewFileRegistry(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := pairServer(t, reg)
	_, first := keypairCert(t, "first")
	tok, _ := reg.MintToken(time.Minute)
	if _, _, err := Pair(nil, srv.URL+"/pair", first, "", PairRequest{Token: tok, Subdomain: "alice", Mode: ModePassthrough}); err != nil {
		t.Fatal(err)
	}
	_, other := keypairCert(t, "other")

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	status, body := pairRefusal(t, srv, reg, other, "bob")
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusServiceUnavailable || len(body) != 1 || body["code"] != "unavailable" {
		t.Errorf("an unwritable book: %d %v, want 503 {\"code\":\"unavailable\"}", status, body)
	}
	if _, ok := reg.BySubdomain("bob"); ok {
		t.Error("a pairing that is not on disk is routed")
	}

	if status, body := pairRefusal(t, srv, reg, other, "alice"); status != http.StatusConflict || body["code"] != "conflict" {
		t.Fatalf("a takeover: %d %v, want 409 conflict", status, body)
	}
	again, err := NewFileRegistry(path, nil)
	if err != nil {
		t.Fatalf("the book a refused takeover left does not load: %v", err)
	}
	if n, _ := again.BySubdomain("alice"); n.Fingerprint == "" {
		t.Fatal("the book lost alice")
	}
}

// Removing a pairing from the file registry survives a restart, and a removal that cannot be
// written keeps the pairing in memory as well as on disk.
func TestARemovedPairingStaysRemovedAcrossARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "book")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nodes.json")
	reg, err := NewFileRegistry(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"alice", "bob"} {
		if err := reg.Put(Node{Fingerprint: "sha256:" + sub, Subdomain: sub, Mode: ModePassthrough, Secret: "s-" + sub}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	err = reg.Remove("bob")
	if cerr := os.Chmod(dir, 0o700); cerr != nil {
		t.Fatal(cerr)
	}
	if err == nil {
		t.Fatal("a removal that could not be written reported success")
	}
	if _, ok := reg.BySubdomain("bob"); !ok {
		t.Fatal("a removal that could not be written forgot bob in memory")
	}
	if err := reg.Remove("bob"); err != nil {
		t.Fatal(err)
	}
	again, err := NewFileRegistry(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.BySubdomain("bob"); ok {
		t.Error("a removed pairing came back after a restart")
	}
	if _, ok := again.BySubdomain("alice"); !ok {
		t.Error("removing bob lost alice")
	}
	if err := again.Remove("carol"); !errors.Is(err, ErrNotPaired) {
		t.Errorf("removing a subdomain never paired: %v, want ErrNotPaired", err)
	}
}
