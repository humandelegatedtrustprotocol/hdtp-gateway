package ingress

import (
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
	if _, ok := r2.ByFingerprint("sha256:abc"); !ok {
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
