package identity

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// leaf20 mints a root and a leaf for kp: what a wallet would have issued.
func leaf20(t *testing.T, kp *Keypair, endpoint string) (leaf, root []byte, rootKey *pactidentity.PrivateKey) {
	t.Helper()
	rootKey, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	root, err = pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Alice", Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	lib, err := ToLib(kp)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = pactidentity.BuildLeaf(pactidentity.LeafOpts{CN: "Alice", RootCN: "Alice", RootKey: rootKey, HostPub: lib.Public, Endpoint: endpoint,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(200 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return leaf, root, rootKey
}

// TestIdentityBackup20CarriesTheLeafAndNeverTheRoot: version 2 seals the LEAF
// key with its leaf and the root certificate (PACT §9); the key comes back
// with the chain attached, and the document holds no root key anywhere.
func TestIdentityBackup20CarriesTheLeafAndNeverTheRoot(t *testing.T) {
	kp, _ := Generate(AlgoEd25519)
	leaf, root, rootKey := leaf20(t, kp, "https://agent.alice.example/mcp")
	doc, err := ExportIdentity20(kp, "alice", "Alice", "ed25519", "a long enough passphrase", leaf, root)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != BackupVersion20 || doc.Endpoint != "https://agent.alice.example/mcp" || doc.RootFingerprint != pactidentity.Fingerprint(rootKey.Public.SPKI) {
		t.Fatalf("document: %+v", doc)
	}
	raw, _ := MarshalBackup(doc)
	if rootPKCS8 := base64.RawURLEncoding.EncodeToString(mustPKCS8(t, rootKey)); containsBytes(raw, rootPKCS8) {
		t.Fatal("the root key must not be in the file")
	}
	got, err := OpenIdentity(doc, "a long enough passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != kp.Fingerprint || got.Protocol != 2 || string(got.Leaf) != string(leaf) || string(got.Root) != string(root) {
		t.Fatalf("the key must come back with its chain: %+v", got)
	}
	// A leaf swapped into the file is additional data that no longer matches.
	other, _ := Generate(AlgoEd25519)
	otherLeaf, _, _ := leaf20(t, other, "https://agent.alice.example/mcp")
	tampered := doc
	tampered.Leaf = base64.RawURLEncoding.EncodeToString(otherLeaf)
	if _, err := OpenIdentity(tampered, "a long enough passphrase"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("a swapped leaf must fail to open: %v", err)
	}
}

// TestIdentityBackupRefusesARootKey: a file whose sealed key is the root's is
// a wallet's secret dressed as a host's; it is refused however it was made.
func TestIdentityBackupRefusesARootKey(t *testing.T) {
	kp, _ := Generate(AlgoEd25519)
	leaf, root, rootKey := leaf20(t, kp, "https://agent.alice.example/mcp")
	rootKP, err := FromLib(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	// Seal the ROOT key, claiming the root's own fingerprint, beside the chain.
	doc, err := exportWith(rootKP, "alice", "Alice", "ed25519", "a long enough passphrase", func(b *IdentityBackup) {
		b.Version = BackupVersion20
		b.Leaf, b.Root = base64.RawURLEncoding.EncodeToString(leaf), base64.RawURLEncoding.EncodeToString(root)
		b.RootFingerprint, b.Endpoint = pactidentity.Fingerprint(rootKey.Public.SPKI), "https://agent.alice.example/mcp"
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenIdentity(doc, "a long enough passphrase")
	if err == nil {
		t.Fatal("a root key must be refused")
	}
	// It is refused as "not the leaf's" before it is even recognised as the
	// root's; either way it never becomes a keypair.
	if !errors.Is(err, ErrRootKey) && err.Error() != "identity: the backup's key is not the leaf's" {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func mustPKCS8(t *testing.T, k *pactidentity.PrivateKey) []byte {
	t.Helper()
	kp, err := FromLib(k)
	if err != nil {
		t.Fatal(err)
	}
	der, err := MarshalPKCS8(kp)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func containsBytes(hay []byte, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && (string(hay) != "" && indexOf(string(hay), needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
