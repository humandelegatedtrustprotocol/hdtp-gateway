// Package testid builds real HDTP identities for tests: a person's root, the
// leaf it issues to a host, and the card that carries that leaf.
//
// It exists because a card is a certificate. A test used to reach a peer's card in one
// line — `contacts.BuildCard(contacts.Card{Key: fpr, Endpoint: url})` — because a
// card was just a key and an address spelled out as properties. A card IS
// a certificate (HDTP §3), so the same line now needs a root, a host key, a leaf
// naming the endpoint, and a signature over the chain. Nine test files across six
// packages needed that, which is how a suite starts growing six slightly different
// wallets, so there is one here.
//
// Nothing in it is a shape invented for tests: every certificate comes from
// hdtp-identity's own builders, the same ones the wallet and the node use, so a
// test that passes here passed against the real certificate profile.
//
// The parameter is `testing.TB`, not `*testing.T`, so a fuzz target can build a real identity for
// its seed corpus — `*testing.F` is a TB too, and a corpus of documents that cannot verify teaches
// a fuzzer nothing (internal/cli/offer_fuzz_test.go).
package testid

import (
	"testing"
	"time"

	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Wallet is the person's side of HDTP §9: a root key, and the certificate for it.
type Wallet struct {
	// CN is the common name of the root and of every leaf it issues.
	CN string
	// Key is the root's private key; it signs the leaves.
	Key *hdtpidentity.PrivateKey
	// RootDER is the second certificate of every Chain this wallet issues.
	RootDER []byte
	// Fpr is the root fingerprint — the identity's name everywhere (HDTP §2).
	Fpr string
}

// NewWallet makes a person's root. Ed25519 by default, which is what a derived
// root is (HDTP §2.1); pass "p256" for the other curve.
func NewWallet(t testing.TB, cn string, alg ...string) *Wallet {
	t.Helper()
	a := "ed25519"
	if len(alg) > 0 && alg[0] != "" {
		a = alg[0]
	}
	key, err := hdtpidentity.GenerateKey(a)
	if err != nil {
		t.Fatalf("testid: root key: %v", err)
	}
	root, err := hdtpidentity.BuildRoot(hdtpidentity.RootOpts{
		CN: cn, Key: key, NotBefore: time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("testid: root certificate: %v", err)
	}
	return &Wallet{CN: cn, Key: key, RootDER: root, Fpr: hdtpidentity.Fingerprint(key.Public().SPKI)}
}

// Host is a host the root has issued to: its own key, its leaf, and the chain.
type Host struct {
	// Key is the host's own key, which the leaf certifies. It is nil on a Host made by IssueOver,
	// whose caller holds the key.
	Key *hdtpidentity.PrivateKey
	// LeafDER is the first certificate of Chain and the one Card carries.
	LeafDER []byte
	Chain   [][]byte // leaf then root, as HDTP §14.2 requires
	// Endpoint is the address the leaf names.
	Endpoint string
	// Kid is the leaf key's fingerprint — what a peer names in an envelope's `kid`.
	Kid string
	// RootFpr is the identity this host serves under: what a contact pins (HDTP §2).
	RootFpr string
}

// Issue gives a host a leaf for one endpoint, valid for a year.
func (w *Wallet) Issue(t testing.TB, endpoint string, alg ...string) *Host {
	t.Helper()
	a := "p256"
	if len(alg) > 0 && alg[0] != "" {
		a = alg[0]
	}
	hostKey, err := hdtpidentity.GenerateKey(a)
	if err != nil {
		t.Fatalf("testid: host key: %v", err)
	}
	now := time.Now()
	leaf, err := hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{
		CN: w.CN, RootCN: w.CN, RootKey: w.Key, HostPub: hostKey.Public(),
		URIs: []string{endpoint}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("testid: leaf for %s: %v", endpoint, err)
	}
	return &Host{
		Key: hostKey, LeafDER: leaf, Chain: [][]byte{leaf, w.RootDER},
		Endpoint: endpoint, Kid: hdtpidentity.Fingerprint(hostKey.Public().SPKI), RootFpr: w.Fpr,
	}
}

// Card renders the host's card (HDTP §3): the leaf, the version, the seal.
func (h *Host) Card(fn, seal string) string {
	card, err := hdtpidentity.EncodeCard(fn, h.LeafDER, seal, nil)
	if err != nil {
		panic("testid: " + err.Error()) // a test's own name, which carries no control character
	}
	return card
}

// Card is the one-liner most tests want: a whole identity, and its card.
func Card(t testing.TB, fn, endpoint, seal string) (card string, w *Wallet, h *Host) {
	t.Helper()
	w = NewWallet(t, fn)
	h = w.Issue(t, endpoint)
	return h.Card(fn, seal), w, h
}

// CardFor is the shortest form: a card for one name at one endpoint, with no seal
// policy. It is what a test that only needs "a valid card" should reach for.
func CardFor(t testing.TB, fn, endpoint string) string {
	t.Helper()
	card, _, _ := Card(t, fn, endpoint, "")
	return card
}

// IssueOver issues a leaf for an endpoint over a key the caller already holds —
// for a test whose account key exists before its certificate does, which is the
// ordinary order: `account create` then `account csr` then `install-leaf`.
func (w *Wallet) IssueOver(t testing.TB, endpoint string, hostSPKI []byte) *Host {
	t.Helper()
	pub, err := hdtpidentity.ParseSPKI(hostSPKI)
	if err != nil {
		t.Fatalf("testid: host key: %v", err)
	}
	now := time.Now()
	leaf, err := hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{
		CN: w.CN, RootCN: w.CN, RootKey: w.Key, HostPub: pub,
		URIs: []string{endpoint}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("testid: leaf for %s: %v", endpoint, err)
	}
	return &Host{
		LeafDER: leaf, Chain: [][]byte{leaf, w.RootDER}, Endpoint: endpoint,
		Kid: hdtpidentity.Fingerprint(hostSPKI), RootFpr: w.Fpr,
	}
}

// DER is the bytes a base64url string carries, read by the rule the identity core reads them with
// (hdtp-identity's DecodeB64url); a test that hands it a string that does not read fails there.
func DER(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hdtpidentity.DecodeB64url(s)
	if err != nil {
		t.Fatalf("not base64url: %q", s)
	}
	return b
}

// Root is a root certificate as the identity core reads one, for a wallet's IssueOpts.Root (the
// core issues under the certificate since 0.6.0, so a leaf can end with its root).
func Root(t testing.TB, der []byte) *hdtpidentity.Cert {
	t.Helper()
	c, err := hdtpidentity.Parse(der)
	if err != nil {
		t.Fatalf("testid: root certificate: %v", err)
	}
	return c
}
