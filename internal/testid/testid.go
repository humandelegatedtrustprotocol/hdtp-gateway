// Package testid builds real PACT 2.0 identities for tests: a person's root, the
// leaf it issues to a host, and the card that carries that leaf.
//
// It exists because PACT 1.x is gone. A test used to reach a peer's card in one
// line — `contacts.BuildCard(contacts.Card{Key: fpr, Endpoint: url})` — because a
// 1.x card was just a key and an address spelled out as properties. A 2.0 card IS
// a certificate (PACT §3), so the same line now needs a root, a host key, a leaf
// naming the endpoint, and a signature over the chain. Nine test files across six
// packages needed that, which is how a suite starts growing six slightly different
// wallets, so there is one here.
//
// Nothing in it is a shape invented for tests: every certificate comes from
// pact-identity's own builders, the same ones the wallet and the node use, so a
// test that passes here passed against the real certificate profile.
package testid

import (
	"testing"
	"time"

	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// Wallet is the person's side of PACT §9: a root key, and the certificate for it.
type Wallet struct {
	CN      string
	Key     *pactidentity.PrivateKey
	RootDER []byte
	// Fpr is the root fingerprint — the identity's name everywhere (PACT §2).
	Fpr string
}

// NewWallet makes a person's root. Ed25519 by default, which is what a derived
// root is (PACT §2.1); pass "p256" for the other curve.
func NewWallet(t *testing.T, cn string, alg ...string) *Wallet {
	t.Helper()
	a := "ed25519"
	if len(alg) > 0 && alg[0] != "" {
		a = alg[0]
	}
	key, err := pactidentity.GenerateKey(a)
	if err != nil {
		t.Fatalf("testid: root key: %v", err)
	}
	root, err := pactidentity.BuildRoot(pactidentity.RootOpts{
		CN: cn, Key: key, NotBefore: time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("testid: root certificate: %v", err)
	}
	return &Wallet{CN: cn, Key: key, RootDER: root, Fpr: pactidentity.Fingerprint(key.Public.SPKI)}
}

// Host is a host the root has issued to: its own key, its leaf, and the chain.
type Host struct {
	Key      *pactidentity.PrivateKey
	LeafDER  []byte
	Chain    [][]byte // leaf then root, as PACT §14.2 requires
	Endpoint string
	// Kid is the leaf key's fingerprint — what a peer names in an envelope's `kid`.
	Kid string
	// RootFpr is the identity this host serves under: what a contact pins (PACT §2).
	RootFpr string
}

// Issue gives a host a leaf for one endpoint, valid for a year.
func (w *Wallet) Issue(t *testing.T, endpoint string, alg ...string) *Host {
	t.Helper()
	a := "p256"
	if len(alg) > 0 && alg[0] != "" {
		a = alg[0]
	}
	hostKey, err := pactidentity.GenerateKey(a)
	if err != nil {
		t.Fatalf("testid: host key: %v", err)
	}
	now := time.Now()
	leaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: w.CN, RootCN: w.CN, RootKey: w.Key, HostPub: hostKey.Public,
		URIs: []string{endpoint}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("testid: leaf for %s: %v", endpoint, err)
	}
	return &Host{
		Key: hostKey, LeafDER: leaf, Chain: [][]byte{leaf, w.RootDER},
		Endpoint: endpoint, Kid: pactidentity.Fingerprint(hostKey.Public.SPKI), RootFpr: w.Fpr,
	}
}

// Card renders the host's card (PACT §3): the leaf, the version, the seal.
func (h *Host) Card(fn, seal string) string {
	return pactidentity.EncodeCard(fn, h.LeafDER, seal, nil)
}

// Card is the one-liner most tests want: a whole identity, and its card.
func Card(t *testing.T, fn, endpoint, seal string) (card string, w *Wallet, h *Host) {
	t.Helper()
	w = NewWallet(t, fn)
	h = w.Issue(t, endpoint)
	return h.Card(fn, seal), w, h
}

// CardFor is the shortest form: a card for one name at one endpoint, with no seal
// policy. It is what a test that only needs "a valid card" should reach for.
func CardFor(t *testing.T, fn, endpoint string) string {
	t.Helper()
	card, _, _ := Card(t, fn, endpoint, "")
	return card
}

// IssueOver issues a leaf for an endpoint over a key the caller already holds —
// for a test whose account key exists before its certificate does, which is the
// ordinary order: `account create` then `account csr` then `install-leaf`.
func (w *Wallet) IssueOver(t *testing.T, endpoint string, hostSPKI []byte) *Host {
	t.Helper()
	pub, err := pactidentity.ParseSPKI(hostSPKI)
	if err != nil {
		t.Fatalf("testid: host key: %v", err)
	}
	now := time.Now()
	leaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: w.CN, RootCN: w.CN, RootKey: w.Key, HostPub: pub,
		URIs: []string{endpoint}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("testid: leaf for %s: %v", endpoint, err)
	}
	return &Host{
		LeafDER: leaf, Chain: [][]byte{leaf, w.RootDER}, Endpoint: endpoint,
		Kid: pactidentity.Fingerprint(hostSPKI), RootFpr: w.Fpr,
	}
}
