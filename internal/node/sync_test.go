package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/testid"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// The sync sweep's whole trust decision: a re-fetched card is applied only
// when it still names the pinned key AND its signature verifies under it.
// Sync must never be a way to move a pin — that is update_contact's job, with
// its old-key signature.
// verifySyncedCard is the whole trust decision of the periodic sync: a re-fetched
// card must still name the pinned ROOT, and its signature must verify under the key
// this node holds for that contact.
//
// It used to be checked against 1.x cards, where the card's X-PACT-KEY and the
// pinned key were one value. They are two now — the pin is the root, the signing
// key is the leaf's — and a card that confuses them is exactly what a compromised
// endpoint would send.
func TestVerifySyncedCard(t *testing.T) {
	w := testid.NewWallet(t, "Peer")
	h := w.Issue(t, "https://p.example/mcp")
	card := h.Card("Peer", "required")
	sign := func(text string) string {
		sig, err := pactidentity.SignDetached(h.Key, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, card, sign(card)); err != nil {
		t.Fatalf("a valid card was refused: %v", err)
	}

	// A card from a DIFFERENT root is refused even with a valid signature by the
	// pinned key — the exact move a compromised endpoint would try.
	other := testid.NewWallet(t, "Peer")
	swapped := other.Issue(t, "https://p.example/mcp").Card("Peer", "required")
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, swapped, sign(swapped)); err == nil {
		t.Fatal("a root swap slid through sync")
	}

	// A tampered card fails the signature.
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, card+"X", sign(card)); err == nil {
		t.Fatal("a tampered card verified")
	}

	// A signature by anyone but the pinned key fails.
	foreign, err := pactidentity.SignDetached(other.Key, []byte(card))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, card, base64.RawURLEncoding.EncodeToString(foreign)); err == nil {
		t.Fatal("a foreign signature verified")
	}

	// Intake rules still apply: a card with no certificate at all is refused.
	bare := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Peer\r\nX-PACT-VERSION:2\r\nEND:VCARD\r\n"
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, bare, sign(bare)); err == nil {
		t.Fatal("a card with no certificate was accepted")
	}
}

// fillRootCert is how a pin made over a SEALED call gets the certificate of the root
// it names (F11). The chain travels once (PACT §13.2) and a sealed sender's chain is
// inside the ciphertext, so the pin kept a fingerprint; behind an edge no client
// certificate ever arrives to fill it either. `get_card` has carried the peer's
// [leaf, root] in its sealed answer all along and nothing read it.
//
// The pin NAMES the root, which is what makes reading it safe: the chain is validated
// against the pinned fingerprint, so a peer answering with somebody else's root — or
// with a root that did not issue the leaf beside it — is refused, not recorded.
func TestFillRootCertTakesOnlyThePinnedRoot(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	peer := testid.NewWallet(t, "Peer")
	host := peer.Issue(t, "https://p.example/mcp")
	stranger := testid.NewWallet(t, "Stranger")
	strangerHost := stranger.Issue(t, "https://s.example/mcp")

	// The pin as a sealed pairing leaves it: the root's name, and no certificate.
	pin, err := st.InsertContact(ctx, store.Contact{AccountID: acct.ID, Fingerprint: peer.Fpr,
		SPKI: host.Key.Public.SPKI, Status: "active", Protocol: 2, Endpoint: host.Endpoint, Leaf: host.LeafDER})
	if err != nil {
		t.Fatal(err)
	}
	if len(pin.RootCert) != 0 {
		t.Fatalf("the fixture already has a root certificate: %q", pin.RootCert)
	}

	n := &Node{opts: Options{Store: st}}
	b64 := func(chain [][]byte) []string {
		return []string{base64.RawURLEncoding.EncodeToString(chain[0]), base64.RawURLEncoding.EncodeToString(chain[1])}
	}
	read := func() []byte {
		c, gerr := st.GetContact(ctx, acct.ID, peer.Fpr)
		if gerr != nil {
			t.Fatal(gerr)
		}
		return c.RootCert
	}

	// A stranger's whole chain, internally valid and not this pin's root.
	n.fillRootCert(ctx, acct.ID, peer.Fpr, pin, b64(strangerHost.Chain))
	if len(read()) != 0 {
		t.Fatal("a root this pin does not name was recorded")
	}
	// The peer's leaf under the stranger's root: neither half belongs to the other.
	n.fillRootCert(ctx, acct.ID, peer.Fpr, pin, b64([][]byte{host.LeafDER, stranger.RootDER}))
	if len(read()) != 0 {
		t.Fatal("a root that did not issue the leaf beside it was recorded")
	}
	// Nonsense, and a chain that is not a chain.
	n.fillRootCert(ctx, acct.ID, peer.Fpr, pin, []string{"!!not base64!!", "!!!"})
	n.fillRootCert(ctx, acct.ID, peer.Fpr, pin, []string{base64.RawURLEncoding.EncodeToString(host.LeafDER)})
	if len(read()) != 0 {
		t.Fatal("a malformed answer was recorded")
	}

	// And the real one.
	n.fillRootCert(ctx, acct.ID, peer.Fpr, pin, b64(host.Chain))
	if got := read(); !bytes.Equal(got, peer.RootDER) {
		t.Fatalf("the pinned root's certificate was not stored: %d bytes, want %d", len(got), len(peer.RootDER))
	}

	// A pin that already holds one is left alone: the root of a pin cannot change,
	// so the stored certificate is the one that was checked when the pin was made.
	filled, err := st.GetContact(ctx, acct.ID, peer.Fpr)
	if err != nil {
		t.Fatal(err)
	}
	n.fillRootCert(ctx, acct.ID, peer.Fpr, filled, b64(strangerHost.Chain))
	if got := read(); !bytes.Equal(got, peer.RootDER) {
		t.Fatal("a stored root certificate was replaced")
	}
}
