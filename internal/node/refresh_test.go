package node

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// verifyRefreshedCard is the whole trust decision of a card refresh: a re-fetched card must
// still name the pinned ROOT, arrive with a chain that validates to that root at the pinned
// address, carry the leaf that chain proved, and be signed by that leaf's key.
//
// The pin and the signing key are two values — the pin is the root, the signing key is the
// leaf's — and a card that confuses them is exactly what a compromised endpoint would send.
func TestVerifyRefreshedCard(t *testing.T) {
	w := testid.NewWallet(t, "Peer")
	h := w.Issue(t, "https://p.example/mcp")
	card := h.Card("Peer", "required")
	now := time.Now()
	sign := func(key *pactidentity.PrivateKey, text string) string {
		sig, err := pactidentity.SignDetached(key, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(sig)
	}
	pin := store.Contact{
		Fingerprint: w.Fpr, SPKI: h.Key.Public().SPKI,
		Endpoint: h.Endpoint, Leaf: h.LeafDER,
	}

	// The ordinary case: the same leaf, answered again.
	renewed, err := verifyRefreshedCard(pin, h.Chain, card, sign(h.Key, card), now)
	if err != nil {
		t.Fatalf("a valid card was refused: %v", err)
	}
	if renewed != nil {
		t.Fatal("an unchanged leaf was reported as a renewal")
	}

	// A card from a DIFFERENT root is refused — the move a compromised endpoint would try.
	other := testid.NewWallet(t, "Peer")
	oh := other.Issue(t, "https://p.example/mcp")
	swapped := oh.Card("Peer", "required")
	if _, err := verifyRefreshedCard(pin, oh.Chain, swapped, sign(oh.Key, swapped), now); err == nil {
		t.Fatal("a root swap slid through a refresh")
	}

	// A tampered card fails the signature; so does a signature by anyone else.
	if _, err := verifyRefreshedCard(pin, h.Chain, card+"X", sign(h.Key, card), now); err == nil {
		t.Fatal("a tampered card verified")
	}
	if _, err := verifyRefreshedCard(pin, h.Chain, card, sign(other.Key, card), now); err == nil {
		t.Fatal("a foreign signature verified")
	}

	// No chain, no refresh. PACT §6.1: `get_card` answers "always the chain". This used to fall
	// back to the pinned leaf's key when the answer carried none, which made the chain something
	// the ANSWERER could leave out — and with it the two checks that make a refresh safe to act
	// on, the root and the address. Whoever answers at the pinned endpoint chooses what is in the
	// answer, so a path taken when something is missing is a path they choose.
	if _, err := verifyRefreshedCard(pin, nil, card, sign(h.Key, card), now); err == nil {
		t.Fatal("an answer with no chain was accepted on the strength of the pinned key alone")
	}
	if _, err := verifyRefreshedCard(pin, h.Chain[:1], card, sign(h.Key, card), now); err == nil {
		t.Fatal("a one-certificate chain was accepted")
	}

	// The card must carry the leaf the chain proved. Signed by the right key is not enough: the
	// same host key can sign a card that embeds some OTHER certificate — here a leaf the same
	// root issued for another address — and that card would be stored, shown and re-shared as
	// this contact's. `update_contact` has refused this since 2.0; the refresh never checked.
	elsewhere := w.Issue(t, "https://elsewhere.example/mcp")
	wrongCert := elsewhere.Card("Peer", "required")
	if _, err := verifyRefreshedCard(pin, h.Chain, wrongCert, sign(h.Key, wrongCert), now); err == nil {
		t.Fatal("a card carrying another certificate than the proven leaf was accepted")
	}

	// Intake rules still apply: a card with no certificate at all is refused.
	bare := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Peer\r\nX-PACT-VERSION:2\r\nEND:VCARD\r\n"
	if _, err := verifyRefreshedCard(pin, h.Chain, bare, sign(h.Key, bare), now); err == nil {
		t.Fatal("a card with no certificate was accepted")
	}
}

// H17: a refresh could not learn a renewal.
//
// The card was checked under the pinned LEAF key, and a peer that has renewed signs with
// its new one — so the honest case came back "the card signature does not verify under the
// pinned key" and was audited as though the endpoint were compromised. The rule being
// enforced ("key changes go through update_contact") is the key-pinned generation's, where
// a successor had to be signed by its predecessor. Under 2.0 the root's signature is the
// authorization: PACT §2, "because the endpoint is unchanged it needs no one's approval to
// accept it."
//
// The other half of this test is the reason the fix is not one line: a chain that validates
// to the pinned root at a DIFFERENT address must still be refused, or a refresh becomes an
// address follow — §5.3's decision taken by a pull.
func TestARefreshLearnsARenewalAndNeverAnAddress(t *testing.T) {
	w := testid.NewWallet(t, "Peer")
	h := w.Issue(t, "https://p.example/mcp")
	now := time.Now()
	sign := func(key *pactidentity.PrivateKey, text string) string {
		sig, err := pactidentity.SignDetached(key, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(sig)
	}
	pin := store.Contact{
		Fingerprint: w.Fpr, SPKI: h.Key.Public().SPKI,
		Endpoint: h.Endpoint, Leaf: h.LeafDER,
	}
	// A renewal: the same root, the same address, a fresh key, a later notBefore.
	fresh, err := pactidentity.GenerateKey("p256")
	if err != nil {
		t.Fatal(err)
	}
	renewLeaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: w.CN, RootCN: w.CN, RootKey: w.Key, HostPub: fresh.Public(),
		URIs: []string{h.Endpoint}, NotBefore: now.Add(time.Hour), NotAfter: now.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	renewChain := [][]byte{renewLeaf, w.RootDER}
	renewCard := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Peer\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:" +
		base64.RawURLEncoding.EncodeToString(renewLeaf) + "\r\nX-PACT-SEAL:required\r\nEND:VCARD\r\n"

	got, err := verifyRefreshedCard(pin, renewChain, renewCard, sign(fresh, renewCard), now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("a renewal signed by the pinned root was refused: %v", err)
	}
	if got == nil {
		t.Fatal("a renewal was accepted but not reported, so the pin would never move")
	}
	if !bytes.Equal(got.Leaf, renewLeaf) || !bytes.Equal(got.SPKI, fresh.Public().SPKI) {
		t.Fatal("the renewal reported a leaf or key that is not the one that validated")
	}

	// And the proof that this case really was broken, kept so it cannot quietly return: the
	// old decision verified the card under the PINNED leaf key, and a renewal's card is
	// signed by the fresh one. That check fails — which is the refusal H17 describes.
	pinnedPub, err := x509.ParsePKIXPublicKey(pin.SPKI)
	if err != nil {
		t.Fatal(err)
	}
	renewSig, err := base64.RawURLEncoding.DecodeString(sign(fresh, renewCard))
	if err != nil {
		t.Fatal(err)
	}
	if identity.VerifyBytes(pinnedPub, []byte(renewCard), renewSig) {
		t.Fatal("a renewal's card verified under the superseded key, so this test proves nothing")
	}

	// The SAME chain at another address: valid, signed by the pinned root, and refused,
	// because where a contact answers is §5.3's decision and not a refresh's.
	elsewhereLeaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: w.CN, RootCN: w.CN, RootKey: w.Key, HostPub: fresh.Public(),
		URIs: []string{"https://moved.example/mcp"}, NotBefore: now.Add(time.Hour), NotAfter: now.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	movedCard := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Peer\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:" +
		base64.RawURLEncoding.EncodeToString(elsewhereLeaf) + "\r\nX-PACT-SEAL:required\r\nEND:VCARD\r\n"
	if _, err := verifyRefreshedCard(pin, [][]byte{elsewhereLeaf, w.RootDER}, movedCard, sign(fresh, movedCard), now.Add(2*time.Hour)); err == nil {
		t.Fatal("a poll followed a contact to a new address, which is §5.3's decision")
	}

	// An OLDER leaf proves nothing (§14.3), even under the right root at the right address.
	oldLeaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: w.CN, RootCN: w.CN, RootKey: w.Key, HostPub: fresh.Public(),
		URIs: []string{h.Endpoint}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldCard := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Peer\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:" +
		base64.RawURLEncoding.EncodeToString(oldLeaf) + "\r\nX-PACT-SEAL:required\r\nEND:VCARD\r\n"
	if _, err := verifyRefreshedCard(pin, [][]byte{oldLeaf, w.RootDER}, oldCard, sign(fresh, oldCard), now.Add(2*time.Hour)); err == nil {
		t.Fatal("a superseded leaf was accepted from a poll")
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
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "refresh.db"))
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
		SPKI: host.Key.Public().SPKI, Status: "active", Endpoint: host.Endpoint, Leaf: host.LeafDER})
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
