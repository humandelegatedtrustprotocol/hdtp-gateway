package node

// Telling contacts where to find you (SPEC §9.4, §10.1).
//
// A node's endpoint is not a detail it keeps to itself: contacts pinned a card
// carrying `X-PACT-ENDPOINT`, and if the owner changes the public URL — or the
// tunnel that produces it — every one of them is still calling the old address.
// PACT's answer is `update_contact`, the same tool key rotation uses.
//
// The signature is what makes it trustworthy. `update_contact` verifies a
// signature over the new card's fingerprint against the key the peer already
// pinned. On an endpoint change the fingerprint is unchanged, so the node signs
// its OWN current fingerprint: proof that whoever sent the new card holds the
// pinned key. No new protocol surface, and an attacker who cannot sign cannot
// move a contact's endpoint.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
)

// Announcer delivers one update_contact call. The default reaches the peer over
// the outbound client; tests substitute their own.
type Announcer func(ctx context.Context, accountID string, peer outbound.Peer, card, sigB64 string) error

// AnnounceEndpointChange tells every active contact of every account the node's
// current card. It reports how many calls landed and how many did not: a peer
// that is offline is a fact to surface, not an error to abort on — the owner's
// endpoint really did change, and the contacts that did hear are correct.
func (n *Node) AnnounceEndpointChange(ctx context.Context, send Announcer) (done, failed int, err error) {
	if send == nil {
		send = n.deliverUpdateContact
	}
	n.mu.RLock()
	accounts := make([]*account, 0, len(n.accounts))
	for _, a := range n.accounts {
		accounts = append(accounts, a)
	}
	n.mu.RUnlock()

	for _, a := range accounts {
		card, cerr := n.Card(ctx, a.rec.ID)
		if cerr != nil {
			return done, failed, cerr
		}
		// The proof: our own fingerprint, signed by the key contacts pinned.
		sig, serr := identity.SignBytes(a.kp, []byte(a.kp.Fingerprint))
		if serr != nil {
			return done, failed, serr
		}
		sigB64 := base64.RawURLEncoding.EncodeToString(sig)

		list, lerr := n.opts.Store.ListContacts(ctx, a.rec.ID)
		if lerr != nil {
			return done, failed, lerr
		}
		for _, c := range list {
			if c.Status != "active" {
				continue
			}
			peer, perr := peerFor(c)
			if perr != nil {
				failed++
				n.auditFor(a.rec.ID, "endpoint_announce", "contact:"+c.Fingerprint, "unreachable")
				continue
			}
			if err := send(ctx, a.rec.ID, peer, card, sigB64); err != nil {
				failed++
				n.auditFor(a.rec.ID, "endpoint_announce", "contact:"+c.Fingerprint, "failed")
				continue
			}
			done++
			n.auditFor(a.rec.ID, "endpoint_announce", "contact:"+c.Fingerprint, "ok")
		}
	}
	return done, failed, nil
}

// peerFor reads a contact's endpoint from the card it gave us.
func peerFor(c store.Contact) (outbound.Peer, error) {
	card, err := contacts.ParseCard(c.Card)
	if err != nil || card.Endpoint == "" {
		return outbound.Peer{}, fmt.Errorf("contact %s has no endpoint on file", c.Fingerprint)
	}
	return outbound.Peer{Endpoint: card.Endpoint, Fingerprint: c.Fingerprint, Seal: card.Seal}, nil
}

// deliverUpdateContact is the real call, presenting the account's identity
// certificate — the contact recognizes us by the key it pinned.
func (n *Node) deliverUpdateContact(ctx context.Context, accountID string, peer outbound.Peer, card, sigB64 string) error {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil {
		return fmt.Errorf("node: unknown account %s", accountID)
	}
	der, err := identity.SelfSignedCert(a.kp, a.rec.Slug)
	if err != nil {
		return err
	}
	// nil Roots = the system roots. A rotation has to reach contacts wherever they
	// are, including behind an edge that terminates TLS (SPEC §10.3).
	client := &outbound.Client{
		Keypair: a.kp,
		Cert:    tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.kp.Signer},
	}
	// The seal decision is one rule in one place (outbound.Client.Call): this
	// site forced Plaintext and so every seal-required contact refused the
	// announcement locally — the peers who most needed the new endpoint were
	// exactly the ones never told. The pinned SPKI makes sealing possible; a
	// contact holding only a fingerprint (mid-rotation) degrades the way Call
	// documents.
	var spki []byte
	if c, cerr := n.opts.Store.GetContact(ctx, accountID, peer.Fingerprint); cerr == nil {
		spki = c.SPKI
	}
	res, err := client.Call(ctx, peer, spki, "update_contact",
		map[string]any{"card": card, "sig": sigB64}, newCallID())
	if err != nil {
		return err
	}
	if res.IsError {
		return fmt.Errorf("peer refused update_contact")
	}
	return nil
}
