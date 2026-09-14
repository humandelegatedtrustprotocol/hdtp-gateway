package node

// PACT 2.0 on the outbound side (PACT §13.2, §14.3, Appendix C): which client
// speaks for this account toward a given contact, and what the client learns
// about the contact as it goes — that the chain has been sent, that a newer
// leaf was accepted — written back to the pin by the callbacks below.

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
)

// peerOf is the outbound view of a pinned contact. A 2.0 pin dials the
// endpoint the leaf names and is recognised by its root; a 1.x pin dials the
// card's endpoint and is recognised by its key.
func (n *Node) peerOf(accountID string, c store.Contact) (outbound.Peer, error) {
	card, err := contacts.ParseCard(c.Card)
	if c.Protocol == 2 {
		endpoint := c.Endpoint
		if endpoint == "" && err == nil {
			endpoint = card.Endpoint
		}
		if endpoint == "" || len(c.Leaf) == 0 {
			return outbound.Peer{}, fmt.Errorf("contact %s has no endpoint on file", c.Fingerprint)
		}
		seal := "required"
		if err == nil && card.Seal != "" {
			seal = card.Seal
		}
		ourKid := ""
		n.mu.RLock()
		if a := n.accounts[accountID]; a != nil {
			ourKid = a.kp.Fingerprint
		}
		n.mu.RUnlock()
		return outbound.Peer{
			Endpoint: endpoint, Fingerprint: c.Fingerprint, Seal: seal,
			Protocol: 2, Root: c.Fingerprint, Leaf: c.Leaf, ChainSeen: ourKid != "" && c.ChainSentKid == ourKid,
		}, nil
	}
	if err != nil || card.Endpoint == "" {
		return outbound.Peer{}, fmt.Errorf("contact %s has no endpoint on file", c.Fingerprint)
	}
	return outbound.Peer{Endpoint: card.Endpoint, Fingerprint: c.Fingerprint, Seal: card.Seal}, nil
}

// wire20 attaches to a client what it must be able to write back about the
// contacts it reaches (PACT §13.2, §14.3).
func (n *Node) wire20(accountID string, client *outbound.Client) *outbound.Client {
	client.Now = n.opts.Now
	client.DialContext = n.opts.DialContext
	client.OnChainSent = func(peer outbound.Peer) {
		n.mu.RLock()
		a := n.accounts[accountID]
		n.mu.RUnlock()
		if a == nil || peer.Protocol != 2 {
			return
		}
		_ = n.opts.Store.SetContactChainSentKid(context.Background(), accountID, peer.Root, a.kp.Fingerprint)
	}
	client.OnRepin = func(peer outbound.Peer, leaf, spki []byte) {
		if peer.Protocol != 2 {
			return
		}
		if err := n.opts.Store.RepinContactAddress(context.Background(), accountID, peer.Root, peer.Endpoint, leaf, spki, n.now().Unix()); err != nil {
			n.auditFor(accountID, "contact_renewal", "contact:"+peer.Root, "error")
			return
		}
		n.auditFor(accountID, "contact_renewal", "contact:"+peer.Root, "ok")
	}
	return client
}

// clientForContact is the client that speaks for an account toward one contact.
// PACT Appendix C row 2: after a renewal with a fresh key, a contact pinned as
// 1.x that has not yet re-pinned still recognises the OLD key — so until the
// rotation fan-out has reached it, the superseded key and its leaf are what
// we present there, as 1.2 §2 requires.
func (n *Node) clientForContact(ctx context.Context, accountID string, c store.Contact) (*outbound.Client, error) {
	client, err := n.OutboundClient(accountID)
	if err != nil {
		return nil, err
	}
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil || a.rec.Protocol != 2 || c.Protocol == 2 {
		return client, nil
	}
	if told, err := n.legacyContactTold(ctx, accountID, c.Fingerprint, a.kp.Fingerprint); err != nil || told {
		return client, nil
	}
	keys, err := n.idm.ActiveLeafKeypairs(ctx, accountID, n.now())
	if err != nil {
		return client, nil
	}
	for _, k := range keys {
		if k.Current || k.KP.Fingerprint == a.kp.Fingerprint {
			continue
		}
		// The most recently superseded key is the one a 1.x contact pinned.
		old := &outbound.Client{Keypair: k.KP, Cert: tlsCertOf(k.KP)}
		return n.wire20(accountID, old), nil
	}
	return client, nil
}

// legacyContactTold reports whether the rotation fan-out has reached a 1.x
// contact with our current key.
func (n *Node) legacyContactTold(ctx context.Context, accountID, contactFpr, currentKid string) (bool, error) {
	rows, err := n.opts.Store.ListRotationFanout(ctx, accountID)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.ContactFpr == contactFpr && r.NewFpr == currentKid {
			return r.Status == "done", nil
		}
	}
	// No row for this contact and this key: the fan-out never had to reach it
	// — the contact was added after the change and pinned the current key.
	return true, nil
}

// tlsCertOf is what a key presents on the wire: its chain for a 2.0 leaf key,
// a self-signed certificate otherwise.
func tlsCertOf(kp *identity.Keypair) tls.Certificate {
	if kp.Protocol == 2 && len(kp.Leaf) > 0 && len(kp.Root) > 0 {
		return tls.Certificate{Certificate: [][]byte{kp.Leaf, kp.Root}, PrivateKey: kp.Signer}
	}
	der, err := identity.SelfSignedCert(kp, "")
	if err != nil {
		return tls.Certificate{}
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
}

// hostOfEndpoint is the host a leaf's endpoint names, for SNI selection.
func hostOfEndpoint(endpoint string) string {
	s := strings.TrimPrefix(endpoint, "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
