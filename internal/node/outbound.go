package node

// PACT 2.0 on the outbound side (PACT §13.2, §14.3, Appendix C): which client
// speaks for this account toward a given contact, and what the client learns
// about the contact as it goes — that the chain has been sent, that a newer
// leaf was accepted — written back to the pin by the callbacks below.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
)

// peerOf is the outbound view of a pinned contact: it dials the endpoint the pinned leaf names
// and is recognised by its root (PACT §2). A contact with no leaf on file cannot be dialled —
// there is no key-pinned kind of contact to fall back to, and the branch that built one from a
// card's endpoint went with the column that selected it.
func (n *Node) peerOf(accountID string, c store.Contact) (outbound.Peer, error) {
	card, err := contacts.ParseCard(c.Card)
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
		Endpoint: endpoint, Seal: seal,
		Root: c.Fingerprint, Leaf: c.Leaf, ChainSeen: ourKid != "" && c.ChainSentKid == ourKid,
	}, nil
}

// wireClient attaches to a client what it must be able to write back about the
// contacts it reaches (PACT §13.2, §14.3).
func (n *Node) wireClient(accountID string, client *outbound.Client) *outbound.Client {
	client.Now = n.opts.Now
	client.DialContext = n.opts.DialContext
	client.OnChainSent = func(peer outbound.Peer) {
		n.mu.RLock()
		a := n.accounts[accountID]
		n.mu.RUnlock()
		if a == nil || !peer.Known() {
			return
		}
		_ = n.opts.Store.SetContactChainSentKid(context.Background(), accountID, peer.Root, a.kp.Fingerprint)
	}
	client.OnRepin = func(peer outbound.Peer, leaf, spki []byte) {
		if !peer.Known() {
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

// tlsCertOf is what a key presents on the wire: the chain — leaf then root —
// and nothing else.
//
// A key with no leaf presents NOTHING rather than a self-signed certificate of
// its own. The identity is the root (PACT §2); a lone certificate names no root,
// so a conforming peer reads it as no identity, and presenting one would make an
// outbound call anonymous while looking like it carried credentials. The only key
// here without a leaf is the account key a first install retires (§14.4) — kept
// so an envelope still sealed to it can be answered, never to speak under.
func tlsCertOf(kp *identity.Keypair) tls.Certificate {
	if kp == nil || len(kp.Leaf) == 0 || len(kp.Root) == 0 {
		return tls.Certificate{}
	}
	return tls.Certificate{Certificate: [][]byte{kp.Leaf, kp.Root}, PrivateKey: kp.Signer}
}

// hostOfEndpoint is the host a leaf's endpoint names, for SNI selection. The
// port is dropped: SNI carries a name, never a port, so a leaf naming
// `https://host:8443/…` must still be found by `host`.
func hostOfEndpoint(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	s := strings.TrimPrefix(endpoint, "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 && !strings.Contains(s[i:], "]") {
		s = s[:i]
	}
	return strings.Trim(s, "[]")
}
