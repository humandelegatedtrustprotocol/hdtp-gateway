package node

// HDTP 1.0 on the outbound side (HDTP §13.2, §14.3, Appendix C): which client
// speaks for this account toward a given contact, and what the client learns
// about the contact as it goes — that the chain has been sent, that a newer
// leaf was accepted — written back to the pin by the callbacks below.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
)

// PeerOf is the outbound view of a pinned contact: it dials the endpoint the pinned leaf names
// and is recognised by its root (HDTP §2). A contact with no leaf on file cannot be dialled —
// there is no key-pinned kind of contact to fall back to, and the branch that built one from a
// card's endpoint went with the column that selected it.
//
// Whether the call is sealed is the contact's card's to say (contacts.SealOf): a card with no
// X-HDTP-SEAL line says `none` (HDTP §3, §13.4), and a card on file that does not read is refused
// here rather than given a policy. This read an absent line, and a card that did not parse, as
// `required`, so a recipient that left the line out was sent envelopes it had not agreed to take
// and could not be reached at all.
func (n *Node) PeerOf(accountID string, c store.Contact) (outbound.Peer, error) {
	if c.Endpoint == "" || len(c.Leaf) == 0 {
		return outbound.Peer{}, fmt.Errorf("contact %s has no endpoint on file", c.Fingerprint)
	}
	seal, err := contacts.SealOf(c.Card, n.now())
	if err != nil {
		return outbound.Peer{}, fmt.Errorf("contact %s: %w", c.Fingerprint, err)
	}
	ourKid := ""
	n.mu.RLock()
	if a := n.accounts[accountID]; a != nil {
		ourKid = a.kp.Fingerprint
	}
	n.mu.RUnlock()
	return outbound.Peer{
		Endpoint: c.Endpoint, Seal: seal,
		Root: c.Fingerprint, Leaf: c.Leaf, ChainSeen: ourKid != "" && c.ChainSentKid == ourKid,
	}, nil
}

// strangerTools are what an identity sends to somebody who is not, or not yet, its contact: the
// two ways in (HDTP §5.1) and the two answers to a request (§6.2). They spend the identity's
// stranger budget whatever the row says — an approval's `contact_accepted` goes to a row the
// approval has just made active — so a flood of approvals or requests is held to one number.
var strangerTools = map[string]bool{
	"request_contact": true, "redeem_invite": true, "contact_accepted": true, "contact_rejected": true,
}

// outboundToContact says whether a call out is charged as to a contact (the per-contact bucket and
// the account's aggregate) or as to a stranger (the account's stranger budget): to a contact when
// the account holds the peer's root as an active contact and the tool is not one of strangerTools.
func (n *Node) outboundToContact(accountID string, peer outbound.Peer, tool string) bool {
	if strangerTools[tool] || peer.Root == "" {
		return false
	}
	c, err := n.opts.Store.GetContact(context.Background(), accountID, peer.Root)
	return err == nil && c.Status == "active"
}

// wireClient attaches to a client what it must be able to write back about the
// contacts it reaches (HDTP §13.2, §14.3): the clock and dialer, `OnChainSent` (records that our
// leaf has been sent), `OnRepin` (moves the pin to a newer leaf, audited as `contact_renewal`),
// and `Budget` (spendOutbound).
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
	client.Budget = func(peer outbound.Peer, tool string) error {
		return n.spendOutbound(accountID, peer, tool)
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
// its own. The identity is the root (HDTP §2); a lone certificate names no root,
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

// spendOutbound charges one call out of accountID to peer to its HDTP §12 outbound budget, before
// the call is sealed: to an active contact that contact's bucket and the account's outbound
// aggregate, to anybody else — or with one of strangerTools, whoever the row says the peer is —
// the account's stranger budget. A refusal leaves the node as nothing.
func (n *Node) spendOutbound(accountID string, peer outbound.Peer, tool string) error {
	charge := limits.StrangerOut()
	if n.outboundToContact(accountID, peer, tool) {
		charge = limits.ContactOut(peer.Root, n.contactCap())
	}
	r := n.decide(context.Background(), accountID, []limits.Charge{charge}, "")
	switch {
	case r == nil:
		return nil
	case r.Unavailable:
		return errors.New("unavailable: this node's limits sidecar is not answering, so nothing is sent")
	default:
		return &outbound.RateLimited{RetryAfter: r.RetryAfter}
	}
}

// IntegrationBudget charges each call of an integration-backed tool to that integration's cap for
// the calling contact (the owner's upstream quota, which one contact may not spend all of), on top
// of the contact's own budget the call has already spent. A refusal is `rate_limited` with its
// wait, or `unavailable` when the sidecar did not answer, and nothing reaches the upstream.
func (n *Node) IntegrationBudget(accountID, integrationID string, next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		c, ok := public.CallerFromContext(ctx)
		if !ok || c.Fingerprint == "" {
			return (&public.Refusal{Unavailable: true}).Result(), nil
		}
		if r := n.decide(ctx, accountID, []limits.Charge{limits.Integration(integrationID, c.Fingerprint)}, ""); r != nil {
			return r.Result(), nil
		}
		return next(ctx, req)
	}
}
