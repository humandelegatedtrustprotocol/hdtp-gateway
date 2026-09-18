package node

// Keeping contacts in sync (PACT §3, §7.1).
//
// A contact's card can change while we are not looking: a new endpoint, a new
// gateway, a different seal policy. The announcement path (update_contact)
// covers peers that could reach us at the moment they changed — a peer whose
// announcement found us offline stays stale on our side until a call fails.
// The sync sweep closes that gap by PULLING: each active contact's get_card is
// re-fetched on a slow cadence and the stored card replaced when — and only
// when — the signature verifies under the key we already pin.
//
// What sync can and cannot move. The re-fetched card MUST name the ROOT we pin, which
// nothing can change (§14.3). The LEAF beneath it is different: a renewal is a new leaf
// signed by that same root for the same address, it authorizes itself — PACT §2, "because
// the endpoint is unchanged it needs no one's approval to accept it" — and the sweep now
// learns one where it used to refuse it as a bad signature. What sync still cannot do is
// move an ADDRESS: the chain is validated against the pinned endpoint as well as the
// pinned root, so a chain valid at some other address is §5.3's business and not a poll's.
// A compromised or confused endpoint therefore cannot walk the pin anywhere the person's
// own root did not sign it to, and cannot move it off the address at all.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// SyncContacts re-fetches every active contact's card across every account.
// Best effort by design: an unreachable peer is a fact to report, not an error
// to abort on. Returns how many contacts were checked and how many changed.
func (n *Node) SyncContacts(ctx context.Context) (checked, changed int) {
	n.mu.RLock()
	ids := make([]string, 0, len(n.accounts))
	for id := range n.accounts {
		ids = append(ids, id)
	}
	n.mu.RUnlock()
	for _, accountID := range ids {
		list, err := n.opts.Store.ListContacts(ctx, accountID)
		if err != nil {
			continue
		}
		for _, c := range list {
			if ctx.Err() != nil {
				return checked, changed
			}
			if c.Status != "active" || len(c.SPKI) == 0 {
				continue // fingerprint-only pins re-verify at next contact, not by poll
			}
			checked++
			if n.syncOne(ctx, accountID, c.Fingerprint) {
				changed++
			}
		}
	}
	return checked, changed
}

// syncOne re-fetches one contact's card and applies it when it verifies.
func (n *Node) syncOne(ctx context.Context, accountID, contactFpr string) bool {
	client, peer, spki, err := n.peerFor(ctx, accountID, contactFpr)
	if err != nil {
		return false // no endpoint on file: nothing to pull from
	}
	res, err := client.Call(ctx, peer, spki, "get_card", map[string]any{}, newCallID())
	if err != nil || res == nil || res.IsError {
		n.auditFor(accountID, "contact_sync", "contact:"+contactFpr, "unreachable")
		return false
	}
	var out struct {
		Card    string `json:"card"`
		CardSig string `json:"card_sig"`
		// The answer has carried the peer's [leaf, root] all along (public/tools.go,
		// `get_card`) and nothing read it, so every pin made over a sealed call kept
		// the root's fingerprint and never its certificate (F11).
		Chain []string `json:"chain"`
	}
	text := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if json.Unmarshal([]byte(text), &out) != nil || out.Card == "" || out.CardSig == "" {
		n.auditFor(accountID, "contact_sync", "contact:"+contactFpr, "invalid")
		return false
	}
	stored, err := n.opts.Store.GetContact(ctx, accountID, contactFpr)
	if err != nil {
		return false
	}
	// The root certificate first, and deliberately BEFORE the card is verified.
	//
	// The two checks are independent and neither implies the other: the card is checked
	// against the pinned LEAF key, which moves at every renewal, while the chain is
	// checked against the pinned ROOT, which is the thing that cannot move (PACT §14.3).
	// So the case where the card signature legitimately fails — a peer that has renewed
	// and whose announce has not reached us yet — is exactly a case where the answer
	// still carries a root we can verify against what we pinned. Doing it after the card
	// check would skip the pins most likely to be missing one, and doing it before costs
	// nothing: `fillRootCert` writes only what validates to the pinned root.
	n.fillRootCert(ctx, accountID, contactFpr, stored, out.Chain)
	der := make([][]byte, 0, 2)
	for _, c := range out.Chain {
		if b, derr := base64.RawURLEncoding.DecodeString(c); derr == nil && len(b) > 0 {
			der = append(der, b)
		}
	}
	renewed, err := verifySyncedCard(stored, der, out.Card, out.CardSig, n.now())
	if err != nil {
		// A card that does not verify, or a chain that does not belong to this pin, is
		// refused — loudly, because a peer serving one is worth the owner's attention.
		n.auditFor(accountID, "contact_sync", "contact:"+contactFpr+" why:"+err.Error(), "invalid")
		return false
	}
	// A renewal the chain proved. The endpoint is the pinned one — `verifySyncedCard`
	// validated against it — so this moves the leaf and never the address.
	if renewed != nil {
		if rerr := n.opts.Store.RepinContactAddress(ctx, accountID, contactFpr, stored.Endpoint, renewed.Leaf, renewed.SPKI, n.now().Unix()); rerr != nil {
			n.auditFor(accountID, "contact_renewal", "contact:"+contactFpr, "error")
			return false
		}
		n.auditFor(accountID, "contact_renewal", "contact:"+contactFpr, "ok")
	}
	if stored.Card == out.Card {
		return false // unchanged: the common case, and no write
	}
	name := contacts.CardName(out.Card)
	if err := n.opts.Store.UpdateContactCard(ctx, accountID, contactFpr, out.Card, name); err != nil {
		n.auditFor(accountID, "contact_sync", "contact:"+contactFpr, "error")
		return false
	}
	n.auditFor(accountID, "contact_sync", "contact:"+contactFpr, "updated")
	return true
}

// verifySyncedCard is the whole trust decision of the periodic sync, kept together so it
// can be tested without a wire: what the answer proves about the contact, and what — if
// anything — the pin should become.
//
// It used to refuse a renewal. The card was checked under `stored.SPKI`, the pinned LEAF
// key, and a peer that had renewed signs its card with the new one — so the honest case
// came back "the card signature does not verify under the pinned key" and was audited as
// though the endpoint were compromised. The rule being enforced, "key changes go through
// update_contact", belongs to the generation where the identity WAS a key and a successor
// had to be signed by its predecessor. Under 2.0 a leaf signed by the pinned root
// authorizes itself: PACT §2, "because the endpoint is unchanged it needs no one's
// approval to accept it."
//
// The chain is therefore what decides, and it is validated against BOTH halves of the pin:
//
//   - `ExpectedRoot` is the pinned root, which cannot change (§14.3), so a peer answering
//     with somebody else's root is refused rather than followed.
//   - `ExpectedEndpoint` is the pinned endpoint, and it is the one that makes this safe to
//     do unattended. A chain that validates to the pinned root at a DIFFERENT address is
//     not a renewal, it is §5.3 — a new address, which needs the owner or
//     `accept_new_hosts`. Advancing a pin from it would turn this sweep into an address
//     follow nobody asked for, which is worse than the refusal it replaced.
//
// Then §14.3 decides which leaf is the identity's voice: a later `notBefore` supersedes,
// an earlier one proves nothing, and equal dates with different bytes is a refusal.
func verifySyncedCard(pin store.Contact, chain [][]byte, card, sigB64 string, now time.Time) (renewed *syncedLeaf, err error) {
	parsed, err := contacts.ValidateInbound(card)
	if err != nil {
		return nil, err
	}
	if parsed.Key != pin.Fingerprint {
		return nil, fmt.Errorf("the card names %s, not the pinned root", parsed.Key)
	}
	// The key the card's signature must verify under: the pinned leaf's, unless the answer
	// carried a chain that proves a newer one.
	signer := pin.SPKI
	if len(chain) == 2 {
		vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{
			Now: now, ExpectedRoot: pin.Fingerprint, ExpectedEndpoint: pin.Endpoint,
		})
		if !vr.OK {
			return nil, fmt.Errorf("the chain it answered with fails rule %d: %s", vr.Rule, vr.Reason)
		}
		held, perr := pactidentity.Parse(pin.Leaf)
		if perr != nil {
			return nil, fmt.Errorf("the pinned leaf is unreadable: %v", perr)
		}
		switch {
		case vr.Leaf.NotBefore.After(held.NotBefore):
			// A renewal, and it takes effect the instant it is seen (§14.3).
			signer = vr.LeafKey.SPKI
			renewed = &syncedLeaf{Leaf: vr.Leaf.DER, SPKI: vr.LeafKey.SPKI}
		case vr.Leaf.NotBefore.Before(held.NotBefore):
			return nil, fmt.Errorf("the leaf it answered with is superseded by the pinned one (§14.3)")
		case !bytes.Equal(vr.Leaf.DER, pin.Leaf):
			return nil, fmt.Errorf("two different leaves claim the same notBefore (§14.3)")
		}
	}
	pub, err := x509.ParsePKIXPublicKey(signer)
	if err != nil {
		return nil, fmt.Errorf("the key to check this card under is unreadable")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("signature is not base64url")
	}
	if !identity.VerifyBytes(pub, []byte(card), sig) {
		return nil, fmt.Errorf("the card signature does not verify under the proven leaf key")
	}
	return renewed, nil
}

// syncedLeaf is a newer leaf a sync proved, and what the pin should become.
type syncedLeaf struct {
	Leaf, SPKI []byte
}

// fillRootCert stores the root certificate of a pin that has none, from the chain
// `get_card` answers with.
//
// The chain travels once (PACT §13.2), so a pin made over a SEALED call kept the root's
// fingerprint and nothing else: the sender's chain is inside the ciphertext, where only
// the library's Decide sees it, and behind an edge no client certificate ever arrives to
// fill the gap. A fingerprint authenticates a chain that shows up; it cannot prove a
// stored leaf, and an archive taken here could prove none of its contacts elsewhere.
//
// Nothing new goes on the wire for this. The answer already carries [leaf, root] inside
// the same sealed reply, so the carrier learns nothing it did not already fail to learn.
//
// What makes it safe is that the pin NAMES the root: `ExpectedRoot` is the pinned
// fingerprint, so a peer that answers with somebody else's root — or with a root that did
// not issue the leaf beside it — is refused rather than recorded.
func (n *Node) fillRootCert(ctx context.Context, accountID, contactFpr string, stored store.Contact, chain []string) {
	if len(stored.RootCert) > 0 || len(chain) != 2 {
		return
	}
	der := make([][]byte, 0, 2)
	for _, c := range chain {
		b, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil || len(b) == 0 {
			n.auditFor(accountID, "contact_root_cert", "contact:"+contactFpr, "invalid")
			return
		}
		der = append(der, b)
	}
	vr := pactidentity.ValidateChain(der, pactidentity.ChainOpts{Now: n.now(), ExpectedRoot: contactFpr})
	if !vr.OK {
		n.auditFor(accountID, "contact_root_cert", "contact:"+contactFpr+" rule:"+strconv.Itoa(vr.Rule), "refused")
		return
	}
	if err := n.opts.Store.SetContactRootCert(ctx, accountID, contactFpr, der[1]); err != nil {
		n.auditFor(accountID, "contact_root_cert", "contact:"+contactFpr, "error")
		return
	}
	n.auditFor(accountID, "contact_root_cert", "contact:"+contactFpr, "ok")
}
