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
// What sync is NOT: a key-change channel. The re-fetched card MUST name the
// key we pin; a card naming any other key is refused outright, because moving
// a pin requires update_contact's old-key signature (PACT §2), not a poll. A
// compromised or confused peer endpoint therefore cannot walk our pin
// anywhere — the worst a bad sync answer can do is be ignored.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

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
	if err := verifySyncedCard(contactFpr, spki, out.Card, out.CardSig); err != nil {
		// A card that does not verify, or names a different key, is refused —
		// loudly, because a peer serving one is worth the owner's attention.
		n.auditFor(accountID, "contact_sync", "contact:"+contactFpr+" why:"+err.Error(), "invalid")
		return false
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

// verifySyncedCard is the whole trust decision, kept together so it can be
// tested without a wire: the card must still name the pinned key, and the
// signature over its bytes must verify under that key.
func verifySyncedCard(pinnedFpr string, pinnedSPKI []byte, card, sigB64 string) error {
	parsed, err := contacts.ValidateInbound(card)
	if err != nil {
		return err
	}
	if parsed.Key != pinnedFpr {
		return fmt.Errorf("the card names %s, not the pinned key — key changes go through update_contact", parsed.Key)
	}
	pub, err := x509.ParsePKIXPublicKey(pinnedSPKI)
	if err != nil {
		return fmt.Errorf("pinned key unreadable")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("signature is not base64url")
	}
	if !identity.VerifyBytes(pub, []byte(card), sig) {
		return fmt.Errorf("the card signature does not verify under the pinned key")
	}
	return nil
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
