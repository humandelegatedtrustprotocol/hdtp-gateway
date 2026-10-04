package node

// Refreshing ONE contact's card, because its owner asked (HDTP §3, §14.3).
//
// A contact's card can change while we are not looking: a renewed leaf, a different seal policy.
// This node does not go looking. HDTP §14.3 has a newer leaf arrive on use — the chain in the
// first envelope after a renewal (§13.2), `certificate_renewed` (§14.4) — and the owner's rule for
// this node is the same: a pin is confirmed when it is needed, and nothing is done proactively.
// So there is no sweep here, on a timer or on request: what is left is one pull, of one contact,
// for a person who pressed the button on that contact's page or an agent that named them to the
// owner MCP's `refresh_contact`.
//
// What a refresh can and cannot move. The re-fetched card MUST name the ROOT we pin, which
// nothing can change (§14.3). The LEAF beneath it is different: a renewal is a new leaf
// signed by that same root for the same address, it authorizes itself — HDTP §2, "because
// the endpoint is unchanged it needs no one's approval to accept it". What a refresh cannot do
// is move an ADDRESS: the chain is validated against the pinned endpoint as well as the
// pinned root, so a chain valid at some other address is §5.3's business and not a pull's.
// A compromised or confused endpoint therefore cannot walk the pin anywhere the person's
// own root did not sign it to, and cannot move it off the address at all.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// What a refresh of one contact found, in the words the portal and the owner MCP both show.
const (
	RefreshUnchanged   = "unchanged"   // they serve the card on file
	RefreshUpdated     = "updated"     // a different card under the same leaf: a name, a seal policy
	RefreshRenewed     = "renewed"     // a newer leaf under the pinned root (§14.3), and the card carrying it
	RefreshUnreachable = "unreachable" // nothing usable came back; the pin stands (§14.3)
	RefreshRefused     = "refused"     // they answered and it did not verify; the pin stands
)

// ContactRefresh is the answer to "refresh this contact".
type ContactRefresh struct {
	Outcome string `json:"outcome"`
	// Why says what did not verify, when the outcome is refused.
	Why string `json:"why,omitempty"`
}

// RefreshContact re-fetches ONE contact's card and applies it when it verifies.
//
// The error is for a refresh that could not be attempted or could not be recorded: no such active
// contact of this account, no endpoint on file, a store that failed. Everything the PEER can cause
// is an outcome and not an error — an endpoint that is down or an answer that does not verify
// leaves the pin exactly as it was (§14.3's MUST NOT), and the owner is told which.
func (n *Node) RefreshContact(ctx context.Context, accountID, contactFpr string) (ContactRefresh, error) {
	client, peer, err := n.peerFor(ctx, accountID, contactFpr)
	if err != nil {
		return ContactRefresh{}, err
	}
	res, err := client.Call(ctx, peer, "get_card", map[string]any{}, newCallID())
	if err != nil || res == nil || res.IsError {
		n.auditFor(accountID, "contact_refresh", "contact:"+contactFpr, "unreachable")
		return ContactRefresh{Outcome: RefreshUnreachable}, nil
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
	refused := func(why string) (ContactRefresh, error) {
		// Loudly: a peer serving a card that does not verify, or a chain that does not belong to
		// this pin, is worth the owner's attention.
		n.auditFor(accountID, "contact_refresh", "contact:"+contactFpr+" why:"+why, "refused")
		return ContactRefresh{Outcome: RefreshRefused, Why: why}, nil
	}
	if json.Unmarshal([]byte(text), &out) != nil || out.Card == "" || out.CardSig == "" {
		return refused("the answer to get_card carries no signed card")
	}
	stored, err := n.opts.Store.GetContact(ctx, accountID, contactFpr)
	if err != nil {
		return ContactRefresh{}, err
	}
	// The root certificate first, and deliberately BEFORE the card is verified.
	//
	// The two checks are independent and neither implies the other: the card is checked
	// against the pinned LEAF key, which moves at every renewal, while the chain is
	// checked against the pinned ROOT, which is the thing that cannot move (HDTP §14.3).
	// So the case where the card signature legitimately fails — a peer that has renewed
	// and whose announce has not reached us yet — is exactly a case where the answer
	// still carries a root we can verify against what we pinned. Doing it after the card
	// check would skip the pins most likely to be missing one, and doing it before costs
	// nothing: `fillRootCert` writes only what validates to the pinned root.
	n.fillRootCert(ctx, accountID, contactFpr, stored, out.Chain)
	// Every element or none: a member that does not decode used to be dropped in silence, so
	// `["junk", leaf, root]` arrived here as a well-formed chain of two.
	der := make([][]byte, 0, len(out.Chain))
	for _, c := range out.Chain {
		b, derr := base64.RawURLEncoding.DecodeString(c)
		if derr != nil || len(b) == 0 {
			return refused("a chain member is not base64url")
		}
		der = append(der, b)
	}
	// One instant for the whole pass: the chain is judged at it and the pin is dated with it.
	// These were two readings of the clock, and the second — `pinned_at` — could be later than
	// the moment the leaf was actually found valid.
	now := n.now()
	renewed, err := verifyRefreshedCard(stored, der, out.Card, out.CardSig, now)
	if err != nil {
		return refused(err.Error())
	}
	found := ContactRefresh{Outcome: RefreshUnchanged}
	// A renewal the chain proved. The endpoint is the pinned one — `verifyRefreshedCard`
	// validated against it — so this moves the leaf and never the address.
	if renewed != nil {
		if rerr := n.opts.Store.RepinContactAddress(ctx, accountID, contactFpr, stored.Endpoint, renewed.Leaf, renewed.SPKI, now.Unix()); rerr != nil {
			n.auditFor(accountID, "contact_renewal", "contact:"+contactFpr, "error")
			return ContactRefresh{}, rerr
		}
		n.auditFor(accountID, "contact_renewal", "contact:"+contactFpr, "ok")
	}
	// "Renewed" is judged against the leaf held BEFORE the call, which is `peer.Leaf`. Over a
	// sealed call the renewal is usually learned on the way through: her answer carries the
	// newer chain and the client repins as it passes (§14.3, `wireClient`), so by the time the card
	// is read here `stored` already holds the new leaf, `renewed` is nil, and the owner who
	// pressed the button during a renewal was told only that a card had changed.
	if renewed != nil || !bytes.Equal(stored.Leaf, peer.Leaf) {
		found.Outcome = RefreshRenewed
	}
	if stored.Card == out.Card {
		n.auditFor(accountID, "contact_refresh", "contact:"+contactFpr, found.Outcome)
		return found, nil // the common case, and no write
	}
	name := contacts.CardName(out.Card)
	if err := n.opts.Store.UpdateContactCard(ctx, accountID, contactFpr, out.Card, name); err != nil {
		n.auditFor(accountID, "contact_refresh", "contact:"+contactFpr, "error")
		return ContactRefresh{}, err
	}
	if found.Outcome == RefreshUnchanged {
		found.Outcome = RefreshUpdated
	}
	n.auditFor(accountID, "contact_refresh", "contact:"+contactFpr, found.Outcome)
	return found, nil
}

// verifyRefreshedCard is the whole trust decision of a card refresh, kept together so it
// can be tested without a wire: what the answer proves about the contact, and what — if
// anything — the pin should become.
//
// It used to refuse a renewal. The card was checked under `stored.SPKI`, the pinned LEAF
// key, and a peer that had renewed signs its card with the new one — so the honest case
// came back "the card signature does not verify under the pinned key" and was audited as
// though the endpoint were compromised. The rule being enforced, "key changes go through
// update_contact", belongs to when the identity WAS a key and a successor
// had to be signed by its predecessor. Under HDTP a leaf signed by the pinned root
// authorizes itself: HDTP §2, "because the endpoint is unchanged it needs no one's
// approval to accept it."
//
// The chain is therefore what decides, and it is validated against BOTH halves of the pin:
//
//   - `ExpectedRoot` is the pinned root, which cannot change (§14.3), so a peer answering
//     with somebody else's root is refused rather than followed.
//   - `ExpectedEndpoint` is the pinned endpoint, and it is the one that makes this safe to
//     do on one click. A chain that validates to the pinned root at a DIFFERENT address is
//     not a renewal, it is §5.3 — a new address, which needs the owner or
//     `accept_new_hosts`. Advancing a pin from it would turn a refresh into an address
//     follow nobody asked for, which is worse than the refusal it replaced.
//
// Then §14.3 decides which leaf is the identity's voice: a later `notBefore` supersedes,
// an earlier one proves nothing, and equal dates with different bytes is a refusal.
func verifyRefreshedCard(pin store.Contact, chain [][]byte, card, sigB64 string, now time.Time) (renewed *renewedLeaf, err error) {
	parsed, err := contacts.ValidateInbound(card)
	if err != nil {
		return nil, err
	}
	if parsed.Key != pin.Fingerprint {
		return nil, fmt.Errorf("the card names %s, not the pinned root", parsed.Key)
	}
	// The chain is not optional. HDTP §6.1 has `get_card` answer "always the chain", and this
	// used to treat one as a bonus: with none, the card was checked under the pinned leaf's key
	// and accepted. Whoever answers at the pinned endpoint decides what is in the answer, so a
	// path taken when something is MISSING is a path they choose — and the one they chose skipped
	// the root check and the address check, which are the two that make a refresh safe to act on.
	if len(chain) != 2 {
		return nil, fmt.Errorf("the answer carries %d certificate(s); get_card answers with the chain, leaf then root (§6.1)", len(chain))
	}
	vr := hdtpidentity.ValidateChain(chain, hdtpidentity.ChainOpts{
		Now: now, ExpectedRoot: pin.Fingerprint, ExpectedEndpoint: pin.Endpoint,
	})
	if !vr.OK {
		return nil, fmt.Errorf("the chain it answered with fails rule %d: %s", vr.Rule, vr.Reason)
	}
	held, perr := hdtpidentity.Parse(pin.Leaf)
	if perr != nil {
		return nil, fmt.Errorf("the pinned leaf is unreadable: %v", perr)
	}
	switch {
	case vr.Leaf.NotBefore.After(held.NotBefore):
		// A renewal, and it takes effect the instant it is seen (§14.3).
		renewed = &renewedLeaf{Leaf: vr.Leaf.DER, SPKI: vr.LeafKey.SPKI}
	case vr.Leaf.NotBefore.Before(held.NotBefore):
		return nil, fmt.Errorf("the leaf it answered with is superseded by the pinned one (§14.3)")
	case !bytes.Equal(vr.Leaf.DER, pin.Leaf):
		return nil, fmt.Errorf("two different leaves claim the same notBefore (§14.3)")
	}
	// The card must carry the leaf the chain proved, as `update_contact` requires
	// (contacts.Manager.UpdateContact). Signed by the right key is not enough: the same host key
	// can sign a card that embeds some other certificate, and that card would be stored, shown
	// and re-shared as this contact's.
	if !bytes.Equal(parsed.Cert, vr.Leaf.DER) {
		return nil, fmt.Errorf("the card's certificate is not the leaf the chain proved")
	}
	if err := identity.VerifyCardSig(vr.LeafKey.SPKI, card, sigB64); err != nil {
		return nil, fmt.Errorf("under the proven leaf key: %v", err)
	}
	return renewed, nil
}

// renewedLeaf is a newer leaf a refresh proved, and what the pin should become.
type renewedLeaf struct {
	Leaf, SPKI []byte
}

// fillRootCert stores the root certificate of a pin that has none, from the chain
// `get_card` answers with.
//
// The chain travels once (HDTP §13.2), so a pin made over a SEALED call kept the root's
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
	vr := hdtpidentity.ValidateChain(der, hdtpidentity.ChainOpts{Now: n.now(), ExpectedRoot: contactFpr})
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
