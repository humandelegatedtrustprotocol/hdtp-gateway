package node

// Telling contacts where to find you (PACT §5.3, §9).
//
// An address is not a setting. It is INSIDE the leaf — the one URI the person's root signed this
// host for — so it changes when the wallet issues a leaf naming another endpoint, and at no other
// time. When that leaf is installed the node tells every contact from the new address with
// `update_contact`, its chain in the envelope: the chain is the proof, and the contact's own
// `accept_new_hosts` decides whether it re-pins at once or asks its owner.
//
// Saving a new `public_url` is therefore not a move and announces nothing: it does not change a
// leaf, so there is nothing new to tell anyone. What it does is in
// `internal/services/settings/settings.go` — it names the accounts whose leaf was issued for the
// old address, which is who needs a new leaf.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
)

// AnnounceMove is PACT §5.3 and §9 after a leaf install: every contact the campaign walks
// (identity.Campaign.Walks) is reached with update_contact carrying the new card, in chain form —
// the chain in the envelope is the proof of the new address, and the contact's setting decides
// whether it re-pins at once or asks its owner. A leaf that did not move the identity walks only
// the contacts an import left owed the handshake. The walk is durable (move_fanout), so an
// interrupted campaign resumes where it stopped when run again for the same leaf.
//
// update_contact is a contact-tier tool, so a peer that does not pin this identity refuses it —
// which is what a contact an import brought may well be: it knew the identity at another host, or
// never accepted it at all (PACT §9.2). For such a contact, and only for one this campaign owes the
// handshake, the refusal falls back to request_contact, and that peer decides under its own
// policy. The contact is marked pending_out BEFORE the request leaves, so an answer that comes at
// once finds the approach it answers; a request that does not arrive is taken back, and one the
// peer refuses outright is taken back and recorded `refused`, never asked again for this leaf. An
// ordinary contact that refuses the new card is left `pending`, as any contact not reached is.
func (n *Node) AnnounceMove(ctx context.Context, accountID, newKid string) (done, failed int, err error) {
	card, err := n.Card(ctx, accountID)
	if err != nil {
		return 0, 0, err
	}
	camp, err := n.idm.CampaignFor(ctx, accountID, newKid)
	if err != nil {
		return 0, 0, err
	}
	announcer := &identity.Announcer{Manager: n.idm, Audit: n.opts.audit, Now: n.opts.Now}
	done, failed, err = announcer.Fanout(ctx, camp, card, func(ctx context.Context, c store.Contact, card string) (string, error) {
		peer, err := n.PeerOf(accountID, c)
		if err != nil {
			return "", err
		}
		peer.ChainSeen = false // the move is proved by the chain, never by a fingerprint
		client, err := n.OutboundClient(accountID)
		if err != nil {
			return "", err
		}
		res, err := client.Call(ctx, peer, "update_contact", map[string]any{"card": card}, "move-"+newKid+"-"+c.Fingerprint)
		if err != nil {
			return "", err
		}
		if !res.IsError {
			return "updated", nil
		}
		// pending_approval is the contact's owner deciding (accept_new_hosts
		// = ask): the campaign reached them, and that is what it is for.
		code, _ := refusalCodeOf(res)
		if code == "pending_approval" {
			return "awaiting_approval", nil
		}
		if !camp.Owes(c) {
			return "", fmt.Errorf("the peer refused update_contact (%s)", codeOr(code))
		}
		return n.handshakeRequest(ctx, accountID, peer, c, newKid)
	})
	// Contacts that were not reached are what the counts are for. Anything else — progress that
	// could not be recorded — is a fault, and it used to be dropped here along with the first.
	if errors.Is(err, identity.ErrFanoutIncomplete) {
		err = nil
	}
	return done, failed, err
}

// handshakeRequest is the handshake's fallback to request_contact for a contact that does not hold
// this identity (PACT §9.2). The row becomes pending_out first — the state the peer's
// `contact_accepted` and `contact_rejected` answer (PACT §5.1) — so an answer sent the moment the
// request lands is not refused here as coming from nobody we had asked. A request that does not
// arrive is taken back and is retried by the next run; one the peer refuses is taken back and
// recorded FanoutRefused.
func (n *Node) handshakeRequest(ctx context.Context, accountID string, peer outbound.Peer, c store.Contact, newKid string) (string, error) {
	st := n.idm.Store
	at := n.now().Unix()
	marked, err := st.MarkContactRequested(ctx, accountID, c.Fingerprint, c.Status, at)
	if err != nil {
		return "", fmt.Errorf("the contact could not be marked as awaiting their answer: %w", err)
	}
	if !marked {
		return "", fmt.Errorf("the contact changed while the campaign walked it")
	}
	rerr := n.RequestContact(ctx, accountID, peer, "", "handshake-"+newKid+"-"+c.Fingerprint)
	code, refused := requestRefusal(rerr)
	if rerr == nil || (refused && code == "pending_approval") {
		return "requested", nil
	}
	if _, terr := st.TakeBackContactRequest(ctx, accountID, c.Fingerprint, c.Status, c.RequestedAt, at); terr != nil {
		return "", fmt.Errorf("request_contact did not land (%v), and the approach could not be taken back: %w", rerr, terr)
	}
	if refused && !transientRefusal(code) {
		return identity.FanoutRefused, nil
	}
	return "", fmt.Errorf("peer refused update_contact, then request_contact: %w", rerr)
}

// transientRefusal says a refusal is about the moment, not the request: the peer is busy or
// failing, and the same request may land later. Every other code is the peer's answer.
func transientRefusal(code string) bool {
	return code == "" || code == "rate_limited" || code == "unavailable"
}

func codeOr(code string) string {
	if code == "" {
		return "no code"
	}
	return code
}

// refusalCodeOf reads the plaintext code of a wrapper-level refusal.
func refusalCodeOf(res *mcp.CallToolResult) (string, bool) {
	if res == nil || len(res.Content) == 0 {
		return "", false
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return "", false
	}
	var body struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(tc.Text), &body) != nil {
		return "", false
	}
	return body.Code, body.Code != ""
}
