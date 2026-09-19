package node

// Telling contacts where to find you (PACT §5.3, §9).
//
// An address is not a setting. It is INSIDE the leaf — the one URI the person's root signed this
// host for — so it changes when the wallet issues a leaf naming another endpoint, and at no other
// time. When that leaf is installed the node tells every contact from the new address with
// `update_contact`, its chain in the envelope: the chain is the proof, and the contact's own
// `accept_new_hosts` decides whether it re-pins at once or asks its owner.
//
// This file used to have a second way. `AnnounceEndpointChange` ran when the owner saved a new
// `public_url`: it signed the account's OWN fingerprint with its key — "proof that whoever sent
// the new card holds the pinned key" — and called `update_contact{card, sig}` on every contact of
// every account. That was 1.x, where a card carried `X-PACT-ENDPOINT` and a pin was a key. Under
// 2.0 saving a setting does not change a leaf, so the card it sent was the card the contact
// already held, `sig` was an argument nothing read, and the calls accomplished nothing — while the
// thing that does move an address was not started, and nobody was told it was now needed. What
// replaced it is in `internal/cli/settings.go`: a `public_url` change names the accounts whose
// leaf was issued for the old address, and sends nothing.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// AnnounceMove is PACT §5.3 and §9 after a leaf install that changed the
// account's address: every contact pinned by our root is reached with
// update_contact carrying the new card, in chain form — the chain in the
// envelope is the proof of the new address, and the contact's setting decides
// whether it re-pins at once or asks its owner. The walk is durable
// (rotation_fanout, kind `move`), so an interrupted campaign resumes where it
// stopped when run again for the same leaf.
func (n *Node) AnnounceMove(ctx context.Context, accountID, newKid string) (done, failed int, err error) {
	card, err := n.Card(ctx, accountID)
	if err != nil {
		return 0, 0, err
	}
	camp := identity.Campaign{AccountID: accountID, NewKid: newKid, Kind: "move"}
	announcer := &identity.Announcer{Manager: n.idm, Audit: n.opts.audit, Now: n.opts.Now}
	done, failed, _ = announcer.Fanout(ctx, camp, card, func(ctx context.Context, c store.Contact, card string) error {
		peer, err := n.peerOf(accountID, c)
		if err != nil {
			return err
		}
		peer.ChainSeen = false // the move is proved by the chain, never by a fingerprint
		client, err := n.OutboundClient(accountID)
		if err != nil {
			return err
		}
		res, err := client.Call(ctx, peer, "update_contact", map[string]any{"card": card}, "move-"+newKid+"-"+c.Fingerprint)
		if err != nil {
			return err
		}
		if res.IsError {
			// pending_approval is the contact's owner deciding (accept_new_hosts
			// = ask): the campaign reached them, and that is what it is for.
			if code, _ := refusalCodeOf(res); code == "pending_approval" {
				return nil
			}
			return fmt.Errorf("peer refused update_contact")
		}
		return nil
	})
	return done, failed, nil
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
