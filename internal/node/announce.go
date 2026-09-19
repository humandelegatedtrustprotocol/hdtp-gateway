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
// leaf, so there is nothing new to tell anyone. What it does is in `internal/cli/settings.go` — it
// names the accounts whose leaf was issued for the old address, which is who needs a new leaf.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// AnnounceMove is PACT §5.3 and §9 after a leaf install that changed the
// account's address: every contact pinned by our root is reached with
// update_contact carrying the new card, in chain form — the chain in the
// envelope is the proof of the new address, and the contact's setting decides
// whether it re-pins at once or asks its owner. The walk is durable (move_fanout), so an
// interrupted campaign resumes where it stopped when run again for the same leaf.
func (n *Node) AnnounceMove(ctx context.Context, accountID, newKid string) (done, failed int, err error) {
	card, err := n.Card(ctx, accountID)
	if err != nil {
		return 0, 0, err
	}
	camp := identity.Campaign{AccountID: accountID, NewKid: newKid}
	announcer := &identity.Announcer{Manager: n.idm, Audit: n.opts.audit, Now: n.opts.Now}
	done, failed, err = announcer.Fanout(ctx, camp, card, func(ctx context.Context, c store.Contact, card string) error {
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
	// Contacts that were not reached are what the counts are for. Anything else — progress that
	// could not be recorded — is a fault, and it used to be dropped here along with the first.
	if errors.Is(err, identity.ErrFanoutIncomplete) {
		err = nil
	}
	return done, failed, err
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
