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
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
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
			peer, perr := n.peerOf(a.rec.ID, c)
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

// deliverUpdateContact is the real call, presenting the account's identity
// certificate — the contact recognizes us by the key it pinned.
func (n *Node) deliverUpdateContact(ctx context.Context, accountID string, peer outbound.Peer, card, sigB64 string) error {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil {
		return fmt.Errorf("node: unknown account %s", accountID)
	}
	// nil Roots = the system roots. A rotation has to reach contacts wherever they
	// are, including behind an edge that terminates TLS (SPEC §10.3). A 2.0
	// account presents its chain and, toward a 2.0 contact, carries it in the
	// envelope: the proof of the new address is the chain itself (PACT §5.3).
	client, err := n.OutboundClient(accountID)
	if err != nil {
		return err
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

// AnnounceMove is PACT §5.3 and §9 after a leaf install that changed the
// account's address: every contact pinned by our root is reached with
// update_contact carrying the new card, in chain form — the chain in the
// envelope is the proof of the new address, and the contact's setting decides
// whether it re-pins at once or asks its owner. The walk is durable
// (rotation_fanout, kind `move`), so an interrupted campaign resumes where it
// stopped when run again for the same leaf. Contacts pinned as 1.x are not
// here: a move puts the old key in a host that has deleted it, and they learn
// of it from the card again over a human channel (PACT Appendix C row 2).
func (n *Node) AnnounceMove(ctx context.Context, accountID, newKid string) (done, failed int, err error) {
	card, err := n.Card(ctx, accountID)
	if err != nil {
		return 0, 0, err
	}
	rot := identity.Rotation{AccountID: accountID, NewFpr: newKid, ModernOnly: true, Kind: "move"}
	rotator := &identity.Rotator{Manager: n.idm, Audit: n.opts.audit, Now: n.opts.Now}
	done, failed, _ = rotator.Fanout(ctx, rot, card, func(ctx context.Context, c store.Contact, card string, _ []byte) error {
		peer, err := n.peerOf(accountID, c)
		if err != nil {
			return err
		}
		peer.ChainSeen = false // the move is proved by the chain, never by a fingerprint
		client, err := n.OutboundClient(accountID)
		if err != nil {
			return err
		}
		res, err := client.Call(ctx, peer, c.SPKI, "update_contact", map[string]any{"card": card}, "move-"+newKid+"-"+c.Fingerprint)
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

// AnnounceLegacyRenewal resumes the 1.x side of a 2.0 renewal: the rotation of
// PACT Appendix C row 2 toward every contact pinned as 1.x, whose pin follows a
// key and not a root, so they must be told the new fingerprint under the old
// key's signature and given the compatibility card.
//
// It exists because nothing could resume that campaign. `Rotator.InFlight` reads
// the 1.x `prev_key` columns, and a 2.0 install retires its old key into the
// leaf ledger instead — so a contact unreachable while the install ran was never
// told again, and its pin kept a key the node had stopped presenting. The walk
// itself is durable (`rotation_fanout`), so this re-derives the proof from the
// ledger and lets `Fanout` skip whoever was already reached.
func (n *Node) AnnounceLegacyRenewal(ctx context.Context, accountID string) (done, failed int, err error) {
	keys, err := n.idm.ActiveLeafKeypairs(ctx, accountID, n.now())
	if err != nil {
		return 0, 0, err
	}
	if len(keys) == 0 || !keys[0].Current {
		return 0, 0, fmt.Errorf("node: no current leaf to announce")
	}
	current := keys[0]
	// The key the 1.x contacts still pin: the most recently superseded one.
	var old *identity.LeafKey
	for i := range keys {
		k := &keys[i]
		if k.Current {
			continue
		}
		if old == nil || k.LeafNotBefore() > old.LeafNotBefore() {
			old = k
		}
	}
	if old == nil {
		return 0, 0, nil // nothing retired, so nobody is holding an older key
	}
	proof, err := identity.SignBytes(old.KP, []byte(current.Kid))
	if err != nil {
		return 0, 0, err
	}
	acct, err := n.opts.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return 0, 0, err
	}
	compat, err := contacts.BuildCompatCard(acct.DisplayName, current.KP.Leaf, string(core.EffectiveSeal(n.opts.Config.Mode, n.opts.Config.Seal)))
	if err != nil {
		return 0, 0, err
	}
	rot := identity.Rotation{
		AccountID: accountID, OldFpr: old.Kid, NewFpr: current.Kid,
		Proof: proof, GraceUntil: old.NotAfter, LegacyOnly: true, Kind: "renewal_1x",
	}
	rotator := &identity.Rotator{Manager: n.idm, Audit: n.opts.audit, Now: n.opts.Now}
	// The notice goes out under the OLD key: a 1.x peer reads the new fingerprint
	// from a card signed by the key it already pinned (§3.9).
	oldClient := &outbound.Client{Keypair: old.KP, Cert: tlsCertOf(old.KP)}
	done, failed, _ = rotator.Fanout(ctx, rot, compat, func(ctx context.Context, c store.Contact, card string, p []byte) error {
		peerCard, perr := contacts.ParseCard(c.Card)
		if perr != nil || peerCard.Endpoint == "" {
			return fmt.Errorf("contact has no reachable endpoint on file")
		}
		peer := outbound.Peer{Endpoint: peerCard.Endpoint, Fingerprint: c.Fingerprint, Seal: peerCard.Seal}
		res, cerr := oldClient.Call(ctx, peer, c.SPKI, "update_contact", map[string]any{
			"card": card, "sig": base64.RawURLEncoding.EncodeToString(p),
		}, "renew1x-"+current.Kid+"-"+c.Fingerprint)
		if cerr != nil {
			return cerr
		}
		if res.IsError {
			return fmt.Errorf("peer refused update_contact")
		}
		return nil
	})
	return done, failed, nil
}
