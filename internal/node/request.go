package node

// Asking to become somebody's contact (PACT §6.2, SPEC §9): `request_contact` with this identity's
// card. It has two callers, and this is the one implementation both use:
//
//   - the owner, who has a peer's card out of band and asks to be added
//     (internal/cli contactInitiator.RequestContact, which then records the pending_out pin);
//   - the move campaign, when a contact an import brought refuses `update_contact` because it
//     does not pin this identity (PACT §9.2): the peer then decides under its own policy.

import (
	"context"
	"errors"
	"fmt"

	"github.com/pact-cloud/pact-gateway/internal/outbound"
)

// ErrRequestRefused is a peer's answer refusing `request_contact`. Code names why, in the peer's
// words (PACT §12); `pending_approval` means the peer already holds a request from us.
type ErrRequestRefused struct{ Code string }

func (e ErrRequestRefused) Error() string {
	if e.Code == "" {
		return "the peer refused the request"
	}
	return "the peer refused the request: " + e.Code
}

// RequestContact sends `request_contact`, carrying this identity's card and the owner's note, to
// peer. callID is the call's idempotency key. A transport failure is returned as it is; an answer
// that refuses is ErrRequestRefused, never taken for a request that landed.
func (n *Node) RequestContact(ctx context.Context, accountID string, peer outbound.Peer, note, callID string) error {
	card, err := n.Card(ctx, accountID)
	if err != nil {
		return err
	}
	client, err := n.OutboundClient(accountID)
	if err != nil {
		return err
	}
	args := map[string]any{"card": card}
	if note != "" {
		args["note"] = note
	}
	res, err := client.Call(ctx, peer, "request_contact", args, callID)
	if err != nil {
		return fmt.Errorf("request_contact: %w", err)
	}
	if res.IsError {
		code, _ := refusalCodeOf(res)
		return ErrRequestRefused{Code: code}
	}
	return nil
}

// requestRefusal reads the peer's code out of a RequestContact error, or "" when it was not a refusal.
func requestRefusal(err error) (string, bool) {
	var r ErrRequestRefused
	if errors.As(err, &r) {
		return r.Code, true
	}
	return "", false
}
