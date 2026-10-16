package node

// Asking to become somebody's contact (HDTP §6.2, SPEC §9): `request_contact` with this identity's
// card. It has two callers, and this is the one implementation both use:
//
//   - the owner, who has a peer's card out of band and asks to be added
//     (internal/cli contactInitiator.RequestContact, which then records the pending_out pin);
//   - the move campaign, when a contact an import brought refuses `update_contact` because it
//     does not pin this identity (HDTP §9.2): the peer then decides under its own policy.

import (
	"context"
	"errors"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// ErrRequestRefused is a peer's answer refusing `request_contact`. Code names why, in the peer's
// words (HDTP §12); `pending_approval` means the peer already holds a request from us.
type ErrRequestRefused struct {
	// Code is the HDTP §12 code the peer answered with, or "" when it sent none.
	Code string
}

// Error says the peer refused the request and, when it named one, the code.
func (e ErrRequestRefused) Error() string {
	if e.Code == "" {
		return "the peer refused the request"
	}
	return "the peer refused the request: " + e.Code
}

// ErrNotReached is a `request_contact` that went out and got no answer, or that this identity's
// own budget or the limits sidecar kept from leaving (outbound.WhyUnsent reads it through Unwrap).
// Anything else RequestContact returns failed here, before the call: this identity's card or its
// client could not be read, which is this node's failure and not the peer's.
type ErrNotReached struct {
	// Err is the call's failure.
	Err error
}

// Error is the call's failure, named as request_contact's.
func (e ErrNotReached) Error() string { return "request_contact: " + e.Err.Error() }

// Unwrap is the call's failure.
func (e ErrNotReached) Unwrap() error { return e.Err }

// RequestContact sends `request_contact`, carrying this identity's card and the owner's note, to
// peer. callID is the call's idempotency key. The call's failure is ErrNotReached; a failure before
// it (the card, the client) is returned as it is; an answer that refuses is ErrRequestRefused,
// never taken for a request that landed.
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
	res, err := client.Call(ctx, peer, core.ToolRequestContact, args, callID)
	if err != nil {
		return ErrNotReached{Err: err}
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
