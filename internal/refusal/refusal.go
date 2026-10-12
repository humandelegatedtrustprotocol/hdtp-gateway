// Package refusal is the one reading of a failure that the owner's doors answer with: the owner
// MCP's {"code","detail"} and the portal's page messages. A refusal the node coded keeps the
// node's own sentence; anything else gets a fixed detail, so no store's or library's text
// reaches a caller.
package refusal

import (
	"errors"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// BadRequest marks a sentence the node wrote about the caller's arguments as a bad_request
// refusal. The owner MCP answers the sentence alone as the detail, and a portal page shows it;
// cause, when there is one, is the error behind it (a dial, a peer's answer) and is in neither.
// Error() is the sentence followed by the cause's text; no door shows it.
func BadRequest(sentence string, cause error) error {
	return badRequest{sentence: sentence, cause: cause}
}

type badRequest struct {
	sentence string
	cause    error
}

func (b badRequest) Error() string {
	if b.cause == nil {
		return b.sentence
	}
	return b.sentence + ": " + b.cause.Error()
}

// Sentence is the sentence a BadRequest in err's chain carries, without its cause; ok is false
// when err holds none.
func Sentence(err error) (sentence string, ok bool) {
	var br badRequest
	if errors.As(err, &br) {
		return br.sentence, true
	}
	return "", false
}

// InternalDetail is the detail of every failure that is the node's own: its text is the
// store's or a library's words and stays off the wire.
const InternalDetail = "the node could not complete this"

// NotFoundDetail is the detail of a store read that found nothing by the id it was given.
const NotFoundDetail = "nothing by that id on this account"

// Of is the code and detail a failure is answered with, on the owner MCP and in the portal's
// pages alike. A refusal the node coded keeps the node's own sentence as its detail; a store's
// not-found is not_found with a fixed detail; anything else is internal with a fixed detail. No
// error's text that the node did not write is in either.
func Of(err error) (code, detail string) {
	if sentence, marked := Sentence(err); marked {
		return "bad_request", sentence
	}
	switch {
	case errors.Is(err, contacts.ErrUnknownContact), errors.Is(err, integrations.ErrUnknownRequest):
		return "not_found", err.Error()
	case errors.Is(err, contacts.ErrWrongState), errors.Is(err, integrations.ErrRequestClosed):
		return "conflict", err.Error()
	case errors.Is(err, contacts.ErrBadRequest), errors.Is(err, messaging.ErrBadRequest):
		return "bad_request", err.Error()
	case errors.Is(err, contacts.ErrContactCap):
		return "payment_required", err.Error()
	case errors.Is(err, messaging.ErrTooLarge), errors.Is(err, messaging.ErrQuota):
		return "too_large", err.Error()
	case errors.Is(err, store.ErrNotFound):
		return "not_found", NotFoundDetail
	}
	return "internal", InternalDetail
}
