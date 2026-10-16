// Package refusal is the one reading of a failure that the owner's doors answer with: the owner
// MCP's {"code","detail"} and the portal's page messages. A refusal the node coded keeps the
// node's own sentence; anything else gets a fixed detail, so no store's or library's text
// reaches a caller.
package refusal

import (
	"errors"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// BadRequest marks a sentence the node wrote about the caller's arguments as a bad_request
// refusal. The owner MCP answers the sentence alone as the detail, and a portal page shows it;
// cause, when there is one, is the error behind it (a dial, a peer's answer) and is in neither.
// Error() is the sentence followed by the cause's text; no door shows it.
func BadRequest(sentence string, cause error) error {
	return coded{code: "bad_request", sentence: sentence, cause: cause}
}

// Unavailable marks a sentence the node wrote about something it could not reach (a peer, a link)
// as an unavailable refusal, read as BadRequest's is.
func Unavailable(sentence string, cause error) error {
	return coded{code: "unavailable", sentence: sentence, cause: cause}
}

// RateLimited marks a sentence the node wrote about a call that a budget refused for now (its own,
// or the peer's) as a rate_limited refusal, read as BadRequest's is.
func RateLimited(sentence string, cause error) error {
	return coded{code: "rate_limited", sentence: sentence, cause: cause}
}

type coded struct {
	code, sentence string
	cause          error
}

func (c coded) Error() string {
	if c.cause == nil {
		return c.sentence
	}
	return c.sentence + ": " + c.cause.Error()
}

// Undelivered marks a message that was recorded and not delivered. why is the node's reason: a
// peer's §12 code, one the node names (node.WhyEndpointRefused, node.WhyUnreachable), or one
// outbound names for a call that never left (outbound.UnsentRateLimited,
// outbound.UnsentLimitsUnavailable). The
// message exists and the retry sweep goes on with it, so a door answers the recorded result beside
// the code (unavailable) and the detail "recorded, not delivered: <why>". Error() is the cause's
// text, as the audit row's why reads it; no door shows it.
func Undelivered(why string, cause error) error {
	return undelivered{why: why, cause: cause}
}

type undelivered struct {
	why   string
	cause error
}

func (u undelivered) Error() string {
	if u.cause == nil {
		return "recorded, not delivered: " + u.why
	}
	return u.cause.Error()
}

// Why is the reason an Undelivered in err's chain carries; ok is false when err holds none.
func Why(err error) (why string, ok bool) {
	var u undelivered
	if errors.As(err, &u) {
		return u.why, true
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
	var c coded
	if errors.As(err, &c) {
		return c.code, c.sentence
	}
	if why, ok := Why(err); ok {
		return "unavailable", "recorded, not delivered: " + why
	}
	if text, ok := identity.Worded(err); ok {
		return "bad_request", text
	}
	var fr messaging.FetchRefusal
	if errors.As(err, &fr) {
		return fr.Code, fr.Sentence
	}
	switch {
	case errors.Is(err, contacts.ErrUnknownContact), errors.Is(err, integrations.ErrUnknownRequest),
		errors.Is(err, identity.ErrNoCertificate):
		return "not_found", err.Error()
	case errors.Is(err, contacts.ErrWrongState), errors.Is(err, integrations.ErrRequestClosed),
		errors.Is(err, integrations.ErrNoCatalog), errors.Is(err, integrations.ErrNotConnected),
		errors.Is(err, identity.ErrSlugTaken):
		return "conflict", err.Error()
	case errors.Is(err, contacts.ErrBadRequest), errors.Is(err, messaging.ErrBadRequest),
		errors.Is(err, integrations.ErrExposureRefused), errors.Is(err, identity.ErrDisplayName),
		errors.Is(err, identity.ErrUnknownAlgorithm),
		errors.Is(err, auth.ErrLabelRequired):
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
