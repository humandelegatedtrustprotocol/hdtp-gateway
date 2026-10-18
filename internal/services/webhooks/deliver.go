package webhooks

// One delivery attempt's record, and which endpoints an event goes to. Ported from BatonDeck's
// gateway/src/webhooks/deliver.ts; the attempt itself (the POST, its timeout and its excerpt) is
// the dispatcher's (dispatch.go).
//
// A delivery is attempted once and never retried, as the cloud's (owner's decision of 2026-09-10,
// ruling C of the plan): no retry storm against a receiver and no ordering questions. A transient
// failure on the receiver's side loses that event, so a receiver that needs certainty reads the
// node (`get_inbox`, `wait_for_updates`) rather than treating the webhook as the record. What is
// kept is the log of what was attempted and what came back, and the failure run that parks an
// endpoint which has stopped answering.

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// ExcerptBytes is how much of an answer, or of the reason none came, a delivery row keeps: enough
// to see an error, not enough to store one.
const ExcerptBytes = 500

// AttemptOutcome is what one attempt did: whether the answer was a 2xx, its status (0 when none
// came), the time it took, and an excerpt of the answer or of the reason none came. Stopped is a
// failure that ended because the node was stopping, which says nothing about the receiver.
type AttemptOutcome struct {
	OK         bool
	HTTPStatus int64
	LatencyMs  int64
	Excerpt    string
	Stopped    bool
}

// NewDeliveryID is a delivery id, distinct per attempt, so the log is a log and not a latest-state
// table.
func NewDeliveryID() string { return newID("whd_") }

// excerpt is s as a delivery row keeps it: text either engine stores (a byte that is not UTF-8,
// and a NUL, which PostgreSQL's text refuses, become U+FFFD, as the cloud's TextDecoder makes
// them), cut to at most ExcerptBytes bytes of whole characters.
func excerpt(s string) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "\uFFFD")
	if len(s) <= ExcerptBytes {
		return s
	}
	cut := ExcerptBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// RecordAttempt writes what one attempt to the account's endpoint did, and the endpoint's health,
// in one transaction, and returns the row's status: delivered or failed, and failed is final. A
// success clears the failure run; a failure counts one, and the FailureLimit-th in a row parks the
// endpoint, which only the owner resumes. A Stopped failure is logged and not counted: a node
// stopping mid-post must not park a receiver that was answering. An endpoint removed meanwhile
// keeps the row and has no health to change.
func (s *Service) RecordAttempt(ctx context.Context, accountID, deliveryID, endpointID string, event EventEnvelope, out AttemptOutcome) (string, error) {
	status := "failed"
	if out.OK {
		status = "delivered"
	}
	now := s.now().UnixMilli()
	err := s.store.Atomically(ctx, func(tx store.Store) error {
		if err := tx.InsertWebhookDelivery(ctx, store.WebhookDelivery{ID: deliveryID, AccountID: accountID,
			EndpointID: endpointID, EventID: event.ID, EventType: event.Type, Status: status,
			HTTPStatus: out.HTTPStatus, LatencyMs: out.LatencyMs, Excerpt: excerpt(out.Excerpt), CreatedAt: now}); err != nil {
			return err
		}
		var err error
		switch {
		case out.OK:
			_, err = tx.ClearWebhookFailures(ctx, accountID, endpointID, now)
		case !out.Stopped:
			_, err = tx.CountWebhookFailure(ctx, accountID, endpointID, FailureLimit, now)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	return status, nil
}

// TargetsFor is the endpoints that take event: active, filtering on nothing or on its type, and
// registered no later than it happened, so an endpoint hears what happens from its registration
// on. The change log keeps whole seconds, so the comparison is in whole seconds: an endpoint
// registered within the second of an event takes it, rather than missing one that came after it.
func TargetsFor(endpoints []EndpointView, event EventEnvelope) []EndpointView {
	var out []EndpointView
	for _, e := range endpoints {
		if e.Status == "active" && e.CreatedAt/1000 <= event.CreatedAt/1000 &&
			(len(e.Events) == 0 || slices.Contains(e.Events, event.Type)) {
			out = append(out, e)
		}
	}
	return out
}
