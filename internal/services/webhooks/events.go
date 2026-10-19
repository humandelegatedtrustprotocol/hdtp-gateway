package webhooks

// Which of the node's events a webhook carries, under the cloud's names (BatonDeck's
// gateway/src/events/registry.ts), so a receiver written for one host reads the other. The table
// below is the one place a bus kind becomes a name: Subscribable is read from it, so a filter can
// only name an event the node emits, and EnvelopeOf is the only reader of a change row here.
//
// What the node emits and the cloud's names do not cover, or cover with more than a row holds, is
// left out rather than sent half-true:
//   - EventRequest is both a contact request and a contact at a new address awaiting the owner
//     (internal/node/node.go OnRequest, OnPending), which the cloud names contact.requested and
//     contact.address_pending; the row does not say which.
//   - EventAttention names the account and not the integration, and integration.attention's data
//     is the integration.
//   - a contact's address or leaf moving (an EventCall with no tool), which the cloud names
//     contact.new_address and contact.renewed; the row does not say which.
//   - an outbound message, a deleted thread, EventRelayed (request.answered's `relayed` is a field
//     of the one answered event), and the node's own housekeeping kinds (invalidate, account,
//     settings).
//
// ask.answered and ask.expired are the node's alone: the cloud has no owner asks (a named
// divergence, README). They say the owner answered an ask, or that it expired unanswered, so an
// agent woken by them reads get_ask; an ask put, withdrawn or a notice posted is the agent's own
// act and is not sent.
//
// request.pending, request.answered and call.made carry a subset of the cloud's data: the change
// row holds the request id and the caller, not the capability, trust flag or expiry, and a call's
// tool, not an integration or a mode.

import (
	"encoding/json"
	"strconv"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// EventEnvelope is an event as a receiver gets it: ids and metadata, never a message's body,
// media, a card or a key.
type EventEnvelope struct {
	// ID is stable for the event (its change row's), so a receiver can deduplicate.
	ID   string
	Type string
	// CreatedAt is unix milliseconds, as the cloud's is; the change log keeps seconds.
	CreatedAt int64
	// Identity is the account's id: the id every owner MCP tool takes, so a receiver acts on the
	// account without looking it up. The cloud's is the slug, a named divergence (README).
	Identity string
	Data     map[string]any
}

// EnvelopeBody is the exact request body; the signature is computed over this string. The key
// order is the cloud's (`id, type, created_at, identity?, data`), and identity is left out when
// empty.
func EnvelopeBody(e EventEnvelope) (string, error) {
	type withIdentity struct {
		ID        string         `json:"id"`
		Type      string         `json:"type"`
		CreatedAt int64          `json:"created_at"`
		Identity  string         `json:"identity,omitempty"`
		Data      map[string]any `json:"data"`
	}
	data := e.Data
	if data == nil {
		data = map[string]any{}
	}
	b, err := json.Marshal(withIdentity{ID: e.ID, Type: e.Type, CreatedAt: e.CreatedAt, Identity: e.Identity, Data: data})
	return string(b), err
}

// emitted is every event the node sends, by the cloud's name: data is the envelope's data for an
// event of that name, and ok false when the event is not one.
var emitted = []struct {
	name string
	data func(e messaging.Event) (map[string]any, bool)
}{
	{"message.received", func(e messaging.Event) (map[string]any, bool) {
		return messageIn(e, "text")
	}},
	{"message.delivered", func(e messaging.Event) (map[string]any, bool) {
		return deliveryOf(e, messaging.StatusDelivered)
	}},
	{"message.failed", func(e messaging.Event) (map[string]any, bool) {
		return deliveryOf(e, messaging.StatusFailed)
	}},
	{"media.received", func(e messaging.Event) (map[string]any, bool) {
		return messageIn(e, "media")
	}},
	{"request.pending", func(e messaging.Event) (map[string]any, bool) {
		if e.Kind != messaging.EventPending || e.Ref == "" {
			return nil, false
		}
		return map[string]any{"request_id": e.Ref, "fingerprint": e.ContactFpr}, true
	}},
	{"request.answered", func(e messaging.Event) (map[string]any, bool) {
		if e.Kind != messaging.EventAnswered || e.Ref == "" {
			return nil, false
		}
		return map[string]any{"request_id": e.Ref}, true
	}},
	{"ask.answered", func(e messaging.Event) (map[string]any, bool) {
		return askOf(e, messaging.AskAnswered)
	}},
	{"ask.expired", func(e messaging.Event) (map[string]any, bool) {
		return askOf(e, messaging.AskExpired)
	}},
	{"call.made", func(e messaging.Event) (map[string]any, bool) {
		// Only the calls the owner's feed reports (a booking, a media send). The node's other
		// EventCall, a contact's address or leaf moving (public's OnEvent), names no tool.
		if e.Kind != messaging.EventCall || !messaging.FeedCalls[e.Ref] || e.ContactFpr == "" {
			return nil, false
		}
		return map[string]any{"fingerprint": e.ContactFpr, "capability": e.Ref}, true
	}},
}

// messageIn is a message a contact sent, of kind ("text" or "media", as messaging records it).
func messageIn(e messaging.Event, kind string) (map[string]any, bool) {
	if e.Kind != messaging.EventMessage || e.Direction != messaging.DirIn || e.MsgID == "" || e.MsgKind != kind {
		return nil, false
	}
	return map[string]any{"thread_id": e.ThreadID, "message_id": e.MsgID, "from": e.ContactFpr}, true
}

// deliveryOf is a message this account sent whose delivery status became status.
func deliveryOf(e messaging.Event, status string) (map[string]any, bool) {
	if e.Kind != messaging.EventDelivery || e.Status != status || e.MsgID == "" {
		return nil, false
	}
	return map[string]any{"thread_id": e.ThreadID, "message_id": e.MsgID}, true
}

// askOf is an ask of this account whose status became status.
func askOf(e messaging.Event, status string) (map[string]any, bool) {
	if e.Kind != messaging.EventAsk || e.Status != status || e.Ref == "" {
		return nil, false
	}
	return map[string]any{"ask_id": e.Ref, "thread_id": e.ThreadID}, true
}

// Subscribable is every name a filter may hold: exactly the names the node emits.
func Subscribable() []string {
	out := make([]string, len(emitted))
	for i, m := range emitted {
		out[i] = m.name
	}
	return out
}

// EnvelopeOf is the envelope a change row is delivered as, for the account whose id is identity;
// ok is false for a row no webhook carries.
func EnvelopeOf(c store.Change, identity string) (env EventEnvelope, ok bool) {
	e := messaging.EventOf(c)
	for _, m := range emitted {
		if data, ok := m.data(e); ok {
			return EventEnvelope{ID: "evt_" + strconv.FormatInt(c.ID, 10), Type: m.name, CreatedAt: c.At * 1000,
				Identity: identity, Data: data}, true
		}
	}
	return EventEnvelope{}, false
}
