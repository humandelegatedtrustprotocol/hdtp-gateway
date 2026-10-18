package internalui

// The Webhooks page (docs/release/webhooks-2026-10-18.md, W3): an account's endpoints, the
// signing secret shown once at create and at rotate, pause and resume, removal, and each
// endpoint's delivery log. The portal is the one door that registers an endpoint (ruling A of the
// plan): the owner MCP and the CLI have none. Every route calls the webhooks service and nothing
// else, and the service writes the audit rows, so these handlers write none.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/webhooks"
)

// WebhooksDeps is what the Webhooks page needs.
type WebhooksDeps struct {
	// Webhooks is the service the dispatcher posts through too: serve builds one for both.
	Webhooks *webhooks.Service
}

// MountWebhookPages registers the Webhooks routes (see the README's route table). The account is
// the one accountMiddleware resolved, so another owner's account is 404 before any of them runs.
func MountWebhookPages(mux *http.ServeMux, d WebhooksDeps) {
	mux.HandleFunc("GET /api/webhooks", d.getAPIWebhooks)
	mux.HandleFunc("GET /api/webhooks/{id}/deliveries", d.getAPIWebhooksIDDeliveries)
	mux.HandleFunc("POST /webhooks/create", d.postWebhooksCreate)
	mux.HandleFunc("POST /webhooks/{id}/rotate", d.postWebhooksIDRotate)
	mux.HandleFunc("POST /webhooks/{id}/status", d.postWebhooksIDStatus)
	mux.HandleFunc("POST /webhooks/{id}/remove", d.postWebhooksIDRemove)
}

// webhookRefusal answers a failure of the service as JSON: the code, the node's sentence (a fixed
// phrase for a failure of the node's own, never an error's text) and, for a registration a check
// refused, the cloud's reason (not_a_url, has_credentials, unknown_event). The status is read from
// the code (pageStatus).
func webhookRefusal(w http.ResponseWriter, err error) {
	code, detail := refusal.Of(err)
	body := map[string]any{"error": code, "detail": detail}
	var r webhooks.Refused
	if errors.As(err, &r) {
		body["reason"] = r.Code
	}
	apiJSONStatus(w, pageStatus(err), body)
}

// getAPIWebhooks serves `GET /api/webhooks`: the account's endpoints, newest first, and the event
// names a filter may hold.
func (d WebhooksDeps) getAPIWebhooks(w http.ResponseWriter, r *http.Request) {
	endpoints, err := d.Webhooks.List(r.Context(), accountParam(r))
	if err != nil {
		webhookRefusal(w, err)
		return
	}
	apiJSON(w, map[string]any{"endpoints": endpoints, "events": webhooks.Subscribable()})
}

// getAPIWebhooksIDDeliveries serves `GET /api/webhooks/{id}/deliveries`: the endpoint's delivery
// log, newest first, the service's default page.
func (d WebhooksDeps) getAPIWebhooksIDDeliveries(w http.ResponseWriter, r *http.Request) {
	rows, err := d.Webhooks.ListDeliveries(r.Context(), accountParam(r), r.PathValue("id"), 0)
	if err != nil {
		webhookRefusal(w, err)
		return
	}
	apiJSON(w, map[string]any{"deliveries": rows})
}

// postWebhooksCreate serves `POST /webhooks/create`: `url`, and `events`, the filter as names
// separated by commas (none: every event). It answers the endpoint and its secret, which is in
// this answer and nowhere else.
func (d WebhooksDeps) postWebhooksCreate(w http.ResponseWriter, r *http.Request) {
	var events []string
	for _, e := range strings.Split(r.PostFormValue("events"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			events = append(events, e)
		}
	}
	endpoint, secret, err := d.Webhooks.Create(r.Context(), accountParam(r), r.PostFormValue("url"), events)
	if err != nil {
		webhookRefusal(w, err)
		return
	}
	apiJSON(w, map[string]any{"endpoint": endpoint, "secret": secret})
}

// postWebhooksIDRotate serves `POST /webhooks/{id}/rotate`: a new secret, in this answer only,
// and when the one it replaced stops being accepted (unix milliseconds).
func (d WebhooksDeps) postWebhooksIDRotate(w http.ResponseWriter, r *http.Request) {
	secret, until, err := d.Webhooks.Rotate(r.Context(), accountParam(r), r.PathValue("id"))
	if err != nil {
		webhookRefusal(w, err)
		return
	}
	apiJSON(w, map[string]any{"secret": secret, "rotating_until": until})
}

// postWebhooksIDStatus serves `POST /webhooks/{id}/status`: `status`, "paused" or "active".
func (d WebhooksDeps) postWebhooksIDStatus(w http.ResponseWriter, r *http.Request) {
	status := r.PostFormValue("status")
	if err := d.Webhooks.SetStatus(r.Context(), accountParam(r), r.PathValue("id"), status); err != nil {
		webhookRefusal(w, err)
		return
	}
	apiJSON(w, map[string]any{"status": status})
}

// postWebhooksIDRemove serves `POST /webhooks/{id}/remove`.
func (d WebhooksDeps) postWebhooksIDRemove(w http.ResponseWriter, r *http.Request) {
	if err := d.Webhooks.Remove(r.Context(), accountParam(r), r.PathValue("id")); err != nil {
		webhookRefusal(w, err)
		return
	}
	apiJSON(w, map[string]any{"status": "removed"})
}
