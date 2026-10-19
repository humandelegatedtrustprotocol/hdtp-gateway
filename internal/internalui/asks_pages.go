package internalui

// The owner's asks on the portal (docs/release/owner-asks-plan-2026-10-19.md, N1): the open ask and
// every notice drawn as a card on the conversation, the Needs you page of open asks, and the
// owner's answer. Every route calls the asks service, the one the owner MCP's tools call, and the
// service writes the audit rows, so these handlers write none.

import (
	"net/http"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/asks"
)

// AsksDeps is what the asks routes need.
type AsksDeps struct {
	// Asks is the service the owner MCP's tools call too: serve builds one for both.
	Asks *asks.Service
}

// MountAskPages registers GET /api/asks and POST /asks/{id}/answer. The account is the one
// accountMiddleware resolved, so another owner's account is 404 before either runs.
func MountAskPages(mux *http.ServeMux, d AsksDeps) {
	mux.HandleFunc("GET /api/asks", d.getAPIAsks)
	mux.HandleFunc("POST /asks/{id}/answer", d.postAsksIDAnswer)
}

// askRefusal answers a failure of the service as JSON: the code and the node's sentence, with the
// status read from the code (pageStatus).
func askRefusal(w http.ResponseWriter, err error) {
	code, detail := refusal.Of(err)
	apiJSONStatus(w, pageStatus(err), map[string]any{"error": code, "detail": detail})
}

// getAPIAsks serves `GET /api/asks`: the account's asks and notices, newest first, or one contact's
// (`contact`), oldest first; `status=open` for the open asks alone. `open` is how many asks wait on
// the owner, the sidebar's badge.
func (d AsksDeps) getAPIAsks(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "" && status != asks.StatusOpen {
		askRefusal(w, refusal.BadRequest("status is open, or omitted for every ask and notice", nil))
		return
	}
	account := accountParam(r)
	list, err := d.Asks.List(r.Context(), account, asks.Filter{Open: status == asks.StatusOpen, Contact: r.URL.Query().Get("contact")})
	if err != nil {
		askRefusal(w, err)
		return
	}
	open, err := d.Asks.CountOpen(r.Context(), account)
	if err != nil {
		askRefusal(w, err)
		return
	}
	apiJSON(w, map[string]any{"asks": list, "open": open})
}

// postAsksIDAnswer serves `POST /asks/{id}/answer`: `component`, the id of the component the owner
// answered with, and `value`, what they chose or wrote (a Choice's option, a TextField's text, a
// DateTimeInput's ISO value; nothing for a Button). It answers the ask as it now is.
func (d AsksDeps) postAsksIDAnswer(w http.ResponseWriter, r *http.Request) {
	v, err := d.Asks.Answer(r.Context(), accountParam(r), r.PathValue("id"),
		asks.Answer{Component: r.PostFormValue("component"), Value: r.PostFormValue("value")})
	if err != nil {
		askRefusal(w, err)
		return
	}
	apiJSON(w, v)
}
