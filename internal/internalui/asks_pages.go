package internalui

// The owner's asks on the portal (docs/release/owner-asks-2026-10-19.md, N1): the open ask and
// every notice drawn as a card on the conversation, the Needs you page of open asks, and the
// owner's answer. Every route calls the asks service, the one the owner MCP's tools call, and the
// service writes the audit rows, so these handlers write none.

import (
	"fmt"
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

// getAPIAsks serves `GET /api/asks`: the account's asks and notices, newest first, or one thread's
// (`thread`) or one contact's (`contact`), oldest first; `status=open` for the open asks alone. `open` is how many asks wait on
// the owner, the sidebar's badge.
func (d AsksDeps) getAPIAsks(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "" && status != asks.StatusOpen {
		askRefusal(w, refusal.BadRequest("status is open, or omitted for every ask and notice", nil))
		return
	}
	account := accountParam(r)
	list, err := d.Asks.List(r.Context(), account, asks.Filter{Open: status == asks.StatusOpen,
		Thread: r.URL.Query().Get("thread"), Contact: r.URL.Query().Get("contact")})
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

// postAsksIDAnswer serves `POST /asks/{id}/answer`: `message`, the A2UI client-to-server action
// the card sends when the owner presses one of the ask's Buttons, its context resolved from the
// card's data model. It answers the ask as it now is. The field is bounded as a surface is.
func (d AsksDeps) postAsksIDAnswer(w http.ResponseWriter, r *http.Request) {
	msg := r.PostFormValue("message")
	if len(msg) > asks.MaxSurfaceBytes {
		askRefusal(w, refusal.TooLarge(fmt.Sprintf("the action is %d bytes, over the %d it may be", len(msg), asks.MaxSurfaceBytes), nil))
		return
	}
	v, err := d.Asks.Answer(r.Context(), accountParam(r), r.PathValue("id"), []byte(msg))
	if err != nil {
		askRefusal(w, err)
		return
	}
	apiJSON(w, v)
}
