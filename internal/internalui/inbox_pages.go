package internalui

// The deletion of a conversation and the SSE event stream (SPEC §7.9, §8.2, §7.6). The
// conversation view reads and sends through messages_pages.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// InboxDeps is what the deletion of a conversation and the event stream need.
type InboxDeps struct {
	Store store.Store
	// Msg deletes a conversation (DeleteThread).
	Msg *messaging.Service
	// Bus is the in-process event bus GET /events subscribes to, per account.
	Bus *messaging.Bus
	// Audit records each deletion of a conversation; nil records nothing (tests).
	Audit func(action, resource, outcome string)
}

// formOrQuery prefers the form body and falls back to the query, so a link and a
// form can both reach the same handler.
func formOrQuery(r *http.Request, key string) string {
	if v := r.PostFormValue(key); v != "" {
		return v
	}
	return r.URL.Query().Get(key)
}

// MountInboxPages registers POST /thread/delete and the server-sent-events stream GET /events. A
// thread id is never a path segment: a contact chooses it, and "." or ".." in a path is removed by
// the browser's URL parser and redirected by the mux, so POST /thread/delete reads it from
// `thread_id` in the form.
func MountInboxPages(mux *http.ServeMux, d InboxDeps) {
	mux.HandleFunc("POST /thread/delete", d.postThreadDelete)
	mux.HandleFunc("GET /events", d.getEvents)
}

// postThreadDelete serves `POST /thread/delete`: one conversation (`thread_id`) of the account in the
// form body, deleted here and only here (messaging.Service.DeleteThread, SPEC §7.9); the owner MCP's
// delete_thread is the same operation. It answers JSON, the operation's own answer: 200
// {status:"deleted", thread_id, contact, messages, files}; 400 {"error":"bad_request"} for an id of
// neither form of HDTP §7, the empty one included, and 413 {"error":"too_large"} for one over 64 bytes; 404
// {"error":"not_found"} for a thread the account does not hold (an account the owner does not
// administer is 404 before this, accountMiddleware); 500 {"error":"internal"}. Each writes one
// thread_delete row.
func (d InboxDeps) postThreadDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		apiJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	account := formOrQuery(r, "account")
	id := formOrQuery(r, "thread_id")
	gone, err := d.Msg.DeleteThread(r.Context(), account, id)
	status, code, outcome := deleteOutcome(err)
	if d.Audit != nil {
		d.Audit("thread_delete", "account:"+account+" "+gone.AuditDetail(id), outcome)
	}
	if code != "" {
		apiJSONStatus(w, status, map[string]any{"error": code})
		return
	}
	apiJSON(w, gone)
}

// deleteOutcome reads a DeleteThread result as the portal answers it: the HTTP status, the refusal
// code ("" for an answer) and the audit outcome. A deletion whose files could not all be taken is
// still a deletion (the orphan sweep takes them later): `ok`, as BatonDeck records it.
func deleteOutcome(err error) (int, string, string) {
	switch {
	case err == nil:
		return http.StatusOK, "", "ok"
	case errors.Is(err, messaging.ErrBadRequest):
		return http.StatusBadRequest, "bad_request", "bad_request"
	case errors.Is(err, messaging.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, "too_large", "too_large"
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found", "not_found"
	default:
		return http.StatusInternalServerError, "internal", "error"
	}
}

// getEvents serves `GET /events`.
func (d InboxDeps) getEvents(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, cancel := d.Bus.Subscribe(account)
	defer cancel()
	fmt.Fprintf(w, ": connected\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-ch:
			if !open {
				return
			}
			// With no account named the subscription is every account's, so each event is held to
			// the accounts the owner administers, read again per event so a membership removed
			// mid-stream stops it. An event is dropped, never answered with an error: an
			// EventSource reconnects on one.
			admins, err := administered(r.Context(), d.Store, OwnerFrom(r.Context()))
			if err != nil || !admins[e.AccountID] {
				continue
			}
			payload, _ := json.Marshal(e)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Kind, payload)
			fl.Flush()
		}
	}
}

var uiMsgCounter = make(chan string, 1)

func init() { uiMsgCounter <- "" }

// newUIMsgID mints a fresh idempotency key for the composer form.
func newUIMsgID() string {
	<-uiMsgCounter
	id := "ui-" + randomHex8()
	uiMsgCounter <- id
	return id
}
