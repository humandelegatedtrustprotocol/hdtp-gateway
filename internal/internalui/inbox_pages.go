package internalui

// Inbox pages + the SSE event stream (SPEC §8.2, §7.6). The composer sends as
// SenderHuman — the sender label is derived from this surface, never a parameter
// (SPEC §7.2).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
)

type InboxDeps struct {
	Store store.Store
	Msg   *messaging.Service
	Bus   *messaging.Bus
	// Send delivers an owner-composed message to the contact AND records it.
	// It is a seam because `internal/messaging` has no path to the wire — it
	// imports only the store — so a page wired straight to Msg.Record wrote a
	// row, said "delivered", and sent nothing. nil keeps the old record-only
	// behaviour for tests that do not compose a node.
	Send func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error)
}

// formOrQuery prefers the form body and falls back to the query, so a link and a
// form can both reach the same handler.
func formOrQuery(r *http.Request, key string) string {
	if v := r.PostFormValue(key); v != "" {
		return v
	}
	return r.URL.Query().Get(key)
}

func MountInboxPages(mux *http.ServeMux, d InboxDeps) {
	mux.HandleFunc("GET /api/inbox", d.getAPIInbox)
	mux.HandleFunc("GET /api/threads/{id}", d.getAPIThreadsID)
	mux.HandleFunc("POST /threads/{id}/send", d.postThreadsIDSend)
	mux.HandleFunc("GET /events", d.getEvents)
}

// getAPIInbox serves `GET /api/inbox`.
func (d InboxDeps) getAPIInbox(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	threads, err := d.Store.ListThreadsByAccount(r.Context(), account)
	if err != nil {
		http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
		return
	}
	unread := map[string]int64{}
	for _, th := range threads {
		n, _ := d.Store.UnreadCount(r.Context(), account, th.ID)
		unread[th.ID] = n
	}
	apiJSON(w, map[string]any{"threads": threads, "unread": unread})
}

// getAPIThreadsID serves `GET /api/threads/{id}`.
func (d InboxDeps) getAPIThreadsID(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	id := r.PathValue("id")
	msgs, err := d.Msg.Thread(r.Context(), account, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// opening a thread reads it (local state only, SPEC §7.6)
	_ = d.Store.MarkThreadRead(r.Context(), account, id)
	contact := ""
	if len(msgs) > 0 {
		contact = msgs[0].ContactFpr
	}
	// A media row's body is a JSON reference, not prose. Rendering it raw
	// showed the owner a blob of JSON and gave them nothing to click, which
	// is why "click-to-fetch" was never true (§7.4, §8.2).
	type row struct {
		store.Message
		Media *mediaRef
	}
	rows := make([]row, 0, len(msgs))
	for _, m := range msgs {
		r := row{Message: m}
		if m.Kind == "media" {
			if ref, ok := parseMediaRef(m.Body); ok {
				r.Media = &ref
			}
		}
		rows = append(rows, r)
	}
	apiJSON(w, map[string]any{
		"thread_id": id, "rows": rows, "contact": contact, "new_msg_id": newUIMsgID(),
	})
}

// postThreadsIDSend serves `POST /threads/{id}/send`.
func (d InboxDeps) postThreadsIDSend(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// Both travel in the form BODY: nothing about which identity or which
	// contact belongs in the address bar.
	account := formOrQuery(r, "account")
	contact := formOrQuery(r, "contact")
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// The portal surface fixes the label: human (SPEC §7.2).
	in := messaging.Input{
		MsgID: r.Form.Get("msg_id"), ThreadID: id,
		Text: r.Form.Get("text"), Origin: messaging.OriginPortal,
	}
	send := d.Send
	if send == nil {
		send = func(ctx context.Context, a, c string, in messaging.Input) (messaging.Result, error) {
			return d.Msg.Record(ctx, a, c, messaging.DirOut, in)
		}
	}
	if _, err := send(r.Context(), account, contact, in); err != nil {
		// The message IS recorded — SendMessage writes before it dials — so
		// this reports a delivery failure, not a lost message.
		http.Error(w, "recorded, but delivery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/threads/"+id+"?account="+account, http.StatusSeeOther)
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
