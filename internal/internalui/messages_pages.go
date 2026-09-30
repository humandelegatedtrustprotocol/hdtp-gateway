package internalui

// The conversation view: contacts on the left, the thread on the right.
//
// Messaging existed end to end — threads, sending, delivery, SSE — and had no way
// IN. `/inbox` listed threads that already existed and `/threads/{id}` opened one,
// so an owner could reply to somebody who had written first and could never start
// a conversation. `send_to_contact` was on the agent surface only. That is why the
// portal looked like it could not send: it could, but only to a thread it had no
// way to create.
//
// Selecting a contact IS the conversation, and sending returns to the same one,
// so the view survives the round trip.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
)

// MessagesDeps is what the conversation view needs.
type MessagesDeps struct {
	Store store.Store
	// Send delivers AND records. Without it the page can show history but not
	// write, which is the state the portal was in.
	Send func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error)
	// SendMedia is the file counterpart of Send: bytes the owner picked in the
	// browser, delivered through the peer's send_media.
	SendMedia func(ctx context.Context, accountID, contactFpr string, in messaging.Input, filename, mime string, data []byte) (messaging.Result, error)
	Audit     func(action, resource, outcome string)
}

type convContact struct {
	Fpr      string `json:"fingerprint"`
	Name     string `json:"label"`
	Status   string `json:"status"`
	Preview  string `json:"preview"`
	Selected bool   `json:"selected"`
	Unread   int    `json:"unread"`
	// Presence is "", "online" or "away".
	//
	// Empty means they have NOT granted us `status.view`, and then nothing is
	// shown at all — a dot for someone who has not agreed to be seen would be
	// inventing a signal we are not entitled to. Granted, it is green when we
	// have confirmed contact with them just now and amber when we have not.
	Presence string `json:"presence"`
	// LastSeen is when that evidence is from (unix seconds), 0 for none. The view says it in the
	// reader's own words and clock (web/src/words.ts `ago`), as every other time on the page.
	LastSeen int64 `json:"last_seen,omitempty"`
}

type convMessage struct {
	Mine bool   `json:"mine"` // right-hand side: we sent it
	Body string `json:"body"`
	Who  string `json:"who"` // agent | human, per PACT §6.2's mandatory labelling
	// TS is when it was written (unix seconds). The view says it (web/src/words.ts `when`): a time
	// formatted here was the host's clock and the host's words, one format of five on the page.
	TS int64 `json:"ts"`
	// Until is when an outbound message still being tried stops being tried (unix seconds), for
	// the line that says so; 0 for any other message.
	Until int64 `json:"until,omitempty"`
	// Media is set when the row is a media message (§7.4). A media row's BODY is
	// a JSON reference, not prose: rendering it raw showed the owner a blob of
	// JSON and gave them nothing to click — the same defect the thread page was
	// fixed for once already, reintroduced here when the conversation view
	// replaced it and looked only at Body.
	Media *convMedia `json:"media,omitempty"`
	State string     `json:"state,omitempty"`
}

// convMedia is what the view needs to offer a media message: a name to show, and
// either something to open (stored bytes) or something to deliberately fetch
// (a URL a contact supplied — never automatic, §7.5).
type convMedia struct {
	Filename string `json:"filename"`
	Mime     string `json:"mime"`
	Size     int64  `json:"size,omitempty"`
	// Hash is set when this node already holds the bytes: GET /media/<hash>.
	Hash string `json:"hash,omitempty"`
	// URL is set when the contact sent a link instead. Fetching it is an
	// owner-initiated act (POST /media/fetch), because auto-fetching an
	// attacker-supplied URL would let any contact drive server-side requests.
	URL string `json:"url,omitempty"`
}

// MountMessagePages registers the conversation view.
func MountMessagePages(mux *http.ServeMux, d MessagesDeps) {
	mux.HandleFunc("GET /api/conversations", d.getAPIConversations)
	mux.HandleFunc("POST /messages/send_media", d.postMessagesSendMedia)
	mux.HandleFunc("POST /messages/send", d.postMessagesSend)
}

// getAPIConversations serves `GET /api/conversations`.
func (d MessagesDeps) getAPIConversations(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	selected := r.URL.Query().Get("contact")

	list, err := d.Store.ListContacts(r.Context(), account)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	threads, _ := d.Store.ListThreadsByAccount(r.Context(), account)
	lastByContact := map[string]store.Thread{}
	for _, t := range threads {
		if cur, ok := lastByContact[t.ContactFpr]; !ok || t.LastAt > cur.LastAt {
			lastByContact[t.ContactFpr] = t
		}
	}

	// Computed over EVERY contact, not just the ones shown: a pending
	// impostor sharing an active contact's name is exactly the case where
	// the owner needs the fingerprint on the row they can see.
	labels := labelContacts(list)

	var people []convContact
	for _, c := range list {
		// Only somebody you have actually accepted can be written to; a
		// pending request is not yet a correspondent.
		if c.Status != "active" {
			continue
		}
		name := labels[c.Fingerprint]
		presence, seen := presenceOf(r.Context(), d.Store, account, threads, c)
		people = append(people, convContact{
			Fpr: c.Fingerprint, Name: name, Status: c.Status,
			Preview:  previewOf(r.Context(), d.Store, account, threads, c.Fingerprint),
			Selected: c.Fingerprint == selected,
			Presence: presence, LastSeen: seen,
		})
	}
	sort.SliceStable(people, func(i, j int) bool {
		a, b := lastByContact[people[i].Fpr], lastByContact[people[j].Fpr]
		return a.LastAt > b.LastAt // most recently active first
	})

	var chosen *convContact
	for i := range people {
		if people[i].Selected {
			chosen = &people[i]
		}
	}
	var msgs []convMessage
	if chosen != nil {
		// EVERY thread with this contact, merged in time order. A conversation
		// is with a person, not with a thread id: PACT threads are a shared
		// grouping a peer can start at will (§7), and reading only the newest
		// showed a history one message long.
		for _, m := range historyWith(r.Context(), d.Store, account, threads, chosen.Fpr) {
			cm := convMessage{
				Mine: m.Direction == "out", Body: m.Body, Who: m.Sender,
				TS: m.CreatedAt, State: deliveryState(m),
			}
			if cm.State == "retrying" {
				cm.Until = m.Deadline()
			}
			if m.Kind == "media" {
				if ref, ok := parseMediaRef(m.Body); ok {
					cm.Media = &convMedia{
						Filename: ref.Filename, Mime: ref.Mime, Size: ref.Size,
						Hash: ref.Hash, URL: ref.URL,
					}
					cm.Body = "" // the reference is not prose; the view renders Media
				}
			}
			msgs = append(msgs, cm)
		}
	}
	apiJSON(w, map[string]any{
		"contacts": people, "messages": msgs,
		// A fresh idempotency key per load: the send form posts it, so a
		// double-submit acknowledges rather than re-sends (PACT §7).
		"new_msg_id": newUIMsgID(),
	})
}

// postMessagesSendMedia serves `POST /messages/send_media`.
//
// A file from the composer. Multipart, capped at PACT §12's 5 MiB before the
// body is read in full; the MIME type is sniffed from the bytes rather than
// trusted from the browser, and the filename is the browser's base name only.
// Answers JSON: an upload is a fetch, not a form the page navigates with.
func (d MessagesDeps) postMessagesSendMedia(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, messaging.MaxMediaBytes+64<<10)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		apiJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "file over 5 MiB, or not a valid upload"})
		return
	}
	account := formOrQuery(r, "account")
	contact := formOrQuery(r, "contact")
	msgID := r.PostForm.Get("msg_id")
	if contact == "" || msgID == "" {
		apiJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "which conversation?"})
		return
	}
	if d.SendMedia == nil {
		apiJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"error": "this node cannot send files yet"})
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		apiJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "no file"})
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, messaging.MaxMediaBytes+1))
	if err != nil || len(data) == 0 || len(data) > messaging.MaxMediaBytes {
		apiJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "file empty or over 5 MiB"})
		return
	}
	name := filepath.Base(hdr.Filename)
	if name == "." || name == "/" || name == "" {
		name = "attachment"
	}
	if len(name) > 200 {
		name = name[:200]
	}
	mime := http.DetectContentType(data)
	if declared := hdr.Header.Get("Content-Type"); declared != "" && strings.HasPrefix(mime, "application/octet-stream") {
		// The sniffer only knows a few dozen types; a declared type wins
		// when the sniff is uninformative, never when it disagrees.
		mime = declared
	}
	in := messaging.Input{
		ThreadID: latestThreadWith(r.Context(), d.Store, account, contact),
		MsgID:    msgID, Origin: messaging.OriginPortal,
	}
	res, err := d.SendMedia(r.Context(), account, contact, in, name, mime, data)
	if err != nil {
		if d.Audit != nil {
			d.Audit("send_media", withAccount(r, "contact:"+contact), "error")
		}
		// Recorded but undelivered is still a message that exists; say which.
		status := http.StatusBadGateway
		if res.ThreadID == "" {
			status = http.StatusBadRequest
		}
		apiJSONStatus(w, status, map[string]any{"error": err.Error(), "recorded": res.ThreadID != ""})
		return
	}
	apiJSON(w, map[string]any{"ok": true, "status": res.Status})
}

// postMessagesSend serves `POST /messages/send`.
func (d MessagesDeps) postMessagesSend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := formOrQuery(r, "account")
	contact := formOrQuery(r, "contact")
	text := strings.TrimSpace(r.PostForm.Get("text"))
	back := func(errMsg string) {
		q := url.Values{"contact": {contact}}
		if account != "" {
			q.Set("account", account)
		}
		if errMsg != "" {
			q.Set("err", errMsg)
		}
		// Back to the SAME conversation: the view must survive sending, and a
		// redirect means a refresh cannot send the message twice.
		http.Redirect(w, r, "/messages?"+q.Encode(), http.StatusSeeOther)
	}
	if text == "" || contact == "" {
		back("nothing to send")
		return
	}
	if d.Send == nil {
		back("this node cannot send yet")
		return
	}
	// Continue the conversation. Leaving ThreadID empty starts a NEW thread per
	// message, which is how the history fragmented into single-message threads.
	in := messaging.Input{
		ThreadID: latestThreadWith(r.Context(), d.Store, account, contact),
		MsgID:    r.PostForm.Get("msg_id"), Text: text,
		// The portal is a person typing (PACT §6.2's mandatory labelling);
		// the owner MCP is what labels a message `agent`.
		Origin: messaging.OriginPortal,
	}
	if _, err := d.Send(r.Context(), account, contact, in); err != nil {
		if d.Audit != nil {
			d.Audit("send_message", withAccount(r, "contact:"+contact), "error")
		}
		back(err.Error())
		return
	}
	back("")
}

// presenceWindow is how recently we must have confirmed contact to call somebody
// online. Long enough to survive a quiet minute, short enough that "online" still
// means something.
const presenceWindow = 5 * time.Minute

// presenceOf answers "can I show whether they are around, and are they?"
//
// The permission comes first and is not ours to assume: `status.view` in what
// THEY granted US (PACT §6.2). Without it there is nothing to show.
//
// With it, the signal is evidence rather than a guess — a message we delivered to
// them, or one they sent us, is proof they were reachable at that moment. No
// probe is sent: asking every contact whether they are up, on every page render,
// would be a burst of traffic to answer a decoration.
func presenceOf(ctx context.Context, st store.MessageStore, account string,
	threads []store.Thread, c store.Contact) (state string, last int64) {

	granted := false
	for _, p := range c.TheirPermissions {
		if p == "status.view" {
			granted = true
			break
		}
	}
	if !granted {
		return "", 0
	}
	for _, m := range historyWith(ctx, st, account, threads, c.Fingerprint) {
		// Inbound at all, or outbound that actually landed.
		if m.Direction == "in" || m.Status == "delivered" {
			if m.CreatedAt > last {
				last = m.CreatedAt
			}
		}
	}
	if last != 0 && time.Since(time.Unix(last, 0)) <= presenceWindow {
		return "online", last
	}
	return "away", last
}

// historyWith is every message exchanged with one contact, oldest first.
func historyWith(ctx context.Context, st store.MessageStore, account string,
	threads []store.Thread, fpr string) []store.Message {

	var all []store.Message
	for _, t := range threads {
		if t.ContactFpr != fpr {
			continue
		}
		rows, err := st.ListMessagesByThread(ctx, account, t.ID)
		if err != nil {
			continue
		}
		all = append(all, rows...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].CreatedAt != all[j].CreatedAt {
			return all[i].CreatedAt < all[j].CreatedAt
		}
		return all[i].Seq < all[j].Seq // same second: the store's order decides
	})
	return all
}

// latestThreadWith is the conversation already under way with a contact, or ""
// when there is none and one should be started.
func latestThreadWith(ctx context.Context, st store.MessageStore, account, fpr string) string {
	threads, err := st.ListThreadsByAccount(ctx, account)
	if err != nil {
		return ""
	}
	best := store.Thread{}
	for _, t := range threads {
		if t.ContactFpr == fpr && t.LastAt >= best.LastAt {
			best = t
		}
	}
	return best.ID
}

// previewOf is the last line of a conversation, for the list.
func previewOf(ctx context.Context, st store.MessageStore, account string,
	threads []store.Thread, fpr string) string {

	rows := historyWith(ctx, st, account, threads, fpr)
	if len(rows) == 0 {
		return ""
	}
	last := rows[len(rows)-1]
	body := last.Body
	if last.Kind == "media" {
		body = "media"
	}
	if len(body) > 48 {
		body = body[:48] + "…"
	}
	if last.Direction == "out" {
		return "you: " + body
	}
	return body
}

// deliveryState is what an outbound message is doing, for the tick-or-clock the
// inbox draws. It separates the two things "pending" used to mean: an attempt
// still in flight (nothing has gone wrong; the first attempt runs inline and
// has a 30s budget) from one that has already failed and is waiting on the
// retry sweep. Showing both as "not delivered yet — retrying" made every
// normal send look like a failure for as long as it took to succeed.
func deliveryState(m store.Message) string {
	if m.Direction != "out" {
		return ""
	}
	switch m.Status {
	case "", "delivered":
		return "delivered"
	case "pending":
		if m.Attempts == 0 {
			return "sending"
		}
		return "retrying"
	case "expired":
		return "expired"
	default:
		return "failed"
	}
}

func shortFpr(f string) string {
	f = strings.TrimPrefix(f, "sha256:")
	if len(f) > 12 {
		return f[:12] + "…"
	}
	return f
}
