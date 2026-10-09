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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// MessagesDeps is what the conversation view needs.
type MessagesDeps struct {
	// Store supplies contacts, threads, messages and the read markers.
	Store store.Store
	// Send delivers AND records. Without it the page can show history but not
	// write, which is the state the portal was in.
	Send func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error)
	// SendMedia is the file counterpart of Send: bytes the owner picked in the
	// browser, delivered through the peer's send_media.
	SendMedia func(ctx context.Context, accountID, contactFpr string, in messaging.Input, filename, mime string, data []byte) (messaging.Result, error)
	// Audit records failed sends; nil records nothing.
	Audit func(action, resource, outcome string)
}

type convContact struct {
	Fpr      string `json:"fingerprint"`
	Name     string `json:"label"`
	Status   string `json:"status"`
	Preview  string `json:"preview"`
	Selected bool   `json:"selected"`
	// Unread is this conversation's unread messages, counted at runtime from the read marker and
	// no further than UnreadCap: `{count: 50, capped: true}` reads "50+" (web/src/words.ts Tally).
	Unread tally `json:"unread"`
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
	Who  string `json:"who"` // agent | human, per HDTP §6.2's mandatory labelling
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
	mux.HandleFunc("POST /messages/read", d.postMessagesRead)
	mux.HandleFunc("POST /messages/send_media", d.postMessagesSendMedia)
	mux.HandleFunc("POST /messages/send", d.postMessagesSend)
}

// ConversationsPage is how many conversations one answer of `GET /api/conversations` lists, most
// recently active first: the page BatonDeck's thread list answers by default (its
// `GET /v1/identities/:slug/threads`, limit 50). A search narrows the list before it is cut, so a
// conversation past the page is one search away; the selected one is always on it.
const ConversationsPage = 50

// UnreadCap is where a conversation's unread count stops, and the page's total too: past it the
// row, or the sidebar's Inbox chip, says "50+". It is BatonDeck's
// BADGE_UNREAD_CAP, so the two inboxes say the same thing about the same backlog. The page
// reads every row's count on every visit, which is why a count is bounded rather than exact.
const UnreadCap = 50

// tally is a count the server may have stopped at a cap: web/src/words.ts's Tally, the shape BatonDeck's
// GET /v1/identities/:slug/badges answers `unread` in. `capped` says there are more than
// `count`.
type tally struct {
	Count  int64 `json:"count"`
	Capped bool  `json:"capped"`
}

// unreadWith counts a conversation's unread messages, no further than UnreadCap. Nothing is
// stored: the count is read from the threads' read markers (threads.last_read_seq) each time.
func unreadWith(ctx context.Context, st store.MessageStore, account, fpr string) (tally, error) {
	n, err := st.UnreadWithContactUpTo(ctx, account, fpr, UnreadCap+1)
	if err != nil {
		return tally{}, err
	}
	if n > UnreadCap {
		return tally{Count: UnreadCap, Capped: true}, nil
	}
	return tally{Count: n}, nil
}

// getAPIConversations serves `GET /api/conversations`.
//
// It answers one page of conversations (ConversationsPage), each with its unread count, and
// `unread`, the page's total, for the sidebar's Inbox chip. The total is the sum of the page's
// counts, stopped at UnreadCap as BatonDeck's Inbox chip is: past it, or when a row stopped at
// its cap, it is `{count: 50, capped: true}`, "50+". Under it, it is exact, or `capped` (a floor,
// "N+") when a conversation past the page holds an unread message too. `more` says there are
// conversations past the page. Reading this changes nothing: a conversation is marked read by
// `POST /messages/read`, which the view sends when it shows one.
func (d MessagesDeps) getAPIConversations(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	selected := r.URL.Query().Get("contact")
	needle := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	list, err := d.Store.ListContacts(r.Context(), account)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	threads, err := d.Store.ListThreadsByAccount(r.Context(), account)
	if err != nil {
		// A conversation list that could not be read is not one with nobody removed.
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	lastByContact := map[string]store.Thread{}
	for _, t := range threads {
		if cur, ok := lastByContact[t.ContactFpr]; !ok || t.LastAt > cur.LastAt {
			lastByContact[t.ContactFpr] = t
		}
	}

	// Computed over EVERY contact, not just the ones shown: a pending
	// impostor sharing an active contact's name is exactly the case where
	// the owner needs the fingerprint on the row they can see. A removed
	// contact's conversation stays, named by what its threads kept.
	former := formerContacts(list, threads)
	labels := labelContacts(append(slices.Clone(list), former...))

	var all []store.Contact
	for _, c := range list {
		// Only somebody you have actually accepted can be written to; a
		// pending request is not yet a correspondent.
		if c.Status != "active" {
			continue
		}
		all = append(all, c)
	}
	all = append(all, former...)
	sort.SliceStable(all, func(i, j int) bool {
		a, b := lastByContact[all[i].Fingerprint], lastByContact[all[j].Fingerprint]
		return a.LastAt > b.LastAt // most recently active first
	})

	// The page: the search first, then the cut, so nobody is out of reach; then the selected
	// conversation, wherever it falls, because the view is showing it.
	var page []store.Contact
	more, onPage := false, map[string]bool{}
	for _, c := range all {
		if needle != "" && !strings.Contains(strings.ToLower(conversationLabel(labels, c)), needle) {
			continue
		}
		if len(page) == ConversationsPage {
			more = true
			continue
		}
		page = append(page, c)
		onPage[c.Fingerprint] = true
	}
	if selected != "" && !onPage[selected] {
		for _, c := range all {
			if c.Fingerprint == selected {
				page = append(page, c)
				onPage[selected] = true
			}
		}
	}

	people := []convContact{}
	total := tally{}
	for _, c := range page {
		unread, err := unreadWith(r.Context(), d.Store, account, c.Fingerprint)
		if err != nil {
			// A count that could not be read is not a count of zero.
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		total.Count += unread.Count
		total.Capped = total.Capped || unread.Capped
		presence, seen := presenceOf(r.Context(), d.Store, account, threads, c)
		people = append(people, convContact{
			Fpr: c.Fingerprint, Name: conversationLabel(labels, c), Status: c.Status,
			Preview:  previewOf(r.Context(), d.Store, account, threads, c.Fingerprint),
			Selected: c.Fingerprint == selected,
			Unread:   unread,
			Presence: presence, LastSeen: seen,
		})
	}
	// Past the page the total is a floor only if something there is unread too: for each thread, a
	// walk from its marker to its first unread message, not a count. "More than N" for a backlog
	// that is all on the page would be false.
	if !total.Capped && len(all) > len(page) {
		withUnread, err := d.Store.ListContactsWithUnread(r.Context(), account)
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		listed := map[string]bool{}
		for _, c := range all {
			listed[c.Fingerprint] = true
		}
		for _, fpr := range withUnread {
			if listed[fpr] && !onPage[fpr] {
				total.Capped = true
				break
			}
		}
	}

	// The chip stops at the same cap as a row and as BatonDeck's ("show 50+ if more than 50"). A row
	// that stopped at the cap puts the sum at it or past it, so it lands here or is 50 capped already;
	// a floor under the cap stays its sum: "50+" for two unread and one past the page would be false.
	if total.Count > UnreadCap {
		total = tally{Count: UnreadCap, Capped: true}
	}

	var chosen *convContact
	for i := range people {
		if people[i].Selected {
			chosen = &people[i]
		}
	}
	var msgs []convMessage
	// through is the newest message of the selected conversation this answer shows: what the view
	// marks read through (POST /messages/read), so a message that lands after it stays unread.
	var through int64
	if chosen != nil {
		// EVERY thread with this contact, merged in time order. A conversation
		// is with a person, not with a thread id: HDTP threads are a shared
		// grouping a peer can start at will (§7), and reading only the newest
		// showed a history one message long.
		for _, m := range historyWith(r.Context(), d.Store, account, threads, chosen.Fpr) {
			through = max(through, m.Seq)
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
		"contacts": people, "messages": msgs, "through": through,
		"unread": total, "more": more,
		// A fresh idempotency key per load: the send form posts it, so a
		// double-submit acknowledges rather than re-sends (HDTP §7).
		"new_msg_id": newUIMsgID(),
	})
}

// postMessagesRead serves `POST /messages/read`: the owner has read a conversation, through the
// message `through` names (the `through` of the `GET /api/conversations` that showed it).
//
// The marker is the reader's own and never wire-visible (SPEC §7.6), so it writes no audit row,
// as BatonDeck's `POST /v1/identities/:slug/threads/:threadId/read` writes no chain row and as
// reading a conversation writes none here: the trail records what was said and done, not every
// glance. It is a high-water mark, never lowered, so a repeat, or a stale mark arriving after a
// newer one, changes nothing. A contact row that is not active (pending, blocked) is 404, and so is
// a `through` that is not a message of this conversation (an unknown contact's, another identity's).
// A removed contact's conversation, which has no row, is marked like an active one's.
func (d MessagesDeps) postMessagesRead(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		apiJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	account := formOrQuery(r, "account")
	contact := r.PostForm.Get("contact")
	through, err := strconv.ParseInt(r.PostForm.Get("through"), 10, 64)
	if contact == "" || err != nil || through <= 0 {
		apiJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	// The list, not GetContact: its "no such row" is each engine's own error, and a store that
	// failed must not answer as a contact that does not exist.
	list, err := d.Store.ListContacts(r.Context(), account)
	if err != nil {
		apiJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": "store"})
		return
	}
	// A removed contact's conversation is read like any other: with no row, ConversationHasMessage
	// below is what says there is a conversation at all.
	if slices.ContainsFunc(list, func(c store.Contact) bool { return c.Fingerprint == contact && c.Status != "active" }) {
		apiJSONStatus(w, http.StatusNotFound, map[string]any{"error": "not_found"})
		return
	}
	ok, err := d.Store.ConversationHasMessage(r.Context(), account, contact, through)
	if err != nil {
		apiJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": "store"})
		return
	}
	if !ok {
		apiJSONStatus(w, http.StatusNotFound, map[string]any{"error": "not_found"})
		return
	}
	if _, err := d.Store.MarkConversationReadThrough(r.Context(), account, contact, through); err != nil {
		apiJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": "store"})
		return
	}
	unread, err := unreadWith(r.Context(), d.Store, account, contact)
	if err != nil {
		apiJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": "store"})
		return
	}
	apiJSON(w, map[string]any{"contact": contact, "unread": unread})
}

// postMessagesSendMedia serves `POST /messages/send_media`.
//
// A file from the composer. Multipart, capped at HDTP §12's 5 MiB before the
// body is read in full; the MIME type is sniffed from the bytes rather than
// trusted from the browser, and the filename is the browser's base name only.
// The account is the query's: the one account resolution checked against the
// owner's memberships, which reads no multipart body (account_resolve.go).
// Answers JSON: an upload is a fetch, not a form the page navigates with.
func (d MessagesDeps) postMessagesSendMedia(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, messaging.MaxMediaBytes+64<<10)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		apiJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "file over 5 MiB, or not a valid upload"})
		return
	}
	account := accountParam(r)
	contact := formOrQuery(r, "contact")
	msgID := r.PostForm.Get("msg_id")
	if account == "" || contact == "" || msgID == "" {
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
		// The portal is a person typing (HDTP §6.2's mandatory labelling);
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
// THEY granted US (HDTP §6.2). Without it there is nothing to show.
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
