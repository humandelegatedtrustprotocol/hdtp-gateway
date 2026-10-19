package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/asks"
)

// askSurface is the story's ask: a TLDR, two ready replies, a field to write one's own and the Send
// button that reads both.
const askSurface = `[{"version":"v0.9.1","createSurface":{"surfaceId":"s1","catalogId":"` + asks.CatalogID + `"}},` +
	`{"version":"v0.9.1","updateComponents":{"surfaceId":"s1","components":[` +
	`{"id":"root","component":"Column","children":["tldr","pick","own","send"]},` +
	`{"id":"tldr","component":"Text","text":"Bob proposes Wed 15:00 for 30 min."},` +
	`{"id":"pick","component":"ChoicePicker","options":[{"label":"Confirm Wed 15:00","value":"confirm"},{"label":"Ask for Thu instead","value":"thu"}],"value":{"path":"/reply"}},` +
	`{"id":"own","component":"TextField","label":"Write my own","value":{"path":"/own"}},` +
	`{"id":"send-label","component":"Text","text":"Send"},` +
	`{"id":"send","component":"Button","child":"send-label","action":{"event":{"name":"answer","context":{"reply":{"path":"/reply"},"own":{"path":"/own"}}}}}]}}]`

// pressed is the A2UI action the card posts when the owner presses Send, its context as resolved
// from the card's data model.
func pressed(button, context string) string {
	return `{"version":"v0.9.1","action":{"name":"answer","surfaceId":"s1","sourceComponentId":"` + button +
		`","timestamp":"2026-10-19T10:00:00Z","context":` + context + `}}`
}

// The asks routes through the whole portal (session, CSRF, account resolution), with the refusals
// of Building rule 3: no session, no CSRF token, an ask that does not exist, another account's ask
// (under one's own account, and with that account named), a malformed answer, an answer to an
// answered ask and a status the list does not take. The control is the owner's own answer, sent as
// the owner's message, once. Then a message the owner writes on the conversation answers the next
// ask, through the send the portal's composer uses.
func TestTheAsksRoutesRefuseWhatTheyMustAndAnswerTheOwnersOwn(t *testing.T) {
	ctx := context.Background()
	var svc *asks.Service
	var msg *messaging.Service
	var sent []messaging.Input
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		msg = &messaging.Service{Store: st, Bus: messaging.NewBus(st)}
		record := func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error) {
			sent = append(sent, in)
			return msg.Record(ctx, accountID, contactFpr, messaging.DirOut, in)
		}
		svc = asks.New(st, msg.Bus, record, func(string, string, string) {}, func(string, string, string) {})
		MountAskPages(mux, AsksDeps{Asks: svc})
		MountMessagePages(mux, MessagesDeps{Store: st, Send: svc.OwnerSend(record)})
	})
	me, session := e.signIn(t, "Me")
	them, _ := e.signIn(t, "Them")
	mine, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Ana", Algo: "p256"})
	theirs, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Zed", Algo: "p256"})
	for owner, acct := range map[string]string{me: mine.ID, them: theirs.ID} {
		if err := e.st.AddMembership(ctx, owner, acct, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	askOn := func(account, msgID string) asks.View {
		t.Helper()
		if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: account, Fingerprint: "sha256:bob", Status: "active"}); err != nil && msgID == "m1" {
			t.Fatal(err)
		}
		in, err := msg.Record(ctx, account, "sha256:bob", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, Sender: messaging.SenderAgent, MsgID: msgID, Text: "Wed 15:00?"})
		if err != nil {
			t.Fatal(err)
		}
		v, err := svc.Ask(ctx, account, in.ThreadID, msgID, []byte(askSurface))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	ask := askOn(mine.ID, "m1")
	theirAsk := askOn(theirs.ID, "m1")

	type answer struct {
		code int
		body map[string]any
	}
	send := func(method, path string, form url.Values, signedIn, csrf bool) answer {
		t.Helper()
		var req *http.Request
		if method == http.MethodGet {
			req = httptest.NewRequest(method, path+"?"+form.Encode(), nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Host = "localhost:8080"
		req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
		if csrf {
			req.Header.Set("X-HDTP-Csrf", "tok")
		}
		if signedIn {
			req.AddCookie(session)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return answer{rec.Code, body}
	}
	as := func(account string, kv ...string) url.Values {
		v := url.Values{"account": {account}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	choose := as(mine.ID, "message", pressed("send", `{"reply":["confirm"],"own":""}`))

	if a := send(http.MethodGet, "/api/asks", as(mine.ID), false, false); a.code != http.StatusUnauthorized {
		t.Fatalf("a read with no session: %d", a.code)
	}
	if a := send(http.MethodPost, "/asks/"+ask.ID+"/answer", choose, false, true); a.code != http.StatusUnauthorized {
		t.Fatalf("an answer with no session: %d", a.code)
	}
	if a := send(http.MethodPost, "/asks/"+ask.ID+"/answer", choose, true, false); a.code != http.StatusForbidden {
		t.Fatalf("an answer with no CSRF token: %d", a.code)
	}
	for name, c := range map[string]struct {
		path string
		form url.Values
		code int
		err  string
	}{
		"an ask that does not exist":              {"/asks/ask_none/answer", choose, http.StatusNotFound, "not_found"},
		"another account's ask, under mine":       {"/asks/" + theirAsk.ID + "/answer", choose, http.StatusNotFound, "not_found"},
		"another account's ask, named":            {"/asks/" + theirAsk.ID + "/answer", as(theirs.ID, "message", pressed("send", `{"reply":["confirm"],"own":""}`)), http.StatusNotFound, ""},
		"no action":                               {"/asks/" + ask.ID + "/answer", as(mine.ID), http.StatusBadRequest, "bad_request"},
		"the old form":                            {"/asks/" + ask.ID + "/answer", as(mine.ID, "component", "pick", "value", "Confirm Wed 15:00"), http.StatusBadRequest, "bad_request"},
		"a reply the ask does not offer":          {"/asks/" + ask.ID + "/answer", as(mine.ID, "message", pressed("send", `{"reply":["fri"],"own":""}`)), http.StatusBadRequest, "bad_request"},
		"a component the ask does not hold":       {"/asks/" + ask.ID + "/answer", as(mine.ID, "message", pressed("nope", `{}`)), http.StatusBadRequest, "bad_request"},
		"nothing written in the write-my-own box": {"/asks/" + ask.ID + "/answer", as(mine.ID, "message", pressed("send", `{"reply":[],"own":" "}`)), http.StatusBadRequest, "bad_request"},
		"an action over its bound": {"/asks/" + ask.ID + "/answer", as(mine.ID, "message", pressed("send", `{"reply":[],"own":"`+strings.Repeat("x", asks.MaxSurfaceBytes)+`"}`)),
			http.StatusRequestEntityTooLarge, "too_large"},
	} {
		a := send(http.MethodPost, c.path, c.form, true, true)
		if a.code != c.code || (c.err != "" && (a.body["error"] != c.err || a.body["detail"] == "")) {
			t.Errorf("%s: %d %v, want %d %s", name, a.code, a.body, c.code, c.err)
		}
	}
	if a := send(http.MethodGet, "/api/asks", as(mine.ID, "status", "answered"), true, false); a.code != http.StatusBadRequest {
		t.Errorf("a status the list does not take: %d", a.code)
	}
	if len(sent) != 0 {
		t.Fatalf("a refused answer sent %+v", sent)
	}

	// The control: the open ask is listed and counted, the owner's tap sends the reply as theirs and
	// answers it, once.
	listed := send(http.MethodGet, "/api/asks", as(mine.ID, "status", "open"), true, false)
	raw, _ := json.Marshal(listed.body)
	if listed.code != http.StatusOK || listed.body["open"] != float64(1) || !strings.Contains(string(raw), ask.ID) || strings.Contains(string(raw), theirAsk.ID) {
		t.Fatalf("the open list: %d %s", listed.code, raw)
	}
	for thread, want := range map[string]bool{ask.ThreadID: true, theirAsk.ThreadID: false} {
		l := send(http.MethodGet, "/api/asks", as(mine.ID, "thread", thread), true, false)
		if raw, _ := json.Marshal(l.body); l.code != http.StatusOK || strings.Contains(string(raw), ask.ID) != want || strings.Contains(string(raw), theirAsk.ID) {
			t.Fatalf("the list of thread %s: %d %s", thread, l.code, raw)
		}
	}
	a := send(http.MethodPost, "/asks/"+ask.ID+"/answer", choose, true, true)
	if a.code != http.StatusOK || a.body["status"] != "answered" || a.body["answer_text"] != `Ana chose: "Confirm Wed 15:00"` {
		t.Fatalf("the owner's answer: %d %v", a.code, a.body)
	}
	if len(sent) != 1 || sent[0].Text != "Confirm Wed 15:00" || sent[0].Origin != messaging.OriginPortal {
		t.Fatalf("sent %+v", sent)
	}
	if again := send(http.MethodPost, "/asks/"+ask.ID+"/answer", choose, true, true); again.code != http.StatusConflict || len(sent) != 1 {
		t.Fatalf("a second tap: %d, sent %d", again.code, len(sent))
	}
	after := send(http.MethodGet, "/api/asks", as(mine.ID), true, false)
	if raw, _ := json.Marshal(after.body); after.body["open"] != float64(0) || !strings.Contains(string(raw), ask.ID) {
		t.Fatalf("every ask after the answer: %s", raw)
	}
	if open := send(http.MethodGet, "/api/asks", as(mine.ID, "status", "open"), true, false); strings.Contains(func() string { b, _ := json.Marshal(open.body); return string(b) }(), ask.ID) {
		t.Fatalf("the answered ask is listed open: %v", open.body)
	}

	// The next ask, answered by the owner typing on the conversation.
	next := askOn(mine.ID, "m2")
	if a := send(http.MethodPost, "/messages/send", as(mine.ID, "contact", "sha256:bob", "text", "Let me check", "msg_id", "ui-1"), true, true); a.code != http.StatusSeeOther {
		t.Fatalf("the composer's send: %d", a.code)
	}
	got, _ := svc.Get(ctx, mine.ID, next.ID)
	if got.Status != "answered" || got.AnswerText != `Ana wrote: "Let me check"` || sent[len(sent)-1].ThreadID != next.ThreadID {
		t.Fatalf("after the owner's message: %+v, sent on %s", got, sent[len(sent)-1].ThreadID)
	}
}
