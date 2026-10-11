package internalui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// POST /thread/delete through the whole portal (session, CSRF, account resolution): the
// owner's own conversation is deleted and answered with what went; a thread the account does not
// hold, another owner's account named in the form, and that owner's thread named under one's own
// account are each 404 and touch nothing; a request without the CSRF header never reaches it. Each
// request that reaches the handler writes exactly one thread_delete row.
func TestDeletingAConversationFromThePortal(t *testing.T) {
	ctx := context.Background()
	var rows []string
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		MountInboxPages(mux, InboxDeps{Store: st, Msg: &messaging.Service{Store: st}, Audit: func(a, r, o string) {
			if a == "thread_delete" {
				rows = append(rows, r+" "+o)
			}
		}})
	})
	me, session := e.signIn(t, "Me")
	them, _ := e.signIn(t, "Them")
	mine, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	theirs, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Theirs", Algo: "p256"})
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, them, theirs.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	svc := &messaging.Service{Store: e.st}
	record := func(account, msgID string) string {
		t.Helper()
		r, err := svc.Record(ctx, account, "sha256:friend", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, MsgID: msgID, Text: "hi", Sender: messaging.SenderHuman})
		if err != nil {
			t.Fatal(err)
		}
		return r.ThreadID
	}
	myThread, theirThread := record(mine.ID, "m1"), record(theirs.ID, "t1")

	post := func(path, body string, csrf bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Host = "localhost:8080"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
		if csrf {
			req.Header.Set("X-HDTP-Csrf", "tok")
		}
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	held := func(account, thread string) bool {
		_, err := e.st.GetThread(ctx, account, thread)
		return err == nil
	}

	// No CSRF header: refused before the handler, nothing deleted, nothing audited as a deletion.
	if rec := post("/thread/delete", "thread_id="+myThread+"&account="+mine.ID, false); rec.Code < 400 || !held(mine.ID, myThread) || len(rows) != 0 {
		t.Fatalf("a request without the CSRF header: %d, held=%v, rows=%v", rec.Code, held(mine.ID, myThread), rows)
	}
	// Another owner's account named in the form: 404 at account resolution, before the handler.
	if rec := post("/thread/delete", "thread_id="+theirThread+"&account="+theirs.ID, true); rec.Code != http.StatusNotFound || !held(theirs.ID, theirThread) || len(rows) != 0 {
		t.Fatalf("another owner's account: %d, held=%v, rows=%v", rec.Code, held(theirs.ID, theirThread), rows)
	}
	// Their thread under my account: not a thread my account holds.
	rec := post("/thread/delete", "thread_id="+theirThread+"&account="+mine.ID, true)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"not_found"`) || !held(theirs.ID, theirThread) {
		t.Fatalf("another account's thread under mine: %d %s, held=%v", rec.Code, rec.Body, held(theirs.ID, theirThread))
	}
	if len(rows) != 1 || !strings.HasSuffix(rows[0], " not_found") {
		t.Fatalf("audit after a refusal = %v; want one not_found row", rows)
	}
	// Unknown thread.
	if rec := post("/thread/delete", "thread_id=no-such-thread&account="+mine.ID, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown thread: %d %s", rec.Code, rec.Body)
	}
	// No thread named: the operation's bad_request.
	if rec := post("/thread/delete", "account="+mine.ID, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"bad_request"`) {
		t.Fatalf("no thread_id: %d %s", rec.Code, rec.Body)
	}
	// Mine: deleted, answered with what went, one ok row naming the contact and the counts.
	rows = nil
	rec = post("/thread/delete", "thread_id="+myThread+"&account="+mine.ID, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleting my conversation: %d %s", rec.Code, rec.Body)
	}
	var got messaging.Deleted
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Status != "deleted" || got.ThreadID != myThread || got.Messages != 1 {
		t.Fatalf("answer %s (%v)", rec.Body, err)
	}
	if held(mine.ID, myThread) {
		t.Fatal("the conversation is still there")
	}
	want := "account:" + mine.ID + " contact:sha256:friend thread_id:" + myThread + " messages:1 files:0 ok"
	if len(rows) != 1 || rows[0] != want {
		t.Fatalf("audit = %v; want exactly [%s]", rows, want)
	}
}

// threadIDsAPathCannotCarry are thread ids a contact may choose (HDTP leaves thread_id free) that a
// path segment cannot carry as they are: a URL parser removes "." and ".." (and their percent
// forms) before the request leaves a browser, and Go's mux redirects them; the rest break a path or
// a query that is not encoded. Each must open, send and delete like any other.
var threadIDsAPathCannotCarry = []string{".", "..", "%2e", "%2E%2e", "a/b", "../x", "a+b", "a&b=c", "#x", "?q", "a b", "é", "日本"}

// Every thread id that can exist is reachable at each portal route that takes one: GET /api/thread
// opens it, POST /thread/send sends into it and POST /thread/delete deletes it, each reading the id
// from `thread_id` in the query or the form, through the whole portal (session, CSRF, the mux).
func TestEveryThreadIDOpensSendsAndDeletesFromThePortal(t *testing.T) {
	ctx := context.Background()
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		MountInboxPages(mux, InboxDeps{Store: st, Msg: &messaging.Service{Store: st}})
	})
	me, session := e.signIn(t, "Me")
	mine, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	svc := &messaging.Service{Store: e.st}
	send := func(method, target string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var body *strings.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(method, target, body)
		req.Host = "localhost:8080"
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
			req.Header.Set("X-HDTP-Csrf", "tok")
		}
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	for i, id := range threadIDsAPathCannotCarry {
		if _, err := svc.Record(ctx, mine.ID, "sha256:friend", messaging.DirIn, messaging.Input{
			Origin: messaging.OriginPeer, MsgID: fmt.Sprintf("in-%d", i), ThreadID: id, Text: "hi", Sender: messaging.SenderHuman,
		}); err != nil {
			t.Fatalf("%q: recording: %v", id, err)
		}

		rec := send(http.MethodGet, "/api/thread?"+url.Values{"thread_id": {id}, "account": {mine.ID}}.Encode(), nil)
		var opened struct {
			ThreadID string            `json:"thread_id"`
			Rows     []json.RawMessage `json:"rows"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &opened) != nil || opened.ThreadID != id || len(opened.Rows) != 1 {
			t.Fatalf("%q: opening: %d %s", id, rec.Code, rec.Body)
		}

		rec = send(http.MethodPost, "/thread/send", url.Values{
			"thread_id": {id}, "account": {mine.ID}, "contact": {"sha256:friend"}, "msg_id": {fmt.Sprintf("out-%d", i)}, "text": {"hello"},
		})
		if msgs, _ := svc.Thread(ctx, mine.ID, id); rec.Code != http.StatusSeeOther || len(msgs) != 2 || msgs[1].Direction != "out" {
			t.Fatalf("%q: sending: %d %s, %d messages in the thread", id, rec.Code, rec.Body, len(msgs))
		}

		rec = send(http.MethodPost, "/thread/delete", url.Values{"thread_id": {id}, "account": {mine.ID}})
		var got messaging.Deleted
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.ThreadID != id || got.Messages != 2 {
			t.Fatalf("%q: deleting: %d %s", id, rec.Code, rec.Body)
		}
		if _, err := e.st.GetThread(ctx, mine.ID, id); err == nil {
			t.Fatalf("%q: still there after the delete", id)
		}
		// A second delete finds nothing: the operation's refusal, not a redirect or another route.
		if rec := send(http.MethodPost, "/thread/delete", url.Values{"thread_id": {id}, "account": {mine.ID}}); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"not_found"`) {
			t.Fatalf("%q: deleting again: %d %s", id, rec.Code, rec.Body)
		}
	}
}

// The conversation view names the threads a conversation merges, which is what its Delete deletes.
func TestTheConversationViewNamesItsThreads(t *testing.T) {
	ctx := context.Background()
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		MountMessagePages(mux, MessagesDeps{Store: st})
	})
	me, session := e.signIn(t, "Me")
	mine, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: mine.ID, Fingerprint: "sha256:friend", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	svc := &messaging.Service{Store: e.st}
	var ids []string
	for _, msgID := range []string{"a", "b"} {
		r, err := svc.Record(ctx, mine.ID, "sha256:friend", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, MsgID: msgID, Text: "hi", Sender: messaging.SenderHuman})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ThreadID)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/conversations?account="+mine.ID+"&contact=sha256:friend", nil)
	req.Host = "localhost:8080"
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var got struct {
		Threads  []string `json:"threads"`
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(got.Threads) != 2 || !contains(got.Threads, ids[0]) || !contains(got.Threads, ids[1]) {
		t.Fatalf("threads = %v; want %v", got.Threads, ids)
	}
	if len(got.Messages) != 2 || got.Messages[0].ID == "" {
		t.Fatalf("messages carry no id: %s", rec.Body)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
