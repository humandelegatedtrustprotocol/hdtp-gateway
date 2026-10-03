package internalui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// The conversation answer carries times as instants, never as words: the view says them in the
// reader's own clock and words (web/src/words.ts), one format for every time on both portals. A
// message still being tried carries the deadline the retry sweep reads (store.Message.Deadline), so
// "trying again until" is the sweep's own answer; and the words for a delivery that did not land
// are the view's, from the state, rather than a raw status the page printed after a warning icon.
func TestConversationTimesAreInstants(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	const fpr = "sha256:peer"
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: fpr, Status: "active", DisplayName: "Peer", Card: "BEGIN:VCARD...",
	}); err != nil {
		t.Fatal(err)
	}
	// What they granted us, as their acceptance records it: status.view is what presence needs.
	if err := e.st.SetContactAccepted(ctx, acct.ID, fpr, "BEGIN:VCARD...", []string{"message.text", "status.view"}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	th := store.Thread{ID: "t1", AccountID: acct.ID, ContactFpr: fpr, CreatedAt: now - 7200, LastAt: now}
	if err := e.st.InsertThread(ctx, th); err != nil {
		t.Fatal(err)
	}
	// One they sent two hours ago (the evidence presence reads), and one of ours the sweep is retrying.
	mustMsg(t, e.st, store.Message{AccountID: acct.ID, ContactFpr: fpr, ThreadID: th.ID, MsgID: "in1",
		Direction: "in", Sender: "human", Kind: "text", Status: "delivered", Body: "hello", CreatedAt: now - 7200})
	mustMsg(t, e.st, store.Message{AccountID: acct.ID, ContactFpr: fpr, ThreadID: th.ID, MsgID: "out1",
		Direction: "out", Sender: "human", Kind: "text", Status: "pending", Body: "hi", CreatedAt: now - 60})
	if err := e.st.SetMessageAttempt(ctx, acct.ID, fpr, "out1", 3, now+60); err != nil {
		t.Fatal(err)
	}

	q := url.Values{"account": {acct.ID}, "contact": {fpr}}
	rr := httptest.NewRecorder()
	MessagesDeps{Store: e.st}.getAPIConversations(rr, httptest.NewRequest("GET", "/api/conversations?"+q.Encode(), nil))
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	var got struct {
		Contacts []map[string]any `json:"contacts"`
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Contacts) != 1 || len(got.Messages) != 2 {
		t.Fatalf("contacts %d, messages %d", len(got.Contacts), len(got.Messages))
	}
	c := got.Contacts[0]
	if c["presence"] != "away" || c["last_seen"] != float64(now-7200) {
		t.Errorf("presence %v, last_seen %v; want away, %d", c["presence"], c["last_seen"], now-7200)
	}
	in, out := got.Messages[0], got.Messages[1]
	if in["ts"] != float64(now-7200) || out["ts"] != float64(now-60) {
		t.Errorf("ts %v, %v; want %d, %d", in["ts"], out["ts"], now-7200, now-60)
	}
	if out["state"] != "retrying" || out["until"] != float64(now-60+int64(store.DefaultMessageExpiry/time.Second)) {
		t.Errorf("state %v, until %v; want retrying until the sweep's deadline", out["state"], out["until"])
	}
	if _, ok := in["until"]; ok {
		t.Errorf("an inbound message carries a deadline: %v", in["until"])
	}
	for _, m := range got.Messages {
		for _, k := range []string{"when", "bad", "since"} {
			if _, ok := m[k]; ok {
				t.Errorf("a message still carries %q, a time or a status said in the host's words", k)
			}
		}
	}
	if _, ok := c["since"]; ok {
		t.Errorf("a contact still carries since: %v", c["since"])
	}
}
