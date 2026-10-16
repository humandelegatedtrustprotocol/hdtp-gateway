package internalui

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

func inboxEnv(t *testing.T) (*http.ServeMux, *messaging.Service, *messaging.Bus, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	bus := messaging.NewBus(st)
	msg := &messaging.Service{Store: st, Bus: bus}
	mux := http.NewServeMux()
	MountInboxPages(mux, InboxDeps{Store: st, Msg: msg, Bus: bus})
	return mux, msg, bus, a.ID
}

func TestSSEDeliversNewMessageEvent(t *testing.T) {
	mux, msg, _, acct := inboxEnv(t)
	// The stream carries the accounts its owner administers; behind the session gate there always is one.
	owner := ownerOf(t, msg.Store.(*store.SQLite))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, signedIn(r, owner))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/events?account=" + acct)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	// consume the connected comment
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, ": connected") {
		t.Fatalf("preamble: %q %v", line, err)
	}
	_, _ = reader.ReadString('\n')

	// a new inbound message publishes onto the open stream
	if _, err := msg.Record(context.Background(), acct, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m1", Text: "hi", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}

	got := make(chan string, 1)
	go func() {
		for {
			l, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(l, "data: ") {
				got <- l
				return
			}
		}
	}()
	select {
	case l := <-got:
		if !strings.Contains(l, `"kind":"message"`) || !strings.Contains(l, acct) {
			t.Fatalf("event payload: %q", l)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no SSE event")
	}
}

// The conversation form sends as a person: the portal names its origin and the label is derived
// from it, never a parameter (SPEC §7.2).
func TestComposerSendsAsHuman(t *testing.T) {
	_, msg, _, acct := inboxEnv(t)
	ctx := context.Background()
	if _, err := msg.Record(ctx, acct, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m1", Text: "hello", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountMessagePages(mux, MessagesDeps{Store: msg.Store.(*store.SQLite), Send: func(ctx context.Context, a, c string, in messaging.Input) (messaging.Result, error) {
		return msg.Record(ctx, a, c, messaging.DirOut, in)
	}})
	form := url.Values{"text": {"hey!"}, "msg_id": {"ui-1"}, "contact": {"sha256:alina"}, "account": {acct}}
	req := httptest.NewRequest("POST", "/messages/send", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther || strings.Contains(rr.Header().Get("Location"), "err=") {
		t.Fatalf("composer POST: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	threads, _ := msg.Store.ListThreadsByAccount(ctx, acct)
	if len(threads) != 1 {
		t.Fatalf("threads: %+v", threads)
	}
	msgs, _ := msg.Thread(ctx, acct, threads[0].ID)
	if len(msgs) != 2 || msgs[1].Sender != "human" || msgs[1].Direction != "out" {
		t.Fatalf("composer message: %+v", msgs)
	}
}

func TestUnreadCountsAcrossTwoContacts(t *testing.T) {
	_, msg, _, acct := inboxEnv(t)
	ctx := context.Background()
	a, _ := msg.Record(ctx, acct, "sha256:alina", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, MsgID: "a1", Text: "1", Sender: messaging.SenderAgent})
	_, _ = msg.Record(ctx, acct, "sha256:alina", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, MsgID: "a2", ThreadID: a.ThreadID, Text: "2", Sender: messaging.SenderAgent})
	b, _ := msg.Record(ctx, acct, "sha256:bharat", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, MsgID: "b1", Text: "1", Sender: messaging.SenderAgent})

	st := msg.Store
	if n, _ := st.UnreadCount(ctx, acct, a.ThreadID); n != 2 {
		t.Fatalf("alina unread = %d, want 2", n)
	}
	if n, _ := st.UnreadCount(ctx, acct, b.ThreadID); n != 1 {
		t.Fatalf("bharat unread = %d, want 1", n)
	}

	// reading alina's conversation through her newest message marks it read; bharat stays unread
	msgs, _ := msg.Thread(ctx, acct, a.ThreadID)
	mux := http.NewServeMux()
	MountMessagePages(mux, MessagesDeps{Store: st.(*store.SQLite)})
	form := url.Values{"account": {acct}, "contact": {"sha256:alina"}, "through": {strconv.FormatInt(msgs[len(msgs)-1].Seq, 10)}}
	req := httptest.NewRequest("POST", "/messages/read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("conversation read: %d %s", rr.Code, rr.Body)
	}
	if n, _ := st.UnreadCount(ctx, acct, a.ThreadID); n != 0 {
		t.Fatalf("alina unread after open = %d", n)
	}
	if n, _ := st.UnreadCount(ctx, acct, b.ThreadID); n != 1 {
		t.Fatalf("bharat unread changed: %d", n)
	}
	// outbound sends never count as unread
	_, _ = msg.Record(ctx, acct, "sha256:alina", messaging.DirOut, messaging.Input{Origin: messaging.OriginPeer, MsgID: "a3", ThreadID: a.ThreadID, Text: "reply", Sender: messaging.SenderHuman})
	if n, _ := st.UnreadCount(ctx, acct, a.ThreadID); n != 0 {
		t.Fatalf("outbound counted as unread: %d", n)
	}
}
