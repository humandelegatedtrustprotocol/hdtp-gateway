package internalui

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	srv := httptest.NewServer(mux)
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

func TestComposerSendsAsHuman(t *testing.T) {
	mux, msg, _, acct := inboxEnv(t)
	ctx := context.Background()
	in, _ := msg.Record(ctx, acct, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m1", Text: "hello", Sender: messaging.SenderAgent})

	form := url.Values{"text": {"hey!"}, "msg_id": {"ui-1"}}
	req := httptest.NewRequest("POST", "/threads/"+in.ThreadID+"/send?account="+acct+"&contact=sha256:alina",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("composer POST: %d", rr.Code)
	}
	msgs, _ := msg.Thread(ctx, acct, in.ThreadID)
	if len(msgs) != 2 || msgs[1].Sender != "human" || msgs[1].Direction != "out" {
		t.Fatalf("composer message: %+v", msgs)
	}
}

func TestUnreadCountsAcrossTwoContacts(t *testing.T) {
	mux, msg, _, acct := inboxEnv(t)
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

	// opening alina's thread marks it read; bharat stays unread
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/threads/"+a.ThreadID+"?account="+acct, nil))
	if rr.Code != 200 {
		t.Fatalf("thread read: %d", rr.Code)
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
