package ownermcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// processEnv is a second node process on e's store file: its own store handle, and its own bus
// with its reader running, as serve runs it.
func processEnv(t *testing.T, e *env, path string) *env {
	t.Helper()
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := messaging.NewBus(st)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { bus.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return &env{st: st, owner: e.owner, acctA: e.acctA, acctB: e.acctB,
		deps: Deps{Store: st, Msg: &messaging.Service{Store: st, Bus: bus}, Bus: bus, Contacts: &contacts.Manager{Store: st}}}
}

// An owner agent waiting on one node process wakes for a message another process stored (SPEC
// §7.8): the wait on B parks, A records, and B answers with the thread before its timeout. Its
// cursor is the change log's, so a wait from it on either process sees nothing new; and a wait
// that ends on the clock answers with the newest change it read, never a clock.
func TestAWaitWakesForAChangeAnotherProcessMade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	a := newEnvAt(t, path)
	b := processEnv(t, a, path)
	csB, _ := connect(t, b, auth.Identity{OwnerID: a.owner}, nil)
	ctx := context.Background()

	var start waitResult
	first, _ := callJSON(t, csB, "wait_for_updates", map[string]any{"account_id": a.acctA})
	if err := json.Unmarshal([]byte(first), &start); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		res     waitResult
		elapsed time.Duration
	}
	woke := make(chan answer, 1)
	go func() {
		began := time.Now()
		text, _ := callJSON(t, csB, "wait_for_updates", map[string]any{"account_id": a.acctA, "since": start.Cursor, "timeout_sec": 20})
		var r waitResult
		_ = json.Unmarshal([]byte(text), &r)
		woke <- answer{r, time.Since(began)}
	}()
	time.Sleep(time.Second) // B is parked
	if _, err := a.deps.Msg.Record(ctx, a.acctA, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "x-1", ThreadID: "t-cross", Text: "from A", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	got := <-woke
	if got.res.TimedOut || len(got.res.Threads) != 1 || got.res.Threads[0].ThreadID != "t-cross" {
		t.Fatalf("the wait on B did not wake for A's message: %+v", got.res)
	}
	if got.elapsed > 10*time.Second {
		t.Fatalf("B woke after %s, not at A's change", got.elapsed)
	}
	// From its cursor, nothing is new — on either process.
	for name, cs := range map[string]*env{"A": a, "B": b} {
		res, err := cs.deps.changesSince(ctx, a.acctA, got.res.Cursor)
		if err != nil || len(res.Threads) != 0 {
			t.Fatalf("process %s re-reported what the cursor had passed: %+v %v", name, res, err)
		}
	}
	// A quiet wait ends on the clock with the newest change it read.
	text, _ := callJSON(t, csB, "wait_for_updates", map[string]any{"account_id": a.acctA, "since": got.res.Cursor, "timeout_sec": 1})
	var quiet waitResult
	_ = json.Unmarshal([]byte(text), &quiet)
	_, newest, _ := b.st.ChangeBounds(ctx)
	if !quiet.TimedOut || quiet.Cursor != newest {
		t.Fatalf("a quiet wait answered cursor %d timed_out %v; the log's newest is %d", quiet.Cursor, quiet.TimedOut, newest)
	}
}

// The queues only the owner clears end a wait (waitResult): a contact parked at a new address is
// published as a request (node.OnPending) and an integration whose token died as attention
// (serve.go), and each wakes the wait, which then answers with the queue. It used to re-read the
// store on the wake, find neither counted as news, and park again until the clock ran out.
func TestAWaitAnswersForAParkedAddressAndForAttention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)

	wait := func(t *testing.T, acct string, change func()) waitResult {
		t.Helper()
		var start waitResult
		first, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": acct})
		if err := json.Unmarshal([]byte(first), &start); err != nil {
			t.Fatal(err)
		}
		woke := make(chan waitResult, 1)
		go func() {
			text, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": acct, "since": start.Cursor, "timeout_sec": 4})
			var r waitResult
			_ = json.Unmarshal([]byte(text), &r)
			woke <- r
		}()
		time.Sleep(500 * time.Millisecond) // parked
		change()
		return <-woke
	}

	root, oldLeaf := movedLeaf(t, "Alina", "https://old.example/alina")
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: root, SPKI: []byte{1}, Status: "active",
		Endpoint: "https://old.example/alina", Leaf: oldLeaf, DisplayName: "Alina"}); err != nil {
		t.Fatal(err)
	}
	_, newLeaf := movedLeaf(t, "Alina", "https://new.example/alina")
	got := wait(t, e.acctA, func() {
		if err := e.st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: e.acctA, Root: root, Endpoint: "https://new.example/alina", Leaf: newLeaf, Why: "ask", At: 1}); err != nil {
			t.Error(err)
		}
		e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventRequest, AccountID: e.acctA, ContactFpr: root})
	})
	if got.TimedOut || got.Addresses != 1 {
		t.Errorf("a wait parked while a contact was held at a new address: %+v", got)
	}

	got = wait(t, e.acctB, func() {
		if _, err := e.st.InsertIntegration(ctx, store.Integration{AccountID: e.acctB, Slug: "cal", Transport: "streamable-http",
			Endpoint: "https://cal.example/mcp", AuthKind: "oauth", Status: "auth_error"}); err != nil {
			t.Error(err)
		}
		e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventAttention, AccountID: e.acctB})
	})
	if got.TimedOut || len(got.NeedsAttention) != 1 || got.NeedsAttention[0].Integration != "cal" {
		t.Errorf("a wait parked while an integration needed re-authorizing: %+v", got)
	}
}

// A cursor older than the change log (which keeps a week) is answered as such, at once, rather
// than as if nothing had moved.
func TestACursorOlderThanTheLogIsSaidToBe(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventRequest, AccountID: e.acctA})
	}
	if _, err := e.st.DeleteChangesBefore(ctx, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventRequest, AccountID: e.acctA})
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	began := time.Now()
	text, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA, "since": 1, "timeout_sec": 5})
	if !strings.Contains(text, `"cursor_expired":true`) || time.Since(began) > 3*time.Second {
		t.Fatalf("a cursor the log no longer holds: %s after %s", text, time.Since(began))
	}
	// And the cursor it answers with is current: the next wait is an ordinary one.
	var r waitResult
	_ = json.Unmarshal([]byte(text), &r)
	if next, err := e.deps.changesSince(ctx, e.acctA, r.Cursor); err != nil || next.CursorExpired {
		t.Fatalf("the cursor handed back is still expired: %+v %v", next, err)
	}
}

// A cursor past the log's newest change — one this log never issued: a store restored into a fresh
// log, or a time passed where an id belongs — is said to be, at once, with the newest as the cursor
// to wait from. Answered as an ordinary cursor, every wait from it waited on nothing, forever.
func TestACursorPastTheLogIsSaidToBe(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventRequest, AccountID: e.acctA})
	_, newest, err := e.st.ChangeBounds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	began := time.Now()
	text, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA, "since": newest + 1_790_000_000, "timeout_sec": 5})
	var r waitResult
	_ = json.Unmarshal([]byte(text), &r)
	if !r.CursorExpired || r.Cursor != newest || time.Since(began) > 3*time.Second {
		t.Fatalf("a cursor past the log: %s after %s; want cursor_expired and cursor %d at once", text, time.Since(began), newest)
	}
}
