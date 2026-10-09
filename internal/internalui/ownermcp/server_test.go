package ownermcp

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

type env struct {
	st    *store.SQLite
	deps  Deps
	owner string
	acctA string
	acctB string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvAt(t, filepath.Join(t.TempDir(), "o.db"))
}

// newEnvAt is newEnv on the store file at path.
func newEnvAt(t *testing.T, path string) *env {
	t.Helper()
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	o, _ := st.CreateOwnerWithID(ctx, "", "Sumit")
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "work", DisplayName: "Work", Algo: "p256"})
	b, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "home", DisplayName: "Home", Algo: "p256"})
	_ = st.AddMembership(ctx, o.ID, a.ID, "admin")
	_ = st.AddMembership(ctx, o.ID, b.ID, "admin")
	bus := messaging.NewBus(st)
	msg := &messaging.Service{Store: st, Bus: bus}
	return &env{
		st: st, owner: o.ID, acctA: a.ID, acctB: b.ID,
		deps: Deps{Store: st, Msg: msg, Bus: bus, Contacts: &contacts.Manager{Store: st}},
	}
}

func connect(t *testing.T, e *env, ident auth.Identity, opts *mcp.ClientOptions) (*mcp.ClientSession, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServerWithExtra(e.deps, Extra{}, ident)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, opts)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); cancel() })
	return cs, cancel
}

func callJSON(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	return text, res.IsError
}

// SPEC §8.5: the surface is stateless, so it declares tools and resources and neither list-change
// notifications nor resource subscriptions — nothing would carry them (a subscribe over the wire is
// refused: cli's TestTheOwnerMCPIsStateless). A message is found with `wait_for_updates` and read through the inbox resource and
// the thread's own.
func TestTheOwnerSurfaceOffersNoSubscriptionsAndAMessageIsReadable(t *testing.T) {
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	caps := cs.InitializeResult().Capabilities
	if caps.Tools == nil || caps.Resources == nil {
		t.Fatalf("the owner surface does not declare its tools and resources: %+v", caps)
	}
	if caps.Tools.ListChanged || caps.Resources.ListChanged || caps.Resources.Subscribe {
		t.Fatalf("a stateless surface declared a notification it cannot deliver: tools %+v resources %+v", caps.Tools, caps.Resources)
	}
	first, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA})
	var start struct {
		Cursor int64 `json:"cursor"`
	}
	if err := json.Unmarshal([]byte(first), &start); err != nil {
		t.Fatalf("first wait: %s", first)
	}
	const threadID = "t-readable"
	if _, err := e.deps.Msg.Record(context.Background(), e.acctA, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m1", ThreadID: threadID, Text: "hi", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	moved, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA, "since": start.Cursor, "timeout_sec": 5})
	if !strings.Contains(moved, threadID) {
		t.Fatalf("the wait did not report the thread that moved: %s", moved)
	}
	rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: URIInbox})
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]int64
	_ = json.Unmarshal([]byte(rr.Contents[0].Text), &summary)
	if summary[e.acctA] != 1 {
		t.Fatalf("inbox summary: %v", summary)
	}
	th, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: URIThreadPrefix + threadID})
	if err != nil || !strings.Contains(th.Contents[0].Text, `"hi"`) {
		t.Fatalf("thread resource: %v", err)
	}
}

// read_thread is the owner MCP's read action: the agent reading is the owner reading, as HDTP
// Cloud's read_thread is, so it marks the thread read through the newest message it hands over,
// and what lands after stays unread.
func TestReadThreadMarksTheThreadReadThroughWhatItReturned(t *testing.T) {
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	ctx := context.Background()
	const threadID = "t-read"
	for _, id := range []string{"m1", "m2"} {
		if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn,
			messaging.Input{Origin: messaging.OriginPeer, MsgID: id, ThreadID: threadID, Text: id, Sender: messaging.SenderAgent}); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := e.st.UnreadCount(ctx, e.acctA, threadID); n != 2 {
		t.Fatalf("before reading: %d unread, want 2", n)
	}
	if text, isErr := callJSON(t, cs, "read_thread", map[string]any{"account_id": e.acctA, "thread_id": threadID}); isErr || !strings.Contains(text, `"m2"`) {
		t.Fatalf("read_thread: %s", text)
	}
	if n, _ := e.st.UnreadCount(ctx, e.acctA, threadID); n != 0 {
		t.Fatalf("after read_thread: %d unread, want 0", n)
	}
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m3", ThreadID: threadID, Text: "m3", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.st.UnreadCount(ctx, e.acctA, threadID); n != 1 {
		t.Fatalf("a message after the read: %d unread, want 1", n)
	}
}

func TestSendToContactStoresAgentLabel(t *testing.T) {
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "send_to_contact", map[string]any{
		"account_id": e.acctA, "contact_fpr": "sha256:alina", "msg_id": "m1", "text": "from my agent",
	})
	if isErr {
		t.Fatalf("send failed: %s", text)
	}
	var res messaging.Result
	_ = json.Unmarshal([]byte(text), &res)
	msgs, _ := e.deps.Msg.Thread(context.Background(), e.acctA, res.ThreadID)
	if len(msgs) != 1 || msgs[0].Sender != "agent" || msgs[0].Direction != "out" {
		t.Fatalf("message: %+v", msgs)
	}
}

// SPEC §7: the agent starts a thread with a topic, and is told when it gives one for a thread that exists.
func TestSendToContactStartsAThreadWithItsTopic(t *testing.T) {
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "send_to_contact", map[string]any{
		"account_id": e.acctA, "contact_fpr": "sha256:alina", "msg_id": "m1", "text": "coffee?", "topic": "Coffee catch-up",
	})
	if isErr {
		t.Fatalf("send failed: %s", text)
	}
	var res messaging.Result
	_ = json.Unmarshal([]byte(text), &res)
	if th, err := e.st.GetThread(context.Background(), e.acctA, res.ThreadID); err != nil || th.Topic != "Coffee catch-up" {
		t.Fatalf("thread: %+v %v", th, err)
	}
	if text, isErr := callJSON(t, cs, "send_to_contact", map[string]any{
		"account_id": e.acctA, "contact_fpr": "sha256:alina", "msg_id": "m2", "text": "renamed?", "thread_id": res.ThreadID, "topic": "Another",
	}); !isErr || !strings.Contains(text, "bad_request") {
		t.Fatalf("a topic for a thread that exists: %s", text)
	}
}

func TestTokenAccountScopingEnforced(t *testing.T) {
	e := newEnv(t)
	// token narrowed to account A: B must be invisible and denied
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner, AccountID: e.acctA}, nil)

	text, _ := callJSON(t, cs, "list_accounts", nil)
	if strings.Contains(text, e.acctB) {
		t.Fatalf("scoped token sees foreign account: %s", text)
	}
	_, isErr := callJSON(t, cs, "get_inbox", map[string]any{"account_id": e.acctB})
	if !isErr {
		t.Fatal("scoped token acted on foreign account")
	}
	_, isErr = callJSON(t, cs, "send_to_contact", map[string]any{
		"account_id": e.acctB, "contact_fpr": "sha256:x", "msg_id": "m1", "text": "no",
	})
	if !isErr {
		t.Fatal("scoped token sent from foreign account")
	}
	// the permitted account still works
	if _, isErr := callJSON(t, cs, "get_inbox", map[string]any{"account_id": e.acctA}); isErr {
		t.Fatal("scoped token denied its own account")
	}
}

func TestPollToolsMatchResources(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, _ = e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m1", Text: "hi", Sender: messaging.SenderAgent})
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil) // no subscriptions at all

	text, isErr := callJSON(t, cs, "get_inbox", map[string]any{"account_id": e.acctA})
	if isErr {
		t.Fatalf("get_inbox: %s", text)
	}
	if !strings.Contains(text, `"unread":1`) {
		t.Fatalf("poll data: %s", text)
	}
	// approve flow + trust flag via tools
	kp := "sha256:pend"
	_, _ = e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: kp, Status: "pending_in", SPKI: []byte{1}})
	if _, isErr := callJSON(t, cs, "approve_contact", map[string]any{"account_id": e.acctA, "contact_fpr": kp, "preset": "friend"}); isErr {
		t.Fatal("approve failed")
	}
	c, _ := e.st.GetContact(ctx, e.acctA, kp)
	if c.Status != "active" || c.Preset != "friend" {
		t.Fatalf("approve result: %+v", c)
	}
	if _, isErr := callJSON(t, cs, "set_trust_flag", map[string]any{"account_id": e.acctA, "contact_fpr": kp, "trust": "may_instruct"}); isErr {
		t.Fatal("trust set failed")
	}
	text, _ = callJSON(t, cs, "read_thread", map[string]any{"account_id": e.acctA, "thread_id": threadOf(t, e)})
	if !strings.Contains(text, `"trust":"messages_only"`) {
		t.Fatalf("trust label missing from agent payload: %s", text)
	}
}

func threadOf(t *testing.T, e *env) string {
	t.Helper()
	threads, err := e.st.ListThreadsByAccount(context.Background(), e.acctA)
	if err != nil || len(threads) == 0 {
		t.Fatal("no thread")
	}
	return threads[0].ID
}

// AC (P14-05e): a switchboard change made through the owner MCP must reconcile
// the caller's live server, exactly as the portal's contact pages already did.
//
// approve_contact wrote the store and stopped there. The per-caller MCP server is
// cached, so the approved contact kept being served the GUEST surface until the
// node restarted — the owner's agent could approve someone who then could not send
// a message. Found end to end by the harness: bob's tools/list stayed
// [redeem_invite request_contact sealed_call] after approval and became the full
// contact tier only after `docker restart`.
func TestOwnerMCPApprovalReconcilesTheCallersServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	var invalidated []string
	e.deps.Invalidate = func(_ context.Context, accountID, fpr string) error {
		invalidated = append(invalidated, accountID+"/"+fpr)
		return nil
	}

	const fpr = "sha256:pendingpeer"
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acctA, Fingerprint: fpr, SPKI: []byte("x"), Status: "pending_in",
	}); err != nil {
		t.Fatal(err)
	}

	cs, cancel := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	defer cancel()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "approve_contact",
		Arguments: map[string]any{"account_id": e.acctA, "contact_fpr": fpr, "preset": "friend"},
	}); err != nil {
		t.Fatalf("approve_contact: %v", err)
	}

	if len(invalidated) == 0 {
		t.Fatal("approving through the owner MCP never reconciled the caller's server — " +
			"the contact stays at guest tier until the node restarts")
	}
	if invalidated[0] != e.acctA+"/"+fpr {
		t.Errorf("reconciled %q, want %q", invalidated[0], e.acctA+"/"+fpr)
	}
}

// An agent that is not holding a subscription still has to learn that something
// happened, and an agent that reconnects has to learn what it missed. The bus
// serves neither: it pushes to attached sessions and drops events when a
// subscriber is full. wait_for_updates is the resumable half.
func TestWaitForUpdatesStartsCleanBlocksAndReportsWhatMoved(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)

	// A first call has no backlog to replay: it hands back a cursor.
	text, isErr := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA})
	if isErr {
		t.Fatalf("wait_for_updates: %s", text)
	}
	var first struct {
		Cursor  int64 `json:"cursor"`
		Threads []struct {
			ThreadID string `json:"thread_id"`
		} `json:"threads"`
	}
	if err := json.Unmarshal([]byte(text), &first); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `"cursor":`) || len(first.Threads) != 0 {
		t.Fatalf("a first call replayed history or gave no cursor: %s", text)
	}

	// The bound is the hosted edition's: 1 to 25 seconds (WaitMaxSec). 0 would answer at once
	// and a loop on it would spin; above 25 is refused rather than clamped, as the cloud refuses it.
	for _, bad := range []int{0, -1, 26, 50} {
		text, isErr := callJSON(t, cs, "wait_for_updates", map[string]any{
			"account_id": e.acctA, "since": first.Cursor, "timeout_sec": bad})
		if !isErr || !strings.Contains(text, `"code":"bad_request"`) {
			t.Fatalf("timeout_sec %d was not refused as bad_request: %s", bad, text)
		}
	}

	// With nothing happening it waits rather than spinning, and says so.
	start := time.Now()
	text, _ = callJSON(t, cs, "wait_for_updates", map[string]any{
		"account_id": e.acctA, "since": first.Cursor, "timeout_sec": 1})
	if waited := time.Since(start); waited < 900*time.Millisecond {
		t.Fatalf("returned in %v without waiting: %s", waited, text)
	}
	if !strings.Contains(text, `"timed_out":true`) {
		t.Fatalf("a wait that ended on the clock did not say so: %s", text)
	}

	// A message that lands after the cursor is what the next call reports.
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "w1", Text: "dinner friday?", Sender: messaging.SenderHuman}); err != nil {
		t.Fatal(err)
	}
	text, isErr = callJSON(t, cs, "wait_for_updates", map[string]any{
		"account_id": e.acctA, "since": first.Cursor, "timeout_sec": 2})
	if isErr {
		t.Fatalf("wait_for_updates: %s", text)
	}
	if !strings.Contains(text, "sha256:alina") || !strings.Contains(text, `"unread":1`) {
		t.Fatalf("the message that arrived was not reported: %s", text)
	}

	// And the digest answers the end-of-day question in one call.
	text, isErr = callJSON(t, cs, "digest", map[string]any{"account_id": e.acctA})
	if isErr {
		t.Fatalf("digest: %s", text)
	}
	if !strings.Contains(text, `"in":1`) || !strings.Contains(text, `"awaiting_reply":true`) {
		t.Fatalf("digest did not report an unanswered inbound message: %s", text)
	}
}

// The change feed says WHO may instruct, WHAT contacts did beyond messaging,
// and what only the owner can fix — the triage inputs an agent loop needs
// without reading a single untrusted body.
func TestChangeFeedCarriesTrustCallsAndAttention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acctA, Fingerprint: "sha256:carol", SPKI: []byte{1}, Status: "active",
		DisplayName: "Carol",
	}); err != nil {
		t.Fatal(err)
	}
	// InsertContact leaves the schema default; the flag is set the way the
	// portal and the owner tool set it.
	if err := e.st.UpdateContactTrust(ctx, e.acctA, "sha256:carol", "may_instruct"); err != nil {
		t.Fatal(err)
	}
	// Everything below comes after this cursor.
	_, since, err := e.st.ChangeBounds(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Carol messaged (a thread) AND booked a slot (a call the node publishes).
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:carol", messaging.DirIn, messaging.Input{
		MsgID: "m-1", Text: "hello", Sender: "agent", Origin: messaging.OriginPeer,
	}); err != nil {
		t.Fatal(err)
	}
	call := func(account, fpr, tool string) {
		e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventCall, AccountID: account, ContactFpr: fpr, Ref: tool})
	}
	call(e.acctA, "sha256:carol", "book_slot")
	// Not another account's call, nor a tool that is not a feed call (the sealed wrapper), nor a
	// caller this account has no contact row for.
	call(e.acctB, "sha256:dave", "book_slot")
	call(e.acctA, "sha256:carol", "sealed_call")
	call(e.acctA, "sha256:ghost", "book_slot")

	// An integration whose token died is the owner's to fix.
	if _, err := e.st.InsertIntegration(ctx, store.Integration{
		AccountID: e.acctA, Slug: "batondeck", Transport: "streamable-http",
		Endpoint: "https://mcp.example/mcp", AuthKind: "oauth", Status: "auth_error",
	}); err != nil {
		t.Fatal(err)
	}

	res, err := e.deps.changesSince(ctx, e.acctA, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Threads) != 1 || res.Threads[0].Trust != "may_instruct" {
		t.Fatalf("thread trust label: %+v", res.Threads)
	}
	if len(res.Calls) != 1 || res.Calls[0].Tool != "book_slot" ||
		res.Calls[0].ContactFpr != "sha256:carol" || res.Calls[0].Trust != "may_instruct" {
		t.Fatalf("calls: %+v", res.Calls)
	}
	if len(res.NeedsAttention) != 1 || res.NeedsAttention[0].Integration != "batondeck" ||
		res.NeedsAttention[0].Kind != "integration_auth" {
		t.Fatalf("needs_attention: %+v", res.NeedsAttention)
	}
	// The cursor advanced past the call, so the next poll does not replay it.
	if again, err := e.deps.changesSince(ctx, e.acctA, res.Cursor); err != nil || len(again.Calls) != 0 || len(again.Threads) != 0 {
		t.Fatalf("the cursor did not advance past what it reported: %+v %v", again, err)
	}
}

// A thread whose contact row is gone still reports a label — the LOWEST one.
// An empty label would be a third trust state nobody defined (SPEC 7.6), and
// an elevated one would hand a removed contact a dead contact's grant.
func TestFeedFailsSafeOnAMissingContactRow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acctA, Fingerprint: "sha256:gone", SPKI: []byte{2}, Status: "active",
		DisplayName: "Gone",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpdateContactTrust(ctx, e.acctA, "sha256:gone", "may_instruct"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:gone", messaging.DirIn, messaging.Input{
		MsgID: "m-gone", Text: "still here?", Sender: "agent", Origin: messaging.OriginPeer,
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.DeleteContact(ctx, e.acctA, "sha256:gone"); err != nil {
		t.Fatal(err)
	}
	res, err := e.deps.changesSince(ctx, e.acctA, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Threads) != 1 || res.Threads[0].Trust != "messages_only" {
		t.Fatalf("a removed contact's thread must fail safe to messages_only: %+v", res.Threads)
	}
}

// The flag accepts exactly its two values; anything else is refused with the
// stored flag untouched.
func TestTrustFlagRejectsUnknownValues(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.acctA, Fingerprint: "sha256:frank", SPKI: []byte{3}, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "set_trust_flag", Arguments: map[string]any{
		"account_id": e.acctA, "contact_fpr": "sha256:frank", "trust": "root_access",
	}})
	if err == nil && !res.IsError {
		t.Fatal("a made-up trust value was accepted")
	}
	c, err := e.st.GetContact(ctx, e.acctA, "sha256:frank")
	if err != nil || c.TrustFlag != "messages_only" {
		t.Fatalf("the stored flag moved on a refused write: %+v (%v)", c, err)
	}
}

// refresh_contact names ONE contact and says what was found. There was a contact-sweep tool here that
// took an account and swept every contact it had; the tool that replaced it has no form that names
// nobody, and a token narrowed to one identity reaches no contact of another.
func TestRefreshContactNamesOneContactOfTheCallersAccount(t *testing.T) {
	e := newEnv(t)
	type asked struct{ account, fpr string }
	var calls []asked
	e.deps.RefreshContact = func(_ context.Context, accountID, fpr string) (string, string, error) {
		calls = append(calls, asked{accountID, fpr})
		if fpr == "sha256:gone" {
			return "", "", errors.New("unknown contact")
		}
		return "refused", "the chain it answered with fails rule 5", nil
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner, AccountID: e.acctA}, nil)

	sweep := "sync_contacts"
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Name == sweep {
			t.Fatal(sweep + " is still offered: no tool refreshes more than one contact")
		}
	}

	text, isErr := callJSON(t, cs, "refresh_contact", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:alina"})
	if isErr {
		t.Fatalf("refresh_contact: %s", text)
	}
	var got struct{ Outcome, Why string }
	if err := json.Unmarshal([]byte(text), &got); err != nil || got.Outcome != "refused" || !strings.Contains(got.Why, "rule 5") {
		t.Fatalf("the agent must be told what was found and why: %s", text)
	}
	// Another identity's contact: denied before anything is dialled.
	if _, isErr := callJSON(t, cs, "refresh_contact", map[string]any{"account_id": e.acctB, "contact_fpr": "sha256:alina"}); !isErr {
		t.Fatal("a token narrowed to one account refreshed a contact of another")
	}
	// A contact that cannot be called is an error, not an outcome about a peer.
	if _, isErr := callJSON(t, cs, "refresh_contact", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:gone"}); !isErr {
		t.Fatal("refreshing nobody answered as though somebody had been asked")
	}
	want := []asked{{e.acctA, "sha256:alina"}, {e.acctA, "sha256:gone"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("the node was asked for %v, want exactly %v", calls, want)
	}
}

// get_inbox keeps a removed contact's thread and says so: removed_contact carries the names the
// thread kept when the row was deleted, null while a row names the fingerprint; a contact added
// again is held, and the field is null again.
func TestGetInboxSaysWhichThreadsLostTheirContact(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:alina", Status: "active", DisplayName: "Alina", SPKI: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m1", Text: "hi", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	type kept struct {
		DisplayName string `json:"display_name"`
		Petname     string `json:"petname"`
	}
	inbox := func() []struct {
		ContactFpr     string `json:"contact_fpr"`
		Unread         int64  `json:"unread"`
		ContactStatus  string `json:"contact_status"`
		RemovedContact *kept  `json:"removed_contact"`
	} {
		t.Helper()
		text, isErr := callJSON(t, cs, "get_inbox", map[string]any{"account_id": e.acctA})
		if isErr {
			t.Fatalf("get_inbox: %s", text)
		}
		if !strings.Contains(text, `"removed_contact":`) || !strings.Contains(text, `"contact_status":`) {
			t.Fatalf("no removed_contact member: %s", text)
		}
		var rows []struct {
			ContactFpr     string `json:"contact_fpr"`
			Unread         int64  `json:"unread"`
			ContactStatus  string `json:"contact_status"`
			RemovedContact *kept  `json:"removed_contact"`
		}
		if err := json.Unmarshal([]byte(text), &rows); err != nil || len(rows) != 1 {
			t.Fatalf("get_inbox rows: %v %s", err, text)
		}
		return rows
	}
	if r := inbox()[0]; r.RemovedContact != nil || r.ContactStatus != "active" {
		t.Fatalf("a held contact's thread: %q %+v", r.ContactStatus, r.RemovedContact)
	}
	if err := e.st.SetContactPetname(ctx, e.acctA, "sha256:alina", "Alina from the bakery"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.DeleteContact(ctx, e.acctA, "sha256:alina"); err != nil {
		t.Fatal(err)
	}
	r := inbox()[0]
	if r.RemovedContact == nil || *r.RemovedContact != (kept{DisplayName: "Alina", Petname: "Alina from the bakery"}) || r.Unread != 1 || r.ContactStatus != StatusRemoved {
		t.Fatalf("after the removal: %q %+v unread=%d", r.ContactStatus, r.RemovedContact, r.Unread)
	}
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:alina", Status: "pending_in", SPKI: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	// Asking again: a request names the fingerprint, so the thread is the request's, not removed.
	if r := inbox()[0]; r.RemovedContact != nil || r.ContactStatus != "pending_in" {
		t.Fatalf("asking again, still marked removed: %q %+v", r.ContactStatus, r.RemovedContact)
	}
}
