package ownermcp

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// delete_thread is the portal's delete through the same operation: the owner's conversation is
// deleted and answered with what went; an empty id is bad_request, a thread the account does not
// hold (another account's included) not_found, an account the token does not reach
// permission_denied, and each call that reaches the operation writes one thread_delete row beside
// the call log's owner_mcp_call.
func TestDeleteThreadDeletesOneConversationAndRefusesTheRest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var rows []string
	e.deps.Audit = func(a, r, o string) {
		if a == "thread_delete" {
			rows = append(rows, r+" "+o)
		}
	}
	record := func(account, msgID string) string {
		t.Helper()
		r, err := e.deps.Msg.Record(ctx, account, "sha256:alina", messaging.DirIn,
			messaging.Input{Origin: messaging.OriginPeer, MsgID: msgID, Text: "hi", Sender: messaging.SenderAgent})
		if err != nil {
			t.Fatal(err)
		}
		return r.ThreadID
	}
	mine, other := record(e.acctA, "m1"), record(e.acctB, "m2")
	held := func(account, thread string) bool {
		_, err := e.st.GetThread(ctx, account, thread)
		return err == nil
	}

	narrow, _ := connect(t, e, auth.Identity{OwnerID: e.owner, AccountID: e.acctA}, nil)
	if text, isErr := callJSON(t, narrow, "delete_thread", map[string]any{"account_id": e.acctB, "thread_id": other}); !isErr || !strings.Contains(text, "permission_denied") || !held(e.acctB, other) {
		t.Fatalf("a token narrowed to another account: %s (error %v), held=%v", text, isErr, held(e.acctB, other))
	}
	if len(rows) != 0 {
		t.Fatalf("a call the policy refused reached the operation: %v", rows)
	}

	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	for _, c := range []struct {
		name, thread, code string
	}{
		{"empty id", "", "bad_request"},
		{"unknown thread", "nosuchthread", "not_found"},
		{"another account's thread", other, "not_found"},
	} {
		text, isErr := callJSON(t, cs, "delete_thread", map[string]any{"account_id": e.acctA, "thread_id": c.thread})
		if !isErr || !strings.Contains(text, `"`+c.code+`"`) {
			t.Fatalf("%s: %s (error %v), want %s", c.name, text, isErr, c.code)
		}
	}
	if !held(e.acctB, other) {
		t.Fatal("another account's thread went")
	}
	if len(rows) != 3 {
		t.Fatalf("refusals wrote %d thread_delete rows, want 3: %v", len(rows), rows)
	}

	rows = nil
	text, isErr := callJSON(t, cs, "delete_thread", map[string]any{"account_id": e.acctA, "thread_id": mine})
	if isErr {
		t.Fatalf("delete_thread: %s", text)
	}
	var got messaging.Deleted
	if err := json.Unmarshal([]byte(text), &got); err != nil || got.Status != "deleted" || got.ThreadID != mine || got.Messages != 1 {
		t.Fatalf("answer %s (%v)", text, err)
	}
	if held(e.acctA, mine) {
		t.Fatal("the conversation is still there")
	}
	want := "account:" + e.acctA + " contact:sha256:alina thread_id:" + mine + " messages:1 files:0 ok"
	if len(rows) != 1 || rows[0] != want {
		t.Fatalf("audit = %v; want exactly [%s]", rows, want)
	}
	// The same answer shape as the portal's, member for member.
	var shape map[string]any
	_ = json.Unmarshal([]byte(text), &shape)
	for _, k := range []string{"status", "thread_id", "contact", "messages", "files"} {
		if _, ok := shape[k]; !ok {
			t.Fatalf("answer lacks %q: %s", k, text)
		}
	}
	if len(shape) != 5 || shape["contact"] != "sha256:alina" {
		t.Fatalf("answer is not its five members, naming the contact: %s", text)
	}
}

// The owner MCP takes a thread id as an argument, never in a path, and holds it to HDTP §7's two
// forms as the portal does (testid.ThreadIDs): an id of a form reads, takes a message and deletes;
// an id of neither form is refused by read_thread, send_to_contact, delete_thread and the thread
// resource, with its code, before anything is read, recorded or deleted.
func TestEveryThreadIDReadsAndDeletesOverTheOwnerMCP(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	for i, c := range testid.ThreadIDs() {
		if c.Code != "" {
			continue
		}
		id := c.ID
		if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn, messaging.Input{
			Origin: messaging.OriginPeer, MsgID: "in-" + strconv.Itoa(i), ThreadID: id, Text: "hi " + id, Sender: messaging.SenderAgent,
		}); err != nil {
			t.Fatalf("%s: recording: %v", c.Name, err)
		}
		text, isErr := callJSON(t, cs, "read_thread", map[string]any{"account_id": e.acctA, "thread_id": id})
		var read []struct {
			Body string `json:"body"`
		}
		if isErr || json.Unmarshal([]byte(text), &read) != nil || len(read) != 1 || read[0].Body != "hi "+id {
			t.Fatalf("%s: read_thread: %s (error %v)", c.Name, text, isErr)
		}
		if text, isErr := callJSON(t, cs, "send_to_contact", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:alina", "thread_id": id, "msg_id": "out-" + strconv.Itoa(i), "text": "back"}); isErr {
			t.Fatalf("%s: send_to_contact: %s", c.Name, text)
		}
		text, isErr = callJSON(t, cs, "delete_thread", map[string]any{"account_id": e.acctA, "thread_id": id})
		var got messaging.Deleted
		if isErr || json.Unmarshal([]byte(text), &got) != nil || got.ThreadID != id || got.Messages != 2 {
			t.Fatalf("%s: delete_thread: %s (error %v)", c.Name, text, isErr)
		}
		if _, err := e.st.GetThread(ctx, e.acctA, id); err == nil {
			t.Fatalf("%s: still there after delete_thread", c.Name)
		}
	}
	for i, c := range testid.ThreadIDs() {
		if c.Code == "" || c.ID == "" {
			continue
		}
		id := c.ID
		// A thread stored under this id before the wipe (migration 0005), as a contact once could.
		if err := e.st.InsertThread(ctx, store.Thread{ID: id, AccountID: e.acctA, ContactFpr: "sha256:alina", CreatedAt: 1, LastAt: 1}); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if text, isErr := callJSON(t, cs, "read_thread", map[string]any{"account_id": e.acctA, "thread_id": id}); !isErr || !strings.Contains(text, c.Code) {
			t.Fatalf("%s: read_thread: %s (error %v), want %s", c.Name, text, isErr, c.Code)
		}
		text, isErr := callJSON(t, cs, "send_to_contact", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:alina", "thread_id": id, "msg_id": "refused-" + strconv.Itoa(i), "text": "back"})
		if msgs, _ := e.st.ListMessagesByThread(ctx, e.acctA, id); !isErr || !strings.Contains(text, c.Code) || len(msgs) != 0 {
			t.Fatalf("%s: send_to_contact: %s (error %v), %d recorded, want %s and none", c.Name, text, isErr, len(msgs), c.Code)
		}
		if text, isErr := callJSON(t, cs, "delete_thread", map[string]any{"account_id": e.acctA, "thread_id": id}); !isErr || text != `{"code":"`+c.Code+`"}` {
			t.Fatalf("%s: delete_thread: %s (error %v), want %s", c.Name, text, isErr, c.Code)
		}
		// A URI the client cannot send (a control character) closes the session before it leaves.
		if _, perr := url.Parse(URIThreadPrefix + id); perr == nil {
			if _, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: URIThreadPrefix + id}); err == nil {
				t.Fatalf("%s: the thread resource read it", c.Name)
			}
		}
		if _, err := e.st.GetThread(ctx, e.acctA, id); err != nil {
			t.Fatalf("%s: a refusal deleted it: %v", c.Name, err)
		}
		if _, err := e.st.DeleteThread(ctx, e.acctA, id); err != nil {
			t.Fatal(err)
		}
	}
}
