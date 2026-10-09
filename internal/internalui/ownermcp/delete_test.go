package ownermcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
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
		{"unknown thread", "no-such-thread", "not_found"},
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
	want := "account:" + e.acctA + " contact:sha256:alina thread:" + mine + " messages:1 files:0 ok"
	if len(rows) != 1 || rows[0] != want {
		t.Fatalf("audit = %v; want exactly [%s]", rows, want)
	}
	// The same answer shape as the portal's, member for member.
	var shape map[string]any
	_ = json.Unmarshal([]byte(text), &shape)
	for _, k := range []string{"status", "thread_id", "messages", "files"} {
		if _, ok := shape[k]; !ok {
			t.Fatalf("answer lacks %q: %s", k, text)
		}
	}
	if len(shape) != 4 {
		t.Fatalf("answer carries more than its four members: %s", text)
	}
}
