package node

import (
	"context"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// The outbound retries run only on the process that holds their lease (SPEC §11.1): a pass that
// does not lead leaves a due message as it was, and one that leads makes its attempt.
func TestARetryPassRunsOnlyWhileItLeads(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "alice")
	n := mustNew(t, e.options())
	alice := accts[0]
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: alice.ID, Fingerprint: "sha256:away", SPKI: []byte{1},
		Status: "active", Endpoint: "https://127.0.0.1:1/a/away/mcp"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertMessage(ctx, store.Message{AccountID: alice.ID, ContactFpr: "sha256:away", MsgID: "due-1", ThreadID: "t-1",
		Direction: "out", Sender: "human", Kind: "text", Body: "hello", Status: "pending", CreatedAt: n.now().Unix()}); err != nil {
		t.Fatal(err)
	}
	attempts := func() int64 {
		t.Helper()
		m, err := e.st.GetMessageByMsgID(ctx, alice.ID, "sha256:away", "out", "due-1")
		if err != nil {
			t.Fatal(err)
		}
		return m.Attempts
	}
	n.retryTick(ctx, func(context.Context) bool { return false })
	if got := attempts(); got != 0 {
		t.Fatalf("a pass that does not hold the lease made %d attempts", got)
	}
	n.retryTick(ctx, func(context.Context) bool { return true })
	if got := attempts(); got != 1 {
		t.Fatalf("a pass that holds the lease made %d attempts, want 1", got)
	}
}
