package public

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A sealed call reads the recipient state once (lead 8 of the port-parity audit, 2026-09-29). The
// open builds it — the account row, the chain, every held leaf key decrypted and parsed, the kids
// once held, the other identities' kids — and the answer is sealed under the key it holds. It was
// read a second time to seal the answer, which decrypted and parsed every held key again for the
// one it uses, on every sealed answer, refusals included.
//
// Counted here on the three ways an answer is sealed: a contact's call answered (sealBack), a
// refusal past the open (sealedCode: an address the owner has not approved), and a budget's
// refusal (sealLimited). No client certificate is presented, so the plaintext gate's own read — for
// a caller whose transport carries a chain — is not among them. Each answer is opened, so the one
// state read is the one it was sealed under.
func TestASealedCallReadsTheRecipientStateOnce(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	reads := 0
	read := s.id.RecipientState
	s.id.RecipientState = func(ctx context.Context) (*RecipientState, error) {
		reads++
		return read(ctx)
	}

	reads = 0
	res := s.call(t, s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hello"}), TransportFacts{})
	if reads != 1 {
		t.Fatalf("a contact's sealed call read the recipient state %d times, want 1", reads)
	}
	if result, _ := s.opened(t, res, p, "send_message"); len(result) == 0 {
		t.Fatal("the answer to a contact's call must open")
	}

	// The same root, from an address the owner has not approved: refused past the open.
	if err := s.st.SetAccountHostPolicy(ctx, s.acct.ID, "ask"); err != nil {
		t.Fatal(err)
	}
	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, s.nowAt.Add(-5*time.Minute))
	reads = 0
	res = s.call(t, s.sealFrom(t, moved, "chain", "send_message", map[string]any{"text": "from elsewhere"}), TransportFacts{})
	if reads != 1 {
		t.Fatalf("a sealed refusal past the open read the recipient state %d times, want 1", reads)
	}
	var code struct {
		Code string `json:"code"`
	}
	if _, errObj := s.opened(t, res, moved, "send_message"); json.Unmarshal(errObj, &code) != nil || code.Code != "pending_approval" {
		t.Fatalf("the refusal must open as pending_approval: %s", errObj)
	}

	// The budget, spent: its refusal is sealed too.
	s.pool.Limit = func(context.Context, Charge) *Refusal { return &Refusal{RetryAfter: time.Minute} }
	reads = 0
	res = s.call(t, s.sealFrom(t, moved, "chain", "send_message", map[string]any{"text": "again"}), TransportFacts{})
	if reads != 1 {
		t.Fatalf("a sealed budget refusal read the recipient state %d times, want 1", reads)
	}
	result, _ := s.opened(t, res, moved, "send_message")
	var inner mcp.CallToolResult
	if err := json.Unmarshal(result, &inner); err != nil || !inner.IsError {
		t.Fatalf("the budget's refusal must open as a tool error: %v (%s)", err, result)
	}
}
