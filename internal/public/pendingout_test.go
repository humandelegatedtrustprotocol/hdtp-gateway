package public

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A contact this node asked, and who has not answered yet (pending_out), sends a sealed
// send_message. The library decides `pending_approval` (PACT §6.1: only contact_accepted and
// contact_rejected run before the answer), and that is what the caller must be told.
//
// It was told `envelope_invalid`. pact-identity's Decide answers pending_approval with the code
// alone — no root, no leaf, where its `ok` names both — so the node's facts carry no key to seal the
// answer to; sealResult then failed on the missing key and ANSWERED, in plaintext, a code of its own,
// and sealBackErr's fallback to the intended code never ran, because a failed seal was not an error.
// A peer holding a request still pending could not tell it was waiting (the cloud's repair logic
// keys off pending_approval), and was told its envelope was bad.
//
// Now a seal that cannot be made is an error, and a refusal that cannot be sealed goes out as
// itself. Until Decide names the signer of a pending_approval (handed to pact-identity), the answer
// is that plaintext code — §13.2 wants it sealed, and this test then has to open it sealed. The
// same holds for the budget's refusal on that path: it is rate_limited, never another code.
func TestAPendingContactsSealedCallIsAnsweredPendingApproval(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "pending_out")

	res := s.call(t, s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "are we there yet"}), TransportFacts{})
	if code := plainCode(t, res); code != "pending_approval" {
		t.Fatalf("a pending contact's sealed call was answered %q, want pending_approval", code)
	}

	// The control: contact_accepted is what a pending contact may call (PACT §6.1), and its answer
	// is sealed to the same peer — so a sealed answer to this peer can be made, and was.
	res = s.call(t, s.sealFrom(t, p, "chain", "contact_accepted", map[string]any{"card": cardOf(p)}), TransportFacts{})
	s.opened(t, res, p, "contact_accepted")

	// The budget, spent, on the same path: its own code.
	s.pool.Limit = func(context.Context, Charge) *Refusal { return &Refusal{RetryAfter: time.Minute} }
	res = s.call(t, s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "again"}), TransportFacts{})
	if code := plainCode(t, res); code != "rate_limited" {
		t.Fatalf("a pending contact over the budget was answered %q, want rate_limited", code)
	}
}

// plainCode is the code of a plaintext refusal, and fails the test on an answer that is not one.
func plainCode(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("want a plaintext refusal, got an answer: %s", text(t, res))
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &body); err != nil {
		t.Fatalf("the refusal is not a code: %v (%s)", err, text(t, res))
	}
	return body.Code
}
