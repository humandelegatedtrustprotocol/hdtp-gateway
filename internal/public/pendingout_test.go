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
// contact_rejected run before the answer), and that is what the caller must be told — sealed, to the
// leaf that signed (PACT §13.2: once a request envelope has opened, an error result MUST be sealed
// back like any other result).
//
// It was told `envelope_invalid`, and then `pending_approval` in plaintext. pact-identity's Decide
// (0.4.1) answers pending_approval with the code alone — no root, no leaf, where its `ok` names both
// — but only after the signature verified, under the chain's leaf in the full form and under the
// pinned leaf in the small form. The node reads the signer from what it already peeked (the chain,
// or the leaf the small form names, matched to the pin that holds it), and seals to it.
//
// Both forms, because the signer comes from a different place in each; and the budget's refusal on
// the same path, which is rate_limited, sealed as a tool error inside `result`.
func TestAPendingContactsSealedCallIsAnsweredPendingApproval(t *testing.T) {
	for _, form := range []string{"chain", "leaf"} {
		t.Run(form, func(t *testing.T) {
			s := newSealedEnv(t)
			p := newPeer(t, s.nowAt.Add(-time.Hour))
			s.pin(t, p, "pending_out")

			res := s.call(t, s.sealFrom(t, p, form, "send_message", map[string]any{"text": "are we there yet"}), TransportFacts{})
			_, errObj := s.openedWith(t, res, p, msgIDFor("send_message", form))
			if code := codeOf(t, errObj); code != "pending_approval" {
				t.Fatalf("a pending contact's sealed call was answered %q in §13.2's `error`, want pending_approval", code)
			}

			// The control: contact_accepted is what a pending contact may call (PACT §6.1), and it
			// runs, and its answer is sealed to the same peer.
			res = s.call(t, s.sealFrom(t, p, form, "contact_accepted", map[string]any{"card": cardOf(p)}), TransportFacts{})
			if result, _ := s.openedWith(t, res, p, msgIDFor("contact_accepted", form)); len(result) == 0 {
				t.Fatal("contact_accepted from a pending contact must be answered with a result")
			}

			// The budget, spent, on the same path: its own code, sealed. It is asked for the root
			// the signature proved, at the guest charge, which the node's budget pays as a proven
			// pending contact's: the guest bucket of that root at its address, no guest total, and its
			// source known from then (node.chargeOf; TestASealedContactIsNotBudgetedAsAGuest, "a
			// pending_out root at the guest charge"). It was asked for nobody, which pays as a
			// stranger, total and all.
			var askedFor []string
			s.pool.Limit = func(ctx context.Context, as Charge) *Refusal {
				f := EnvelopeFactsFrom(ctx)
				if as != ChargeGuest || f == nil {
					t.Errorf("the budget was asked with charge %v and facts %+v, want a guest charge with the envelope's facts", as, f)
				} else {
					askedFor = append(askedFor, f.From)
				}
				return &Refusal{RetryAfter: time.Minute}
			}
			res = s.call(t, s.sealFrom(t, p, form, "send_message", map[string]any{"text": "again"}), TransportFacts{})
			if len(askedFor) != 1 || askedFor[0] != p.fpr() {
				t.Fatalf("the budget was asked for %q, want once for the root that signed (%s)", askedFor, p.fpr())
			}
			result, _ := s.openedWith(t, res, p, msgIDFor("send_message", form))
			var inner mcp.CallToolResult
			if err := json.Unmarshal(result, &inner); err != nil || !inner.IsError || len(inner.Content) == 0 {
				t.Fatalf("a budget refusal past the open must be sealed as a tool error: %v (%s)", err, result)
			}
			if code := codeOf(t, json.RawMessage(inner.Content[0].(*mcp.TextContent).Text)); code != "rate_limited" {
				t.Fatalf("a pending contact over the budget was answered %q, want rate_limited", code)
			}
		})
	}
}

// codeOf is the `code` of a refusal object, and fails the test on anything else.
func codeOf(t *testing.T, obj json.RawMessage) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(obj, &body); err != nil {
		t.Fatalf("not a refusal: %v (%s)", err, obj)
	}
	return body.Code
}
