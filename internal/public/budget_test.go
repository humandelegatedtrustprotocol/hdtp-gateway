package public

// What a sealed call spends (HDTP §12): every inner call that reaches dispatch — tools/list, and a
// tool the caller may not see or that does not exist, as much as one it may call — and a replay
// answered from its record spends nothing. The cloud spends at the same point (its surface budgets
// before it dispatches, after the replay). Until this, `tools/list` and an unknown tool were free
// here and charged there, which is a difference a battery aimed at both could only report.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

func TestEveryInnerCallSpendsAndAReplayDoesNot(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	var charged []Charge
	s.pool.Limit = func(_ context.Context, as Charge) *Refusal {
		charged = append(charged, as)
		return nil
	}
	spent := func(t *testing.T, want int, what string) {
		t.Helper()
		if len(charged) != want {
			t.Fatalf("%s: %d charges so far, want %d", what, len(charged), want)
		}
	}
	list := s.sealFrom(t, p, "chain", "tools_list", nil, func(o *hdtpidentity.SealOpts) { o.Method, o.Params = "tools/list", json.RawMessage(`{}`) })
	s.call(t, list, TransportFacts{})
	spent(t, 1, "a sealed tools/list")

	s.call(t, s.sealFrom(t, p, "chain", "no_such_tool", map[string]any{}), TransportFacts{})
	spent(t, 2, "a tool that does not exist")

	send := s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"})
	s.call(t, send, TransportFacts{})
	spent(t, 3, "send_message")
	s.call(t, send, TransportFacts{})
	spent(t, 3, "the same envelope again, answered from its record")
	for _, as := range charged {
		if as != ChargeCaller {
			t.Fatalf("an active contact's calls were charged %v, want the caller's own budget", charged)
		}
	}
}

// A call refused by the budget is not the envelope's answer: the same envelope, sent again once the
// budget holds a call, is served — not answered rate_limited from the replay record for as long as
// the envelope lives.
func TestARefusedCallIsNotRecordedAsTheAnswer(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	refuse := true
	s.pool.Limit = func(context.Context, Charge) *Refusal {
		if refuse {
			return &Refusal{RetryAfter: 3 * time.Second}
		}
		return nil
	}
	send := s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"})
	result, _ := s.opened(t, s.call(t, send, TransportFacts{}), p, "send_message")
	var inner mcp.CallToolResult
	if err := json.Unmarshal(result, &inner); err != nil || !inner.IsError || !strings.Contains(inner.Content[0].(*mcp.TextContent).Text, `"retry_after":3`) {
		t.Fatalf("the refusal is not rate_limited with retry_after 3: %s", result)
	}
	refuse = false
	result, _ = s.opened(t, s.call(t, send, TransportFacts{}), p, "send_message")
	if err := json.Unmarshal(result, &inner); err != nil || inner.IsError {
		t.Fatalf("the envelope sent again once the budget held a call was not served: %s", result)
	}
}

// A peer turned away because the account's contact list is full is told `unavailable`, bare: no
// count, no cap, and not `rate_limited`, since no number of seconds is true of a full list (HDTP
// §12; the cloud answers the same). The owner is told more; that is its own door's mapping.
func TestAFullContactListIsUnavailableToAPeer(t *testing.T) {
	if got := domainCode(fmt.Errorf("wrapped: %w", contacts.ErrContactCap)); got != "unavailable" {
		t.Fatalf("a full contact list reaches a peer as %q", got)
	}
}

// A budget nobody could be asked about (the limits sidecar is not answering) refuses the call
// `unavailable`, sealed like any refusal past the open, and audited as that: never `rate_limited`,
// which would name a wait that nothing measured, and never served (the owner's rule of 2026-09-29).
func TestABudgetThatCannotBeAskedRefusesUnavailable(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	down := true
	s.pool.Limit = func(context.Context, Charge) *Refusal {
		if down {
			return &Refusal{Unavailable: true}
		}
		return nil
	}
	send := s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"})
	result, _ := s.opened(t, s.call(t, send, TransportFacts{}), p, "send_message")
	var inner mcp.CallToolResult
	if err := json.Unmarshal(result, &inner); err != nil || !inner.IsError || inner.Content[0].(*mcp.TextContent).Text != `{"code":"unavailable"}` {
		t.Fatalf("with no budget to ask, the call was answered %s, want a sealed unavailable", result)
	}
	down = false
	result, _ = s.opened(t, s.call(t, send, TransportFacts{}), p, "send_message")
	if err := json.Unmarshal(result, &inner); err != nil || inner.IsError {
		t.Fatalf("the same envelope, sent again once the budget could be asked, was not served: %s", result)
	}
}
