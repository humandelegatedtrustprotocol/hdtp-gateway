package public

// The budget before the pin's moves (HDTP §12, hdtp-gateway #186): a sealed call the budget refuses
// changes nothing — no newer leaf learned, no address moved or remembered, no address parked for the
// owner — and the same call once the budget holds one does all of it. The cloud's surface spends at
// the same point (gateway/src/identity/surface.ts, "The budget BEFORE the effects", review P-10).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// refusedRateLimited holds an answer to be the sealed rate_limited a budget refusal is.
func refusedRateLimited(t *testing.T, s *sealedEnv, res *mcp.CallToolResult, p *peer, msgID string) {
	t.Helper()
	result, _ := s.openedWith(t, res, p, msgID)
	var inner mcp.CallToolResult
	if err := json.Unmarshal(result, &inner); err != nil || !inner.IsError || !strings.Contains(text(t, &inner), `"code":"rate_limited"`) {
		t.Fatalf("the over-budget call was answered %s, want a sealed rate_limited", result)
	}
}

func TestAnOverBudgetCallMovesNoPin(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		endpoint string
		tool     string
		args     map[string]any
	}{
		{"a renewal at the pinned address", endpointA, "send_message", map[string]any{"text": "hi"}},
		{"a new address under auto", endpointA2, "send_message", map[string]any{"text": "hi"}},
		{"a renewal on a call refused for its thread_id", endpointA, "send_message", map[string]any{"text": "hi", "thread_id": "."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSealedEnv(t)
			p := newPeer(t, s.nowAt.Add(-time.Hour))
			s.pin(t, p, "active")
			var events []string
			s.id.OnEvent = func(event, _, endpoint string) { events = append(events, event+"@"+endpoint) }
			refuse := true
			s.pool.Limit = func(context.Context, Charge) *Refusal {
				if refuse {
					return &Refusal{RetryAfter: 5 * time.Second}
				}
				return nil
			}
			newer := &peer{root: p.root, host: p.host}
			newer.leaf = newer.leafFor(t, tc.endpoint, s.nowAt.Add(-30*time.Minute))
			env := s.sealFrom(t, newer, "chain", tc.tool, tc.args)

			refusedRateLimited(t, s, s.call(t, env, TransportFacts{}), newer, msgIDFor(tc.tool, "chain"))
			c, err := s.st.GetContact(ctx, s.acct.ID, p.fpr())
			if err != nil {
				t.Fatal(err)
			}
			if string(c.Leaf) != string(p.leaf) || c.Endpoint != endpointA {
				t.Fatalf("an over-budget call moved the pin: endpoint %s, leaf moved %v", c.Endpoint, string(c.Leaf) != string(p.leaf))
			}
			if fe, _ := s.st.ListFormerEndpoints(ctx, s.acct.ID); len(fe) != 0 {
				t.Fatalf("an over-budget call remembered a former address: %+v", fe)
			}
			if len(events) != 0 {
				t.Fatalf("an over-budget call told the owner: %v", events)
			}

			// The control: the same envelope once the budget holds a call moves the pin.
			refuse = false
			s.call(t, env, TransportFacts{})
			c, err = s.st.GetContact(ctx, s.acct.ID, p.fpr())
			if err != nil {
				t.Fatal(err)
			}
			if string(c.Leaf) != string(newer.leaf) || c.Endpoint != tc.endpoint {
				t.Fatalf("the call the budget took did not move the pin: endpoint %s", c.Endpoint)
			}
		})
	}
}

// Under `ask`, a pinned root at a new address is parked for the owner — but only by a call the
// guest budget it pays took.
func TestAnOverBudgetCallFromANewAddressParksNothing(t *testing.T) {
	ctx := context.Background()
	s := newSealedEnv(t)
	if err := s.st.SetAccountHostPolicy(ctx, s.acct.ID, "ask"); err != nil {
		t.Fatal(err)
	}
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	var pendings []string
	s.id.OnPending = func(_, endpoint, _ string) { pendings = append(pendings, endpoint) }
	refuse := true
	s.pool.Limit = func(context.Context, Charge) *Refusal {
		if refuse {
			return &Refusal{RetryAfter: 5 * time.Second}
		}
		return nil
	}
	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, s.nowAt.Add(-30*time.Minute))
	env := s.sealFrom(t, moved, "chain", "send_message", map[string]any{"text": "hi"})

	refusedRateLimited(t, s, s.call(t, env, TransportFacts{}), moved, msgIDFor("send_message", "chain"))
	if _, err := s.st.GetPendingAddress(ctx, s.acct.ID, p.fpr()); err == nil || len(pendings) != 0 {
		t.Fatalf("an over-budget call parked its address for the owner (told %v)", pendings)
	}

	refuse = false
	s.call(t, env, TransportFacts{})
	if pa, err := s.st.GetPendingAddress(ctx, s.acct.ID, p.fpr()); err != nil || pa.Endpoint != endpointA2 || len(pendings) != 1 {
		t.Fatalf("the call the budget took did not park its address: %+v %v (told %v)", pa, err, pendings)
	}
}

// failingRepin is a contact store whose pin will not move.
type failingRepin struct{ store.ContactStore }

func (failingRepin) RepinContactAddress(context.Context, string, string, string, []byte, []byte, int64) error {
	return errors.New("the pin did not move")
}

// A move the open decided that cannot be recorded refuses the call envelope_invalid — sealed, since
// the envelope is open by then (HDTP §13.2) — with one row, and nothing is dispatched.
func TestAMoveThatCannotBeRecordedIsRefusedSealed(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	var rows []string
	s.deps.AuditAs = func(kind, action, resource, outcome string) { rows = append(rows, action+" "+outcome) }
	s.id.Store = failingRepin{s.id.Store}
	newer := &peer{root: p.root, host: p.host}
	newer.leaf = newer.leafFor(t, endpointA, s.nowAt.Add(-30*time.Minute))
	res := s.call(t, s.sealFrom(t, newer, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{})
	_, errObj := s.openedWith(t, res, newer, msgIDFor("send_message", "chain"))
	if string(errObj) != `{"code":"envelope_invalid"}` {
		t.Fatalf("answered %s, want a sealed envelope_invalid", text(t, res))
	}
	if len(rows) != 1 || rows[0] != "sealed_call envelope_invalid" {
		t.Fatalf("audited %q, want the one sealed_call row", rows)
	}
}
