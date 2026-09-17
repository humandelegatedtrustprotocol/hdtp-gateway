package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// waitInbox polls an owner's inbox until a message body turns up, or the budget
// runs out. It lived in the relay scenario's test file until the relay went; two
// other scenarios depend on it, so it has its own file rather than riding along
// with whatever happens to survive next.
func waitInbox(ctx context.Context, o *Owned, want string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last string
	for {
		raw, err := o.Owner.Call(ctx, "get_inbox", map[string]any{"account_id": o.AccountID})
		if err == nil {
			last = raw
			if strings.Contains(raw, want) {
				return nil
			}
			// get_inbox lists thread summaries; the body lives in the thread.
			var threads []struct {
				ThreadID string `json:"thread_id"`
			}
			_ = json.Unmarshal([]byte(raw), &threads)
			for _, th := range threads {
				body, err := o.Owner.Call(ctx, "read_thread", map[string]any{
					"account_id": o.AccountID, "thread_id": th.ThreadID})
				if err == nil && strings.Contains(body, want) {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("inbox never carried it (last: %s)", shorten(last, 300))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// auditDelivery pulls the delivery-related audit rows. Those events go to the hash
// chain, not to stdout, so a container log with nothing about delivery in it says
// nothing either way. It was `auditRelay` until the relay went; what it reads is
// the same rows minus a word that no longer appears in any of them.
func auditDelivery(ctx context.Context, t *testing.T, o *Owned, label string) string {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "audit_query", map[string]any{"limit": 200})
	if err != nil {
		return label + " audit: " + err.Error()
	}
	var rows []struct{ Action, Resource, Outcome string }
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return label + " audit: unreadable"
	}
	var hits []string
	for _, r := range rows {
		a := strings.ToLower(r.Action)
		if strings.Contains(a, "deliver") || strings.Contains(a, "send") || strings.Contains(a, "sealed") {
			hits = append(hits, r.Action+" "+r.Resource+" -> "+r.Outcome)
		}
	}
	if len(hits) == 0 {
		return label + " audit: no delivery rows at all"
	}
	return label + " audit:\n  " + strings.Join(hits, "\n  ")
}
