package node

import (
	"context"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// refresh_contact and call_contact tell a call that never left as this node's answer (#182): this
// identity's own budget refusing it is rate_limited with the wait, audited rate_limited; the limits
// sidecar not answering is unavailable saying so, audited limits_unavailable. A refresh told the
// owner the peer was unreachable, and a call was audited failed and answered unavailable, so the
// peer was blamed for a refusal this host made and the wait was lost.
func TestACallOutThatNeverLeftIsToldAsThisNodesAnswer(t *testing.T) {
	e, accounts := newEnv(t, "alice")
	acct := accounts[0]
	ctx := context.Background()
	w := testid.NewWallet(t, "Peer")
	h := w.Issue(t, "https://peer.invalid/mcp")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: w.Fpr, SPKI: h.Key.Public().SPKI, Status: "active",
		Endpoint: h.Endpoint, Leaf: h.LeafDER, Card: h.Card("Peer", "required"),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := New(ctx, e.options())
	if err != nil {
		t.Fatal(err)
	}
	client, err := n.OutboundClient(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; client.Budget(outbound.Peer{Root: w.Fpr}, "send_message") == nil; i++ {
		if i > 10000 {
			t.Fatal("the contact's budget out never ran out")
		}
	}
	rowOf := func(action string) string {
		e.mu.Lock()
		defer e.mu.Unlock()
		for i := len(e.rows) - 1; i >= 0; i-- {
			if strings.HasPrefix(e.rows[i], action+" ") {
				return e.rows[i]
			}
		}
		return ""
	}
	check := func(what, code, detail, outcome string, err error, action string) {
		t.Helper()
		gotCode, gotDetail := refusal.Of(err)
		if gotCode != code || !strings.Contains(gotDetail, detail) {
			t.Errorf("%s: %s %q (%v), want %s %q", what, gotCode, gotDetail, err, code, detail)
		}
		if row := rowOf(action); !strings.HasSuffix(row, " "+outcome) {
			t.Errorf("%s: audited %q, want %s", what, row, outcome)
		}
	}
	_, err = n.CallContact(ctx, acct.ID, w.Fpr, "send_message", map[string]any{"text": "hi"})
	check("call_contact over budget", "rate_limited", "try again in", "rate_limited", err, "call_contact")
	_, err = n.RefreshContact(ctx, acct.ID, w.Fpr)
	check("refresh_contact over budget", "rate_limited", "try again in", "rate_limited", err, "contact_refresh")

	e.limits.Stop()
	_, err = n.CallContact(ctx, acct.ID, w.Fpr, "send_message", map[string]any{"text": "hi"})
	check("call_contact with the sidecar down", "unavailable", outbound.LimitsUnavailableSentence, "limits_unavailable", err, "call_contact")
	_, err = n.RefreshContact(ctx, acct.ID, w.Fpr)
	check("refresh_contact with the sidecar down", "unavailable", outbound.LimitsUnavailableSentence, "limits_unavailable", err, "contact_refresh")
}
