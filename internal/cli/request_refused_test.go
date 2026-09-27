package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/node"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	"github.com/pact-cloud/pact-gateway/internal/testid"
)

// A request_contact the peer refuses is a refusal (PACT §12), not a request that landed. The
// owner's add-by-card took any answer for success, recorded a pending_out pin and audited it as
// such; a peer already holding our request answers `pending_approval`, and one that will not take
// requests answers its own code. Now the owner is told, nothing is pinned, and the audit row says
// `refused`. A request that is not refused still lands pending_out.
func TestARefusedRequestPinsNothingAndIsAuditedAsRefused(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	peer := testid.NewWallet(t, "Chitra")
	card := peer.Issue(t, "https://chitra.example/a/chitra/mcp").Card("Chitra", "optional")

	var rows []string
	answer := error(node.ErrRequestRefused{Code: "pending_approval"})
	ci := &contactInitiator{
		manager: &contacts.Manager{Store: st},
		audit:   func(action, resource, outcome string) { rows = append(rows, action+" → "+outcome) },
		request: func(context.Context, string, outbound.Peer, string, string) error { return answer },
	}
	if _, err := ci.RequestContact(ctx, a.ID, card, ""); err == nil || !strings.Contains(err.Error(), "pending_approval") {
		t.Fatalf("a refused request must reach the owner with the peer's code: %v", err)
	}
	if _, err := st.GetContact(ctx, a.ID, peer.Fpr); err == nil {
		t.Fatal("a refused request pinned the peer as if it had landed")
	}
	if strings.Join(rows, "\n") != "contact_initiate → refused" {
		t.Fatalf("the audit trail for a refused request: %q", rows)
	}

	// A transport failure is not a refusal: it is audited as unreachable.
	rows, answer = nil, errors.New("dial tcp: connection refused")
	if _, err := ci.RequestContact(ctx, a.ID, card, ""); err == nil {
		t.Fatal("an unreachable peer was taken for a request that landed")
	}
	if strings.Join(rows, "\n") != "contact_initiate → unreachable" {
		t.Fatalf("the audit trail for an unreachable peer: %q", rows)
	}

	// The control: an answer that is not a refusal lands pending_out.
	rows, answer = nil, nil
	res, err := ci.RequestContact(ctx, a.ID, card, "")
	if err != nil || res.Status != "pending_out" {
		t.Fatalf("a request the peer took: %+v %v", res, err)
	}
	if c, err := st.GetContact(ctx, a.ID, peer.Fpr); err != nil || c.Status != "pending_out" {
		t.Fatalf("a request the peer took must be pinned pending_out: %+v %v", c, err)
	}
	if strings.Join(rows, "\n") != "contact_initiate → pending_out" {
		t.Fatalf("the audit trail for a request that landed: %q", rows)
	}
}
