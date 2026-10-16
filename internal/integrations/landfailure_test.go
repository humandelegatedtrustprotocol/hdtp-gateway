package integrations

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// statusWriteFails is a store whose integration status writes fail while fail is set.
type statusWriteFails struct {
	store.Store
	fail bool
}

func (s *statusWriteFails) UpdateIntegrationStatus(ctx context.Context, id, status string) error {
	if s.fail {
		return errors.New("store: database is locked")
	}
	return s.Store.UpdateIntegrationStatus(ctx, id, status)
}

// A move into auth_error whose status write failed did not happen: nothing is audited
// integration_auth and OnAuthError does not fire, or whoever it woke would read the old status, and
// a call's integration_call row says error, not the auth_error that did not land. The control, the
// same failure with the write succeeding, moves the row, audits and fires once.
func TestAMoveIntoAuthErrorThatWasNotWrittenIsNotAnnounced(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://x.example/mcp", AuthKind: "oauth"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateIntegrationStatus(ctx, in.ID, "ok"); err != nil {
		t.Fatal(err)
	}
	in.Status = "ok"
	ws := &statusWriteFails{Store: st, fail: true}
	var told []string
	aud := &auditRec{}
	m := &Manager{Store: ws, Audit: aud.fn, OnAuthError: func(id string) { told = append(told, id) }}
	unauthorized := errors.New("failed to connect: Unauthorized")

	m.landFailure(ctx, in, unauthorized)
	m.NoteCallFailure(ctx, in.ID, unauthorized)
	if len(told) != 0 || aud.hasRow("integration_auth", "integration:cal", "error") || !aud.hasRow("integration_call", "integration:cal", "error") {
		t.Errorf("a status write that failed: OnAuthError heard %v, audit %v; want neither the hook nor integration_auth, and integration_call error", told, aud.rows)
	}
	if got, _ := st.GetIntegrationByID(ctx, in.ID); got.Status != "ok" {
		t.Fatalf("the row moved with its write failing: %q", got.Status)
	}

	ws.fail = false
	aud.rows = nil
	m.NoteCallFailure(ctx, in.ID, unauthorized)
	if got, _ := st.GetIntegrationByID(ctx, in.ID); got.Status != "auth_error" || len(told) != 1 ||
		!aud.hasRow("integration_auth", "integration:cal", "error") || !aud.hasRow("integration_call", "integration:cal", "auth_error") {
		t.Errorf("the control, the write succeeding: landed %q, OnAuthError heard %v, audit %v", got.Status, told, aud.rows)
	}
}
