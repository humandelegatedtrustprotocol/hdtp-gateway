package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/audit"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// auditEnv builds a two-account, two-owner node with an attributed row in each
// account plus one node-level row, and returns a mux serving /api/audit.
func auditEnv(t *testing.T) (*http.ServeMux, store.Store, store.Account, store.Account) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "au.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acctA, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	acctB, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "b", DisplayName: "B", Algo: "p256"})
	if _, err := st.CreateOwnerWithID(ctx, "owner-a", "Owner A"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateOwnerWithID(ctx, "owner-b", "Owner B"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembership(ctx, "owner-a", acctA.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembership(ctx, "owner-b", acctB.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	clock := time.Unix(1756000000, 0)
	w := &audit.Writer{Sink: st, Now: func() time.Time { return clock }}
	_ = w.Append(ctx, acctA.ID, "contact", "sha256:alina", "tools/call", "tool:send_message", "ok", "", "")
	_ = w.Append(ctx, acctB.ID, "contact", "sha256:bharat", "tools/call", "tool:book_slot", "ok", "", "")
	_ = w.Append(ctx, "", "owner", "o1", "portal_login", "", "ok", "", "")

	mux := http.NewServeMux()
	MountAuditPages(mux, st)
	return mux, st, acctA, acctB
}

// asOwner issues the request with the session owner the gate would have set.
func asOwner(t *testing.T, mux *http.ServeMux, owner, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req = req.WithContext(context.WithValue(req.Context(), ownerKey{}, owner))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// The audit trail is scoped by the SESSION, never by what the client volunteers.
// The first version of this scoping honoured a named ?account= and served the
// whole node's trail when the parameter was omitted — sending less yielded
// more, and any signed-in owner could read every account's contact, booking
// and message rows.
func TestAuditPageScopesByTheSessionOwner(t *testing.T) {
	mux, st, acctA, acctB := auditEnv(t)

	// Unnamed: owner A gets their own account's rows and the node's, never B's.
	rr := asOwner(t, mux, "owner-a", "/api/audit")
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "send_message") || !strings.Contains(body, "portal_login") {
		t.Fatalf("owner A's unnamed read lost rows it should see: %d\n%s", rr.Code, body)
	}
	if strings.Contains(body, "book_slot") {
		t.Fatalf("omitting ?account= leaked another account's rows: %s", body)
	}

	// Naming an account you do not administer is refused, and refused as 404:
	// whether it exists is not this owner's business.
	if rr := asOwner(t, mux, "owner-a", "/api/audit?account="+acctB.ID); rr.Code != http.StatusNotFound {
		t.Fatalf("another owner's account answered %d", rr.Code)
	}

	// Naming your own account still works.
	if rr := asOwner(t, mux, "owner-a", "/api/audit?account="+acctA.ID); rr.Code != 200 || !strings.Contains(rr.Body.String(), "send_message") {
		t.Fatalf("owner A's named read: %d\n%s", rr.Code, rr.Body.String())
	}

	// An owner who administers nothing sees only the node's own rows.
	if _, err := st.CreateOwnerWithID(context.Background(), "owner-none", "Nobody"); err != nil {
		t.Fatal(err)
	}
	rr = asOwner(t, mux, "owner-none", "/api/audit")
	body = rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "portal_login") {
		t.Fatalf("membership-less owner lost the node rows: %d\n%s", rr.Code, body)
	}
	if strings.Contains(body, "send_message") || strings.Contains(body, "book_slot") {
		t.Fatalf("membership-less owner read account rows: %s", body)
	}

	// No session owner at all fails closed, never serves the trail.
	req := httptest.NewRequest("GET", "/api/audit", nil)
	plain := httptest.NewRecorder()
	mux.ServeHTTP(plain, req)
	if plain.Code != http.StatusUnauthorized {
		t.Fatalf("ownerless request answered %d", plain.Code)
	}
}

// The actor filter narrows within the session's scope.
func TestAuditPageFiltersByActor(t *testing.T) {
	mux, st, acctA, _ := auditEnv(t)
	ctx := context.Background()
	clock := time.Unix(1756000100, 0)
	w := &audit.Writer{Sink: st, Now: func() time.Time { return clock }}
	_ = w.Append(ctx, acctA.ID, "contact", "sha256:carol", "tools/call", "tool:get_card", "ok", "", "")

	rr := asOwner(t, mux, "owner-a", "/api/audit?actor=sha256:alina")
	body := rr.Body.String()
	if !strings.Contains(body, "send_message") || strings.Contains(body, "sha256:carol") || strings.Contains(body, "portal_login") {
		t.Fatalf("actor filter: %s", body)
	}
}
