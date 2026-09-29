package internalui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
)

// AC (P10-05d): at zero passkeys the portal root IS the wizard, not a link to
// it. SPEC §8.3 says the portal "auto-shows the wizard"; it used to render a
// shell whose only affordance was a hyperlink, so an owner who did not click it
// left the node unclaimed — and an unclaimed node is claimable by whoever
// reaches it next.
func TestPortalRootAutoShowsTheWizardAtZeroPasskeys(t *testing.T) {
	// §8.3: with zero passkeys the portal leads to the wizard and nowhere else.
	// The SPA routes on /api/session's needs_setup, so THAT is the load-bearing
	// signal now; the ceremony itself and its bundle presence are held by
	// TestEmbeddedBundleCarriesTheCeremonies, and the gate that keeps a stranger
	// from registering guards /setup/begin server-side (SetupAllowed), asserted
	// in TestPortalRegistrationAndLoginCeremony when setup closes.
	e := newEnv(t)
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/session", nil))
	if rr.Code != 200 {
		t.Fatalf("session at zero passkeys: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"needs_setup":true`) {
		t.Fatalf("the portal does not lead to the wizard at zero passkeys: %s", rr.Body.String())
	}
	// The wizard view must have shipped, or the routing above lands on nothing.
	if !strings.Contains(bundleJS(t), "Register a passkey") {
		t.Error("the compiled portal has no wizard view")
	}
}

func firstN(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

// dashEnv is a node with two identities, A administered by owner-a and B by owner-b, and A's people:
// two active contacts, one request waiting, one contact waiting at a new address, one blocked.
func dashEnv(t *testing.T) (store.Store, store.Account, store.Account) {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "dash.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "Alex", Algo: "p256"})
	b, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "b", DisplayName: "Bea", Algo: "p256"})
	for _, o := range []struct{ id, acct string }{{"owner-a", a.ID}, {"owner-b", b.ID}} {
		if _, err := st.CreateOwnerWithID(ctx, o.id, o.id); err != nil {
			t.Fatal(err)
		}
		if err := st.AddMembership(ctx, o.id, o.acct, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	for i, status := range []string{"active", "active", "pending_in", "blocked"} {
		c := store.Contact{AccountID: a.ID, Fingerprint: fmt.Sprintf("sha256:c%d", i), SPKI: []byte{1}, Status: status}
		if _, err := st.InsertContact(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: b.ID, Fingerprint: "sha256:b0", SPKI: []byte{1}, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: a.ID, Root: "sha256:c0", Endpoint: "https://new.example/c0", Leaf: []byte{1}, Why: "ask", At: 1}); err != nil {
		t.Fatal(err)
	}
	// A has a root (a wallet signed it), so its certificate is read; B has none.
	if err := st.SetAccountRoot(ctx, a.ID, "sha256:root-a", []byte{1}); err != nil {
		t.Fatal(err)
	}
	return st, a, b
}

// The overview answers, for each identity the owner administers and no other, the numbers its links
// explain — the People page's contacts, the Requests tab's waiting — and the certificate the identity
// page shows, from the same reader. A read that fails is a failed answer, never a zero.
func TestTheOverviewCountsWhatItsLinksShow(t *testing.T) {
	st, a, b := dashEnv(t)
	notAfter := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	cert := func(_ context.Context, id string) (identity.CertificateInfo, error) {
		if id != a.ID {
			return identity.CertificateInfo{}, nil
		}
		return identity.CertificateInfo{Certified: true, Kid: "k1", Endpoint: "https://node.example/a", NotAfter: notAfter, RenewalDue: true}, nil
	}
	mux := http.NewServeMux()
	MountDashboard(mux, DashboardDeps{Store: st, Certificate: cert})

	rr := asOwner(t, mux, "owner-a", "/api/dashboard")
	var got struct {
		Accounts []dashAccount `json:"accounts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if len(got.Accounts) != 1 || got.Accounts[0].ID != a.ID {
		t.Fatalf("owner A's overview lists %+v, want A alone (B is owner B's)", got.Accounts)
	}
	row := got.Accounts[0]
	// Two active; one request plus one contact at a new address — what the Requests tab holds.
	if row.Contacts != 2 || row.Pending != 2 {
		t.Errorf("counted %d contacts and %d waiting, want 2 and 2", row.Contacts, row.Pending)
	}
	want := dashCert{Certified: true, Served: true, Endpoint: "https://node.example/a", NotAfter: "2026-10-20T12:00:00Z", RenewalDue: true}
	if row.Certificate == nil || *row.Certificate != want {
		t.Errorf("certificate %+v, want %+v", row.Certificate, want)
	}

	// An identity no wallet has signed is not asked of the reader, which walks what a root owes: it is
	// answered as unsigned. (Owner A here administers only A, so a second owner reads B.)
	if err := st.AddMembership(context.Background(), "owner-a", b.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	asked := map[string]bool{}
	counted := http.NewServeMux()
	MountDashboard(counted, DashboardDeps{Store: st, Certificate: func(_ context.Context, id string) (identity.CertificateInfo, error) {
		asked[id] = true
		return identity.CertificateInfo{Certified: true}, nil
	}})
	var both struct {
		Accounts []dashAccount `json:"accounts"`
	}
	rr = asOwner(t, counted, "owner-a", "/api/dashboard")
	if err := json.Unmarshal(rr.Body.Bytes(), &both); err != nil || rr.Code != 200 || len(both.Accounts) != 2 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if !asked[a.ID] || asked[b.ID] {
		t.Errorf("the reader was asked of %v; want A (which has a root) and never B", asked)
	}
	for _, row := range both.Accounts {
		if row.ID == b.ID && (row.Certificate == nil || *row.Certificate != (dashCert{})) {
			t.Errorf("B, which no wallet signed, answered %+v; want an unsigned certificate", row.Certificate)
		}
	}

	// An identity certified and holding no current leaf says so, and no dates for a leaf that is not.
	unserved := http.NewServeMux()
	MountDashboard(unserved, DashboardDeps{Store: st, Certificate: func(context.Context, string) (identity.CertificateInfo, error) {
		return identity.CertificateInfo{Certified: true, NotAfter: notAfter}, nil
	}})
	body := asOwner(t, unserved, "owner-a", "/api/dashboard").Body.String()
	if !strings.Contains(body, `"certificate":{"certified":true,"served":false,"renewal_due":false}`) {
		t.Errorf("an identity with no current leaf: %s", body)
	}

	// A contact list or a certificate that cannot be read fails the answer.
	for name, d := range map[string]DashboardDeps{
		"contacts": {Store: failingContacts{st}},
		"certificate": {Store: st, Certificate: func(context.Context, string) (identity.CertificateInfo, error) {
			return identity.CertificateInfo{}, errors.New("no")
		}},
	} {
		m := http.NewServeMux()
		MountDashboard(m, d)
		if rr := asOwner(t, m, "owner-a", "/api/dashboard"); rr.Code != http.StatusInternalServerError {
			t.Errorf("an unreadable %s answered %d: %s", name, rr.Code, rr.Body.String())
		}
	}

	// No session, no overview.
	plain := httptest.NewRecorder()
	mux.ServeHTTP(plain, httptest.NewRequest("GET", "/api/dashboard", nil))
	if plain.Code != http.StatusUnauthorized {
		t.Errorf("an ownerless read answered %d", plain.Code)
	}
}
