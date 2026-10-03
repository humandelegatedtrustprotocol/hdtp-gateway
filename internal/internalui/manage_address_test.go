package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// movedLeaf is a leaf under a fresh root, naming endpoint: what a contact that moved presents.
func movedLeaf(t *testing.T, cn, endpoint string) (root string, leaf []byte) {
	t.Helper()
	at := time.Now().Add(-time.Hour)
	rootKey, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	host, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{CN: cn, RootCN: cn, RootKey: rootKey, HostPub: host.Public(),
		Endpoint: endpoint, NotBefore: at, NotAfter: at.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return hdtpidentity.Fingerprint(rootKey.Public().SPKI), leaf
}

// N-18: a contact parked at a new address under `ask` (HDTP §5.3) could be answered from the CLI
// alone — no portal route listed it or decided it, so a person on the portal never learned one was
// waiting. The Requests tab now lists it and approves or rejects it through the same decision.
func TestTheRequestsTabDecidesAContactAtANewAddress(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "addr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	acct := a.ID
	aud := &recAudit{}
	var invalidated []string
	inval := func(_ context.Context, _, fpr string) error { invalidated = append(invalidated, fpr); return nil }
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{Store: st, Contacts: &contacts.Manager{Store: st}, Audit: aud.fn, Invalidate: inval})
	MountDashboard(mux, DashboardDeps{Store: st})

	const oldAt, newAt = "https://old.example/alina", "https://new.example/alina"
	park := func(t *testing.T, cn string) string {
		t.Helper()
		root, oldLeaf := movedLeaf(t, cn, oldAt)
		if _, err := st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: root, SPKI: []byte{1}, Status: "active",
			Endpoint: oldAt, Leaf: oldLeaf, DisplayName: cn}); err != nil {
			t.Fatal(err)
		}
		_, newLeaf := movedLeaf(t, cn, newAt)
		if err := st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: acct, Root: root, Endpoint: newAt, Leaf: newLeaf, Why: "ask", At: 1}); err != nil {
			t.Fatal(err)
		}
		return root
	}
	approved, rejected := park(t, "Alina"), park(t, "Bo")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/requests?account="+acct, nil))
	var got struct {
		Addresses []contacts.AddressWaiting `json:"addresses"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("%d %s: %v", rr.Code, rr.Body.String(), err)
	}
	if len(got.Addresses) != 2 {
		t.Fatalf("GET /api/requests lists %d contacts at a new address, want 2: %s", len(got.Addresses), rr.Body.String())
	}
	for _, w := range got.Addresses {
		if w.Endpoint != newAt || w.Pinned != oldAt || w.Why != "ask" || w.Name == "" {
			t.Errorf("listed %+v: want pinned at %s, waiting at %s, why ask, with a name", w, oldAt, newAt)
		}
	}

	// The dashboard's "N waiting" links to this tab, so it counts what the tab holds. It answers an
	// owner, for the identities they administer.
	if _, err := st.CreateOwnerWithID(ctx, "owner-me", "Me"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembership(ctx, "owner-me", acct, "admin"); err != nil {
		t.Fatal(err)
	}
	rr = asOwner(t, mux, "owner-me", "/api/dashboard")
	var dash struct {
		Accounts []struct {
			Pending int `json:"pending"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &dash); err != nil || len(dash.Accounts) != 1 || dash.Accounts[0].Pending != 2 {
		t.Fatalf("the dashboard counts %+v waiting, want 2: %s", dash.Accounts, rr.Body.String())
	}
	// The overview answers what it shows and nothing else: the audit trail is the Audit page's, and a
	// member nobody renders is a read the page pays for on every visit.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	for k := range members {
		if k != "posture" && k != "accounts" {
			t.Errorf("the dashboard answers %q, which the overview does not show", k)
		}
	}

	decide := func(t *testing.T, root, decision string) int {
		t.Helper()
		return postForm(t, mux, "/requests/addresses/"+url.PathEscape(root)+"/"+decision+"?account="+acct, url.Values{}).Code
	}
	if code := decide(t, approved, "approve"); code != http.StatusSeeOther {
		t.Fatalf("approve answered %d", code)
	}
	if c, _ := st.GetContact(ctx, acct, approved); c.Endpoint != newAt {
		t.Fatalf("approving did not move the pin: %s", c.Endpoint)
	}
	if fe, _ := st.ListFormerEndpoints(ctx, acct); len(fe) != 1 || fe[0].Endpoint != oldAt {
		t.Fatalf("the address it left is not remembered: %+v", fe)
	}
	if !aud.hasRow("contact_address_approve", "contact:"+approved+" endpoint:"+newAt, "ok") {
		t.Errorf("approval not audited as the CLI audits it: %v", aud.rows)
	}

	if code := decide(t, rejected, "reject"); code != http.StatusSeeOther {
		t.Fatalf("reject answered %d", code)
	}
	if c, _ := st.GetContact(ctx, acct, rejected); c.Endpoint != oldAt {
		t.Fatalf("rejecting moved the pin: %s", c.Endpoint)
	}
	if !aud.hasRow("contact_address_reject", "contact:"+rejected, "ok") {
		t.Errorf("rejection not audited: %v", aud.rows)
	}
	if left, _ := st.ListPendingAddresses(ctx, acct); len(left) != 0 {
		t.Fatalf("decided addresses still wait: %+v", left)
	}
	// Either answer changes what that root is served, so its composed surface is dropped.
	if !slices.Contains(invalidated, approved) || !slices.Contains(invalidated, rejected) {
		t.Errorf("composed surfaces dropped for %v, want both roots", invalidated)
	}
	// Nothing waits for that root any more: a second answer is a 404, not a silent success.
	if code := decide(t, approved, "approve"); code != http.StatusNotFound {
		t.Fatalf("deciding an address nobody waits at answered %d, want 404", code)
	}
}
