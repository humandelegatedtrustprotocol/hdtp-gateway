package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// PACT §5.2: a stranger at an address that belongs, or lately belonged, to a contact is "shown to
// the owner beside the name of the contact who holds or held that address". The node refused such
// a stranger auto-acceptance and kept the claim on the audit row only; the Requests tab now names
// the contact. The control is a request from an address nobody holds, which names nobody.
func TestTheRequestsTabNamesTheContactWhoseAddressARequestComesFrom(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "claim.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	const friendAt, freshAt = "https://bharat.example/mcp", "https://someone.example/mcp"
	friend, friendLeaf := movedLeaf(t, "Bharat", friendAt)
	squatter, squatterLeaf := movedLeaf(t, "Bharat", friendAt)
	stranger, strangerLeaf := movedLeaf(t, "Chen", freshAt)
	for _, c := range []store.Contact{
		{AccountID: a.ID, Fingerprint: friend, SPKI: []byte{1}, Status: "active", Endpoint: friendAt, Leaf: friendLeaf, DisplayName: "Bharat"},
		{AccountID: a.ID, Fingerprint: squatter, SPKI: []byte{2}, Status: "pending_in", Endpoint: friendAt, Leaf: squatterLeaf, DisplayName: "Bharat"},
		{AccountID: a.ID, Fingerprint: stranger, SPKI: []byte{3}, Status: "pending_in", Endpoint: freshAt, Leaf: strangerLeaf, DisplayName: "Chen"},
	} {
		if _, err := st.InsertContact(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetContactPetname(ctx, a.ID, friend, "Bharat from school"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{Store: st, Contacts: &contacts.Manager{Store: st}, Audit: (&recAudit{}).fn})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/requests?account="+a.ID, nil))
	var got struct {
		Pending []struct {
			Fingerprint   string `json:"fingerprint"`
			AddressOf     string `json:"address_of"`
			AddressOfName string `json:"address_of_name"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || len(got.Pending) != 2 {
		t.Fatalf("%d %s: %v", rr.Code, rr.Body.String(), err)
	}
	for _, p := range got.Pending {
		switch p.Fingerprint {
		case squatter:
			if p.AddressOf != friend || p.AddressOfName != "Bharat from school" {
				t.Errorf("the request at bharat's address names %q (%q), want bharat by the owner's name for him", p.AddressOf, p.AddressOfName)
			}
		case stranger:
			if p.AddressOf != "" || p.AddressOfName != "" {
				t.Errorf("a request from an address nobody holds names %q", p.AddressOfName)
			}
		}
	}
}
