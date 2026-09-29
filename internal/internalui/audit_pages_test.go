package internalui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/audit"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
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
	w := &audit.Writer{Sink: store.AuditAppender{St: st}, Now: func() time.Time { return clock }}
	_ = w.Append(ctx, acctA.ID, "contact", "sha256:alina", "tools/call", "tool:send_message", "ok", "", "")
	_ = w.Append(ctx, acctB.ID, "contact", "sha256:bharat", "tools/call", "tool:book_slot", "ok", "", "")
	_ = w.Append(ctx, "", "owner", "o1", "portal_login", "", "ok", "", "")

	mux := http.NewServeMux()
	MountAuditPages(mux, AuditDeps{Store: st})
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
	w := &audit.Writer{Sink: store.AuditAppender{St: st}, Now: func() time.Time { return clock }}
	_ = w.Append(ctx, acctA.ID, "contact", "sha256:carol", "tools/call", "tool:get_card", "ok", "", "")

	rr := asOwner(t, mux, "owner-a", "/api/audit?actor=sha256:alina")
	body := rr.Body.String()
	if !strings.Contains(body, "send_message") || strings.Contains(body, "sha256:carol") || strings.Contains(body, "portal_login") {
		t.Fatalf("actor filter: %s", body)
	}
}

// failingContacts is a store whose contact lists cannot be read.
type failingContacts struct{ store.Store }

func (failingContacts) ListContacts(context.Context, string) ([]store.Contact, error) {
	return nil, errors.New("disk on fire")
}

// The owner, 2026-09-29: "audit page, we use names instead of ids". The answer carries a directory
// beside its rows (web/src/audit_names.ts reads it): each kind of id the rows write, by name —
// within the read's own scope, so naming never becomes a way to read what the scope withholds.
func TestTheAuditAnswerNamesItsIds(t *testing.T) {
	_, st, acctA, acctB := auditEnv(t)
	ctx := context.Background()
	for _, c := range []store.Contact{
		{AccountID: acctA.ID, Fingerprint: "sha256:alina", SPKI: []byte{1}, Status: "active", DisplayName: "Alina"},
		{AccountID: acctA.ID, Fingerprint: "sha256:quiet", SPKI: []byte{1}, Status: "active", DisplayName: "Never in a row"},
		{AccountID: acctB.ID, Fingerprint: "sha256:bharat", SPKI: []byte{1}, Status: "active", DisplayName: "Bharat"},
	} {
		if _, err := st.InsertContact(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	tokens := &auth.TokenService{Store: st}
	_, kept, err := tokens.Create(ctx, "owner-a", "laptop agent", "")
	if err != nil {
		t.Fatal(err)
	}
	_, revoked, err := tokens.Create(ctx, "owner-a", "old agent", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tokens.Revoke(ctx, revoked); err != nil {
		t.Fatal(err)
	}
	// A row about a contact who is no longer one: its fingerprint is in the row and in no list.
	w := &audit.Writer{Sink: store.AuditAppender{St: st}, Now: func() time.Time { return time.Unix(1756000200, 0) }}
	_ = w.Append(ctx, acctA.ID, "owner", "", "contact_remove", "account:"+acctA.ID+" contact:sha256:gone", "ok", "", "")

	passkeys := func(context.Context) ([]auth.PasskeyInfo, error) {
		return []auth.PasskeyInfo{{ID: "pk-1", OwnerID: "owner-a", Tag: "MacBook"}}, nil
	}
	mux := http.NewServeMux()
	MountAuditPages(mux, AuditDeps{Store: st, Tokens: tokens, Passkeys: passkeys})
	rr := asOwner(t, mux, "owner-a", "/api/audit")
	if rr.Code != 200 {
		t.Fatalf("audit: %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Names struct {
			Owners     map[string]string    `json:"owners"`
			Identities map[string]string    `json:"identities"`
			Contacts   map[string]string    `json:"contacts"`
			Keys       map[string]nameEntry `json:"keys"`
			Passkeys   map[string]string    `json:"passkeys"`
		} `json:"names"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	n := got.Names
	if n.Owners["owner-a"] != "Owner A" || n.Owners["owner-b"] != "Owner B" {
		t.Errorf("owners: %v", n.Owners)
	}
	// The identities of the read's scope, and no other: B is not owner A's.
	if n.Identities[acctA.ID] != "A" || len(n.Identities) != 1 {
		t.Errorf("identities: %v, want only %s", n.Identities, acctA.ID)
	}
	// Contacts the rows mention, from the scope's own lists: B's contact is not A's to name, a contact
	// no row mentions is not sent, and one no list holds is absent (the page says "not in your contacts").
	if n.Contacts["sha256:alina"] != "Alina" {
		t.Errorf("contacts: %v, want sha256:alina named", n.Contacts)
	}
	for _, not := range []string{"sha256:bharat", "sha256:quiet", "sha256:gone"} {
		if _, ok := n.Contacts[not]; ok {
			t.Errorf("contacts name %s: %v", not, n.Contacts)
		}
	}
	if n.Keys[kept] != (nameEntry{Name: "laptop agent"}) || n.Keys[revoked] != (nameEntry{Name: "old agent", Revoked: true}) {
		t.Errorf("keys: %v", n.Keys)
	}
	if n.Passkeys["pk-1"] != "MacBook" {
		t.Errorf("passkeys: %v", n.Passkeys)
	}

	// Without the token and passkey lists, those two are null — unknown — never an empty map, which
	// the page would read as "every key was deleted".
	bare := http.NewServeMux()
	MountAuditPages(bare, AuditDeps{Store: st})
	body := asOwner(t, bare, "owner-a", "/api/audit").Body.String()
	if !strings.Contains(body, `"keys":null`) || !strings.Contains(body, `"passkeys":null`) {
		t.Errorf("unwired lists are not null: %s", body)
	}

	// A list that cannot be read fails the answer: rows named from half a directory would read as a
	// trail whose people were removed.
	broken := http.NewServeMux()
	MountAuditPages(broken, AuditDeps{Store: failingContacts{st}})
	if rr := asOwner(t, broken, "owner-a", "/api/audit"); rr.Code != http.StatusInternalServerError {
		t.Errorf("an unreadable contact list answered %d: %s", rr.Code, rr.Body.String())
	}
}

// Build rule 1's divergence, named where a test holds it: the portal's /api/audit answers `names`
// beside its rows (for a person, who reads names); the owner MCP's `audit_query` (ownermcp/parity.go)
// answers the rows as stored, the shape agents and the cloud's battery already read. A change to
// either side is a decision this test makes somebody take: an `audit_query` that starts answering
// names takes this entry out, and one that stops answering bare rows is caught here too.
func TestTheAuditReadsDivergeInNamesAlone(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("ownermcp", "parity.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (ot ownerTools) auditQueryTool(")
	if start < 0 {
		t.Fatal("ownermcp/parity.go has no auditQueryTool")
	}
	end := strings.Index(body[start:], "\n}\n")
	tool := body[start : start+end]
	if !strings.Contains(tool, "jsonResult(rows)") {
		t.Errorf("audit_query no longer answers the rows as stored; if it names their ids now, remove this divergence:\n%s", tool)
	}
	if strings.Contains(tool, "names") {
		t.Errorf("audit_query mentions names; if it answers them, remove this divergence")
	}
}
