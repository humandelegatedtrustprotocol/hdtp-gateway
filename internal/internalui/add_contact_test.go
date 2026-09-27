package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// Reaching out to somebody — pasting the invite link they sent you — existed only
// as an owner-MCP tool (E16). The portal could CREATE invites and never redeem
// one, so an owner at the browser could be invited by a friend and have no way to
// accept: the Contacts page listed contacts and offered no way to add one.
//
// Same shape as the unreachable dashboard links, the missing sign-out and the
// path-only invite: a capability with no affordance. The portal and the owner MCP
// are meant to be at parity (SPEC §8.4), and they were not.
func TestContactsPageOffersAWayToAcceptAnInvite(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{
		Store: e.st,
		AddContact: func(context.Context, string, string, string, string, string) (string, string, error) {
			return "sha256:friend", "active", nil
		},
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/contacts?account="+acct.ID, nil)
	mux.ServeHTTP(rr, req)
	var got struct {
		CanAdd  bool     `json:"can_add"`
		Presets []string `json:"presets"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("contacts API did not answer JSON: %v — %s", err, firstN(rr.Body.String(), 200))
	}
	// The form lives in the SPA now; what the backend owes it is the signal that
	// adding is possible, and the presets its grant selector shows. The SPA's
	// side — that a form for invite_url exists at all — is held by the bundle
	// contract test in webui_test.go.
	if !got.CanAdd {
		t.Fatal("the API does not offer contact-adding even though AddContact is wired")
	}
	if len(got.Presets) == 0 {
		t.Error("no presets for the grant selector")
	}
}

// And it must actually redeem: the button has to reach the same code path the
// owner MCP's add_contact uses, or the two surfaces disagree about what happens.
func TestAcceptingAnInviteRedeemsIt(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	var gotAccount, gotURL string
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{
		Store: e.st,
		AddContact: func(_ context.Context, accountID, inviteURL, _, _, _ string) (string, string, error) {
			gotAccount, gotURL = accountID, inviteURL
			return "sha256:friend", "active", nil
		},
	})

	form := url.Values{"invite_url": {"https://friend.example/i/tok"}, "account": {acct.ID}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/contacts/add?account="+acct.ID,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rr, req)

	if gotURL != "https://friend.example/i/tok" {
		t.Errorf("the invite link never reached the redeemer: %q", gotURL)
	}
	if gotAccount != acct.ID {
		t.Errorf("redeemed as account %q, want %q", gotAccount, acct.ID)
	}
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
		t.Errorf("after accepting, the owner got %d", rr.Code)
	}
}

// A refusal must be shown, not swallowed: a link that is expired, revoked or
// simply mistyped is the common case, and silence looks like success.
func TestARefusedInviteIsReportedToTheOwner(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{
		Store: e.st,
		AddContact: func(context.Context, string, string, string, string, string) (string, string, error) {
			return "", "", errInviteRefused{}
		},
	})
	form := url.Values{"invite_url": {"https://friend.example/i/gone"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/contacts/add?account="+acct.ID,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rr, req)

	// The POST redirects, so a refresh cannot re-submit the invite, and the
	// refusal rides the redirect's query — which is exactly what the SPA reads
	// (response.url) to show its banner.
	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatalf("no redirect after a refused invite: %d", rr.Code)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u.Query().Get("err"), "expired") {
		t.Errorf("the refusal was never carried to the owner: redirect %q", loc)
	}
}

type errInviteRefused struct{}

func (errInviteRefused) Error() string { return "that invite is expired or already used" }

// SPEC §9.3: the portal imports a card, and on the owner's confirmation the node runs the PACT
// §5.2 manual flow — request_contact at the address the card names, landing pending_out. The
// portal took only an invite link, so a card an owner held out of band could reach a contact
// only through the owner MCP (review N-17). The same route now takes a card and a note, hands
// them to the same function add_contact calls, and says the answer is a wait, not a contact.
func TestAddingFromACardAsksAndSaysTheyAreWaiting(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	var gotURL, gotCard, gotNote string
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{
		Store: e.st,
		AddContact: func(_ context.Context, _, inviteURL, card, note, _ string) (string, string, error) {
			gotURL, gotCard, gotNote = inviteURL, card, note
			return "sha256:friend", "pending_out", nil
		},
	})
	const card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Friend\r\nEND:VCARD"
	form := url.Values{"card": {card}, "note": {"we met in Pune"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/contacts/add?account="+acct.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rr, req)

	if gotCard != card || gotNote != "we met in Pune" || gotURL != "" {
		t.Fatalf("the card path did not reach the adder as a card: url=%q card=%q note=%q", gotURL, gotCard, gotNote)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if said := loc.Query().Get("added"); !strings.Contains(said, "waiting") {
		t.Fatalf("a request that lands pending_out was reported as %q, not as a wait", said)
	}
}
