package internalui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/ownermcp"
)

// A removed contact's conversation stays in the inbox (owner, 2026-10-09: "conversation should live
// since its record of exchange even if contact is deleted"), named by what its threads kept when the
// row was deleted and marked removed; it is read like any other, and a contact added again is named
// by its row.

type removedRow struct {
	Fpr    string `json:"fingerprint"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Unread tally  `json:"unread"`
}

func (u *unreadEnv) rows(t *testing.T, q url.Values) map[string]removedRow {
	t.Helper()
	if q == nil {
		q = url.Values{}
	}
	q.Set("account", u.acct)
	rr := httptest.NewRecorder()
	u.mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/conversations?"+q.Encode(), nil))
	if rr.Code != 200 {
		t.Fatalf("GET /api/conversations: %d %s", rr.Code, rr.Body)
	}
	var a struct {
		Contacts []removedRow `json:"contacts"`
		Messages []convMessage
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &a); err != nil {
		t.Fatalf("%v: %s", err, rr.Body)
	}
	out := map[string]removedRow{}
	for _, c := range a.Contacts {
		out[c.Fpr] = c
	}
	return out
}

func TestARemovedContactsConversationListsUnderItsKeptNameMarkedRemoved(t *testing.T) {
	u := newUnreadEnv(t)
	ctx := context.Background()
	u.contact(t, u.acct, "sha256:alex", "active", 300) // display name "alex"
	u.msgs(t, u.acct, "sha256:alex", "in", 2)
	u.contact(t, u.acct, "sha256:pat", "active", 250)
	if err := u.st.SetContactPetname(ctx, u.acct, "sha256:pat", "Patricia (work)"); err != nil {
		t.Fatal(err)
	}
	u.contact(t, u.acct, "sha256:dana", "active", 200)
	u.contact(t, u.acct, "sha256:blocked", "blocked", 100)
	for _, fpr := range []string{"sha256:alex", "sha256:pat"} {
		if err := u.st.DeleteContact(ctx, u.acct, fpr); err != nil {
			t.Fatal(err)
		}
	}
	// A conversation whose contact went before names were kept: no name to show, and still removed.
	if err := u.st.InsertThread(ctx, store.Thread{ID: "th-old", AccountID: u.acct, ContactFpr: "sha256:0123456789abcdefXYZ", CreatedAt: 50, LastAt: 50}); err != nil {
		t.Fatal(err)
	}

	got := u.rows(t, nil)
	want := map[string]removedRow{
		"sha256:alex":                {Label: "alex · removed", Status: "removed", Unread: tally{Count: 2}},
		"sha256:pat":                 {Label: "Patricia (work) · removed", Status: "removed"},
		"sha256:dana":                {Label: "dana", Status: "active"},
		"sha256:0123456789abcdefXYZ": {Label: "0123456789ab… · removed", Status: "removed"},
	}
	for fpr, w := range want {
		g, ok := got[fpr]
		w.Fpr = fpr
		if !ok || g != w {
			t.Errorf("%s: got %+v (listed %v), want %+v", fpr, g, ok, w)
		}
	}
	// A blocked row with a conversation keeps it listed, under the row's name and status.
	if g := got["sha256:blocked"]; g.Label != "blocked" || g.Status != "blocked" {
		t.Errorf("the blocked contact's conversation: %+v", g)
	}

	// The search reads the label the row shows.
	if hit := u.rows(t, url.Values{"q": {"removed"}}); len(hit) != 3 || hit["sha256:dana"] != (removedRow{}) || hit["sha256:blocked"] != (removedRow{}) {
		t.Errorf("searching 'removed' found %v", hit)
	}

	// Read like any other conversation: the mark lands and the count drops.
	a := u.list(t, url.Values{"contact": {"sha256:alex"}})
	if a.Through == 0 {
		t.Fatal("the removed conversation's messages were not shown")
	}
	if rr := u.read(t, u.acct, "sha256:alex", a.Through); rr.Code != 200 {
		t.Fatalf("marking a removed conversation read: %d %s", rr.Code, rr.Body)
	}
	if n := u.rows(t, nil)["sha256:alex"].Unread; n.Count != 0 {
		t.Errorf("after the read, %+v unread", n)
	}
	// The refusals stand: a message of another conversation, and a fingerprint with no conversation.
	if rr := u.read(t, u.acct, "sha256:blocked", a.Through); rr.Code != 404 {
		t.Errorf("a blocked row's read through alex's message: %d", rr.Code)
	}
	if rr := u.read(t, u.acct, "sha256:nobody", a.Through); rr.Code != 404 {
		t.Errorf("an unknown fingerprint's read: %d", rr.Code)
	}

	// Added again, under a new name: the row's name, and no marker.
	if _, err := u.st.InsertContact(ctx, store.Contact{AccountID: u.acct, Fingerprint: "sha256:alex", Status: "active", DisplayName: "Alexandra"}); err != nil {
		t.Fatal(err)
	}
	if g := u.rows(t, nil)["sha256:alex"]; g.Label != "Alexandra" || g.Status != "active" {
		t.Errorf("re-added: %+v", g)
	}
}

// A kept name is a name a peer chose, and it is decorated by the rule two live ones are: a removed
// "dana" beside a live "dana" carries its fingerprint, and so does the live one.
func TestAKeptNameThatMatchesALiveOneCarriesItsFingerprint(t *testing.T) {
	u := newUnreadEnv(t)
	ctx := context.Background()
	u.contact(t, u.acct, "sha256:dana", "active", 300)
	if err := u.st.DeleteContact(ctx, u.acct, "sha256:dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.st.InsertContact(ctx, store.Contact{AccountID: u.acct, Fingerprint: "sha256:dana-two", Status: "active", DisplayName: "dana"}); err != nil {
		t.Fatal(err)
	}
	got := u.rows(t, nil)
	if g := got["sha256:dana"].Label; g != "dana · dana · removed" {
		t.Errorf("removed: %q", g)
	}
	if g := got["sha256:dana-two"].Label; g != "dana · dana-two" {
		t.Errorf("live: %q", g)
	}
}

// The owner's rule is that the record lives: a removed contact who asks again (a pending_in row now
// names the fingerprint) keeps the history listed, named by the request's row and with its status,
// read-only in the view; when that request expires the conversation is "removed" again, under the
// petname the owner gave before.
func TestARemovedContactAskingAgainKeepsTheHistoryListed(t *testing.T) {
	u := newUnreadEnv(t)
	ctx := context.Background()
	u.contact(t, u.acct, "sha256:sam", "active", 300)
	u.msgs(t, u.acct, "sha256:sam", "in", 1)
	if err := u.st.SetContactPetname(ctx, u.acct, "sha256:sam", "Sam from climbing"); err != nil {
		t.Fatal(err)
	}
	if err := u.st.DeleteContact(ctx, u.acct, "sha256:sam"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.st.InsertContact(ctx, store.Contact{AccountID: u.acct, Fingerprint: "sha256:sam", Status: "pending_in", DisplayName: "Samuel", CreatedAt: 100}); err != nil {
		t.Fatal(err)
	}
	if g := u.rows(t, nil)["sha256:sam"]; g.Label != "Samuel" || g.Status != "pending_in" || g.Unread.Count != 1 {
		t.Errorf("while the request waits: %+v", g)
	}
	if a := u.list(t, url.Values{"contact": {"sha256:sam"}}); a.Through == 0 {
		t.Error("the history is not shown while the request waits")
	}
	if _, err := u.st.DeleteExpiredPendingContacts(ctx, u.acct, 500); err != nil {
		t.Fatal(err)
	}
	if g := u.rows(t, nil)["sha256:sam"]; g.Label != "Sam from climbing · removed" || g.Status != "removed" {
		t.Errorf("after the request expired: %+v", g)
	}
}

// The conversation list and get_inbox say a removed contact in one word: two copies, held here.
func TestTheListAndGetInboxSayRemovedInOneWord(t *testing.T) {
	if statusRemoved != ownermcp.StatusRemoved {
		t.Fatalf("the list says %q, get_inbox %q", statusRemoved, ownermcp.StatusRemoved)
	}
}
