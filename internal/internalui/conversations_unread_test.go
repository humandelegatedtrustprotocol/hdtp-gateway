package internalui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// The inbox's unread counts are read at runtime from each conversation's read marker
// (threads.last_read_seq), over one page of conversations, and never stored. A row stops counting
// at UnreadCap and says so; the page's total is the sum of its rows, and says it is a floor when a
// row stopped or a conversation past the page has unread too. Showing a conversation marks it read
// through the newest message the view was shown (POST /messages/read).

type unreadEnv struct {
	st   store.Store
	mux  *http.ServeMux
	acct string
	seq  int
}

func newUnreadEnv(t *testing.T) *unreadEnv {
	t.Helper()
	e := newEnv(t)
	acct, err := e.st.CreateAccount(context.Background(), store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountMessagePages(mux, MessagesDeps{Store: e.st})
	return &unreadEnv{st: e.st, mux: mux, acct: acct.ID}
}

// contact adds a contact in a state, with one thread last active at `at`.
func (u *unreadEnv) contact(t *testing.T, acct, fpr, status string, at int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := u.st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: fpr, Status: status, DisplayName: strings.TrimPrefix(fpr, "sha256:")}); err != nil {
		t.Fatal(err)
	}
	if err := u.st.InsertThread(ctx, store.Thread{ID: acct + fpr, AccountID: acct, ContactFpr: fpr, CreatedAt: at, LastAt: at}); err != nil {
		t.Fatal(err)
	}
}

// msgs records n messages in a direction on the contact's thread.
func (u *unreadEnv) msgs(t *testing.T, acct, fpr, dir string, n int) {
	t.Helper()
	for range n {
		u.seq++
		mustMsg(t, u.st, store.Message{AccountID: acct, ContactFpr: fpr, ThreadID: acct + fpr, MsgID: fmt.Sprintf("m%d", u.seq),
			Direction: dir, Sender: "human", Kind: "text", Status: "delivered", Body: "hi", CreatedAt: 100})
	}
}

type unreadAnswer struct {
	Contacts []struct {
		Fpr    string `json:"fingerprint"`
		Unread tally  `json:"unread"`
	} `json:"contacts"`
	Unread  tally `json:"unread"`
	More    bool  `json:"more"`
	Through int64 `json:"through"`
}

func (u *unreadEnv) list(t *testing.T, q url.Values) unreadAnswer {
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
	var a unreadAnswer
	if err := json.Unmarshal(rr.Body.Bytes(), &a); err != nil {
		t.Fatalf("%v: %s", err, rr.Body)
	}
	return a
}

func (u *unreadEnv) read(t *testing.T, acct, fpr string, through int64) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"account": {acct}, "contact": {fpr}, "through": {strconv.FormatInt(through, 10)}}
	req := httptest.NewRequest("POST", "/messages/read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	u.mux.ServeHTTP(rr, req)
	return rr
}

func (a unreadAnswer) row(t *testing.T, fpr string) tally {
	t.Helper()
	for _, c := range a.Contacts {
		if c.Fpr == fpr {
			return c.Unread
		}
	}
	t.Fatalf("%s is not on the page", fpr)
	return tally{}
}

func TestEachConversationCountsItsUnreadAndThePageSumsThem(t *testing.T) {
	u := newUnreadEnv(t)
	u.contact(t, u.acct, "sha256:alina", "active", 300)
	u.msgs(t, u.acct, "sha256:alina", "in", 3)
	u.msgs(t, u.acct, "sha256:alina", "out", 2) // ours are never unread
	u.contact(t, u.acct, "sha256:bharat", "active", 200)
	u.msgs(t, u.acct, "sha256:bharat", "in", 1)
	u.contact(t, u.acct, "sha256:chen", "active", 100) // nothing from them
	u.contact(t, u.acct, "sha256:pending", "pending_in", 400)
	u.msgs(t, u.acct, "sha256:pending", "in", 5) // not a correspondent yet: not on the page, not in the sum

	a := u.list(t, nil)
	if got := a.row(t, "sha256:alina"); got != (tally{Count: 3}) {
		t.Errorf("alina: %+v, want 3", got)
	}
	if got := a.row(t, "sha256:bharat"); got != (tally{Count: 1}) {
		t.Errorf("bharat: %+v, want 1", got)
	}
	if got := a.row(t, "sha256:chen"); got != (tally{}) {
		t.Errorf("chen: %+v, want 0", got)
	}
	if a.Unread != (tally{Count: 4}) || a.More {
		t.Errorf("total %+v more %v; want 4, exact, no more", a.Unread, a.More)
	}
}

func TestAnEmptyInboxCountsZero(t *testing.T) {
	u := newUnreadEnv(t)
	a := u.list(t, nil)
	if len(a.Contacts) != 0 || a.Unread != (tally{}) || a.More {
		t.Fatalf("an empty inbox answered %+v", a)
	}
}

func TestAConversationOverTheCapSaysCapped(t *testing.T) {
	u := newUnreadEnv(t)
	u.contact(t, u.acct, "sha256:alina", "active", 100)
	u.msgs(t, u.acct, "sha256:alina", "in", UnreadCap)
	if a := u.list(t, nil); a.row(t, "sha256:alina") != (tally{Count: UnreadCap}) || a.Unread.Capped {
		t.Fatalf("exactly the cap is an exact count: %+v", a)
	}
	u.msgs(t, u.acct, "sha256:alina", "in", 1)
	a := u.list(t, nil)
	if got := a.row(t, "sha256:alina"); got != (tally{Count: UnreadCap, Capped: true}) {
		t.Fatalf("one past the cap: %+v, want %d capped", got, UnreadCap)
	}
	if a.Unread != (tally{Count: UnreadCap, Capped: true}) {
		t.Fatalf("a capped row leaves the total exact: %+v", a.Unread)
	}
	// A second conversation: the total stays at the cap, "50+", as BatonDeck's Inbox chip does.
	u.contact(t, u.acct, "sha256:bharat", "active", 50)
	u.msgs(t, u.acct, "sha256:bharat", "in", 1)
	if a := u.list(t, nil); a.Unread != (tally{Count: UnreadCap, Capped: true}) || a.row(t, "sha256:bharat") != (tally{Count: 1}) {
		t.Fatalf("a capped row and one more: total %+v, bharat %+v; want %d capped and 1", a.Unread, a.row(t, "sha256:bharat"), UnreadCap)
	}
}

// The sidebar's total stops at UnreadCap even when no row does: rows under the cap that sum past it
// read "50+" (owner: "show 50+ if more than 50"), and a sum at the cap is exact.
func TestThePagesTotalStopsAtTheCap(t *testing.T) {
	u := newUnreadEnv(t)
	u.contact(t, u.acct, "sha256:alina", "active", 200)
	u.msgs(t, u.acct, "sha256:alina", "in", UnreadCap-10)
	u.contact(t, u.acct, "sha256:bharat", "active", 100)
	u.msgs(t, u.acct, "sha256:bharat", "in", 10)
	if a := u.list(t, nil); a.Unread != (tally{Count: UnreadCap}) {
		t.Fatalf("a sum of exactly the cap: %+v, want %d exact", a.Unread, UnreadCap)
	}
	u.msgs(t, u.acct, "sha256:bharat", "in", 1)
	a := u.list(t, nil)
	if a.Unread != (tally{Count: UnreadCap, Capped: true}) {
		t.Fatalf("rows of %d and 11 summed to %+v, want %d capped", UnreadCap-10, a.Unread, UnreadCap)
	}
	if a.row(t, "sha256:alina") != (tally{Count: UnreadCap - 10}) || a.row(t, "sha256:bharat") != (tally{Count: 11}) {
		t.Fatalf("the rows stay exact under their own cap: %+v", a.Contacts)
	}
}

func TestUnreadPastThePageMakesTheTotalAFloor(t *testing.T) {
	u := newUnreadEnv(t)
	// ConversationsPage+1 conversations; the oldest falls off the page.
	for i := range ConversationsPage + 1 {
		u.contact(t, u.acct, fmt.Sprintf("sha256:c%03d", i), "active", int64(1000-i))
	}
	oldest := fmt.Sprintf("sha256:c%03d", ConversationsPage)
	u.msgs(t, u.acct, "sha256:c000", "in", 2)

	a := u.list(t, nil)
	if len(a.Contacts) != ConversationsPage || !a.More {
		t.Fatalf("page of %d, more %v; want %d and more", len(a.Contacts), a.More, ConversationsPage)
	}
	// Past the page there is nothing unread: the sum is the whole, and saying "more than" would be false.
	if a.Unread != (tally{Count: 2}) {
		t.Fatalf("total %+v with nothing unread past the page, want exactly 2", a.Unread)
	}
	u.msgs(t, u.acct, oldest, "in", 1)
	a = u.list(t, nil)
	if a.Unread != (tally{Count: 2, Capped: true}) {
		t.Fatalf("total %+v with an unread message past the page, want 2 capped", a.Unread)
	}

	// The selected conversation is on the page wherever it falls, and a search reaches past the cut.
	if a := u.list(t, url.Values{"contact": {oldest}}); a.row(t, oldest) != (tally{Count: 1}) {
		t.Fatalf("the selected conversation: %+v", a)
	}
	a = u.list(t, url.Values{"q": {strings.TrimPrefix(oldest, "sha256:")}})
	if len(a.Contacts) != 1 || a.Contacts[0].Fpr != oldest || a.More {
		t.Fatalf("a search for the oldest answered %+v", a)
	}
}

func TestShowingAConversationZeroesItsCount(t *testing.T) {
	u := newUnreadEnv(t)
	u.contact(t, u.acct, "sha256:alina", "active", 200)
	u.msgs(t, u.acct, "sha256:alina", "in", 2)
	u.contact(t, u.acct, "sha256:bharat", "active", 100)
	u.msgs(t, u.acct, "sha256:bharat", "in", 1)

	// Reading the list marks nothing: the sidebar's poll must not.
	shown := u.list(t, url.Values{"contact": {"sha256:alina"}})
	if shown.row(t, "sha256:alina") != (tally{Count: 2}) || shown.Through == 0 {
		t.Fatalf("before marking: %+v", shown)
	}
	// One lands after the view was shown: marking through what it showed leaves it unread.
	u.msgs(t, u.acct, "sha256:alina", "in", 1)
	rr := u.read(t, u.acct, "sha256:alina", shown.Through)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"unread":{"count":1,"capped":false}`) {
		t.Fatalf("mark read: %d %s", rr.Code, rr.Body)
	}
	again := u.list(t, url.Values{"contact": {"sha256:alina"}})
	if again.row(t, "sha256:alina") != (tally{Count: 1}) {
		t.Fatalf("the message after the mark: %+v, want 1", again.row(t, "sha256:alina"))
	}
	if rr := u.read(t, u.acct, "sha256:alina", again.Through); rr.Code != 200 {
		t.Fatalf("mark read: %d %s", rr.Code, rr.Body)
	}
	a := u.list(t, nil)
	if a.row(t, "sha256:alina") != (tally{}) || a.row(t, "sha256:bharat") != (tally{Count: 1}) || a.Unread != (tally{Count: 1}) {
		t.Fatalf("after reading alina: %+v", a)
	}
	// Idempotent: again, and a stale mark, change nothing.
	for _, through := range []int64{again.Through, shown.Through} {
		if rr := u.read(t, u.acct, "sha256:alina", through); rr.Code != 200 || !strings.Contains(rr.Body.String(), `"count":0`) {
			t.Fatalf("a repeat mark through %d: %d %s", through, rr.Code, rr.Body)
		}
	}
	if a := u.list(t, nil); a.row(t, "sha256:alina") != (tally{}) {
		t.Fatalf("a repeat mark brought unread back: %+v", a)
	}
}

func TestMarkingReadRefusesWhatIsNotThisIdentitysConversation(t *testing.T) {
	u := newUnreadEnv(t)
	other, err := u.st.CreateAccount(context.Background(), store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	u.contact(t, u.acct, "sha256:alina", "active", 100)
	u.msgs(t, u.acct, "sha256:alina", "in", 1)
	mine := u.list(t, url.Values{"contact": {"sha256:alina"}}).Through
	u.contact(t, u.acct, "sha256:blocked", "blocked", 100)
	u.msgs(t, u.acct, "sha256:blocked", "in", 1)
	u.contact(t, other.ID, "sha256:theirs", "active", 100)
	u.msgs(t, other.ID, "sha256:theirs", "in", 1)
	theirs, _ := u.st.ListMessagesByThread(context.Background(), other.ID, other.ID+"sha256:theirs")
	blocked, _ := u.st.ListMessagesByThread(context.Background(), u.acct, u.acct+"sha256:blocked")

	for _, c := range []struct {
		name      string
		acct, fpr string
		through   int64
		code      int
	}{
		{"an unknown contact", u.acct, "sha256:nobody", mine, 404},
		{"another identity's contact", u.acct, "sha256:theirs", theirs[0].Seq, 404},
		{"a message of another identity's", u.acct, "sha256:alina", theirs[0].Seq, 404},
		{"a blocked contact, through its own message", u.acct, "sha256:blocked", blocked[0].Seq, 404},
		{"no contact", u.acct, "", mine, 400},
		{"no message", u.acct, "sha256:alina", 0, 400},
		// The control, last: a receiver that refused everything would pass every case above.
		{"control: this identity's conversation", u.acct, "sha256:alina", mine, 200},
	} {
		if rr := u.read(t, c.acct, c.fpr, c.through); rr.Code != c.code {
			t.Errorf("%s: %d %s, want %d", c.name, rr.Code, rr.Body, c.code)
		}
	}
	// The refusals moved nobody's marker; the control moved only its own.
	if n, _ := u.st.UnreadWithContactUpTo(context.Background(), other.ID, "sha256:theirs", 10); n != 1 {
		t.Errorf("another identity's conversation has %d unread after the refusals, want 1", n)
	}
	if n, _ := u.st.UnreadWithContactUpTo(context.Background(), u.acct, "sha256:blocked", 10); n != 1 {
		t.Errorf("the blocked contact's thread has %d unread after the refusals, want 1", n)
	}
}

// SPEC §8.2 names the page and the cap as numbers; they are these constants, or the sentence is false.
func TestTheSpecSaysTheInboxPageAndCap(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join(repoRootUI(t), "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		fmt.Sprintf("one page of the %d most recently active conversations", ConversationsPage),
		fmt.Sprintf("stopped at %d (\"%d+\")", UnreadCap, UnreadCap),
		fmt.Sprintf("the sidebar's Inbox count the page's sum, stopped at the same %d", UnreadCap),
	} {
		if !strings.Contains(string(spec), want) {
			t.Errorf("SPEC.md does not say %q", want)
		}
	}
}
