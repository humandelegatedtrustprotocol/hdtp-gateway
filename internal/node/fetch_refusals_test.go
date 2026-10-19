package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// #224. A fetch of a peer's link for an identity this node does not serve answered internal: the
// portal's POST /media/fetch, the one door that calls FetchMedia, said 500 "media: unknown
// account", as a send did before #207. It is refused as a send is: conflict for an identity the
// store holds that is awaiting its certificate or could not be loaded, not_found for one it does
// not hold. The control, a served identity, gets past this check to the message's.
func TestAFetchForAnIdentityThisNodeDoesNotServeIsRefusedByCode(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "fetch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	waiting, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "waiting", DisplayName: "W", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	broken, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "broken", DisplayName: "B", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{opts: Options{Store: st}, awaiting: map[string]struct{}{"waiting": {}}, unavailable: map[string]string{"broken": "x"}}
	for _, c := range []struct {
		name, account, code, detail string
	}{
		{"awaiting its certificate", waiting.ID, "conflict", "fetch: waiting has no certificate yet, so it cannot fetch: its wallet issues one"},
		{"not loaded", broken.ID, "conflict", "fetch: broken is not serving on this node"},
		{"not held", "nonesuch", "not_found", "fetch: unknown account"},
	} {
		_, err := n.FetchMedia(ctx, c.account, "m1")
		if code, detail := refusal.Of(err); code != c.code || detail != c.detail {
			t.Errorf("an identity %s: %s %q; want %s %q", c.name, code, detail, c.code, c.detail)
		}
	}
}

// The refusals of Building rule 3 at the door that calls FetchMedia, the portal's POST /media/fetch,
// over a served node and over one whose identity awaits its certificate: an identity the store does
// not hold is 404 and one awaiting its certificate 409 (#224: both were 500); a message the
// identity does not hold is 404, and so is another identity's message; a request naming no message
// is 400, as is a message with no link to fetch. The control is a message whose file the node
// already holds: it answers its hash. A caller with no session is refused 401 before the handler
// runs (TestTheSessionGateIsAnAllowList), and one naming an identity it does not administer 404
// (accountMiddleware, TestPortalRefusesAnAccountTheOwnerDoesNotAdminister).
func TestTheMediaFetchDoorRefusesByTheTargetsTruth(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 30)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 30)
	waiting, err := alina.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "waiting", DisplayName: "W", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	alina.n.mu.Lock()
	alina.n.awaiting["waiting"] = struct{}{}
	alina.n.mu.Unlock()

	acct := alina.n.accounts[alina.acct.ID]
	held, err := acct.media.SendInline(ctx, acct.msg, alina.acct.ID, "sha256:peer",
		messaging.Input{MsgID: "held", Origin: messaging.OriginMCP}, "a.txt", "text/plain", []byte("held bytes"))
	if err != nil {
		t.Fatal(err)
	}
	text, err := acct.msg.Record(ctx, alina.acct.ID, "sha256:peer", messaging.DirIn,
		messaging.Input{MsgID: "text", ThreadID: held.ThreadID, Text: "no link here", Origin: messaging.OriginPeer, Sender: messaging.SenderHuman})
	if err != nil {
		t.Fatal(err)
	}
	idOf := func(st store.Store, account, threadID, msgID string) string {
		t.Helper()
		msgs, err := st.ListMessagesByThread(ctx, account, threadID)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range msgs {
			if m.MsgID == msgID {
				return m.ID
			}
		}
		t.Fatalf("no message %s in thread %s", msgID, threadID)
		return ""
	}
	heldID, textID := idOf(alina.st, alina.acct.ID, held.ThreadID, "held"), idOf(alina.st, alina.acct.ID, text.ThreadID, "text")
	bacct := bharat.n.accounts[bharat.acct.ID]
	theirs, err := bacct.media.SendInline(ctx, bacct.msg, bharat.acct.ID, "sha256:peer",
		messaging.Input{MsgID: "theirs", Origin: messaging.OriginMCP}, "b.txt", "text/plain", []byte("their bytes"))
	if err != nil {
		t.Fatal(err)
	}
	// Another identity's message, named under Alina's: an id Alina's identity does not hold.
	theirsID := idOf(bharat.st, bharat.acct.ID, theirs.ThreadID, "theirs")

	mux := http.NewServeMux()
	internalui.MountMediaPages(mux, internalui.MediaDeps{Store: alina.st, Blobs: acct.media.Blobs, Fetch: alina.n.FetchMedia})
	fetch := func(form url.Values) (int, map[string]string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/media/fetch", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		var body map[string]string
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		return rr.Code, body
	}
	for _, c := range []struct {
		name    string
		form    url.Values
		want    int
		inError string
	}{
		{"an identity the store does not hold", url.Values{"account": {"nonesuch"}, "message": {heldID}}, http.StatusNotFound, "fetch: unknown account"},
		{"an identity awaiting its certificate", url.Values{"account": {waiting.ID}, "message": {heldID}}, http.StatusConflict, "no certificate yet"},
		{"a message the identity does not hold", url.Values{"account": {alina.acct.ID}, "message": {"no-such-message"}}, http.StatusNotFound, ""},
		{"another identity's message", url.Values{"account": {alina.acct.ID}, "message": {theirsID}}, http.StatusNotFound, ""},
		{"no message named", url.Values{"account": {alina.acct.ID}}, http.StatusBadRequest, "account and message are required"},
		{"a message with no link", url.Values{"account": {alina.acct.ID}, "message": {textID}}, http.StatusBadRequest, "not a media message with a link"},
	} {
		code, body := fetch(c.form)
		if code != c.want || !strings.Contains(body["error"], c.inError) || body["hash"] != "" {
			t.Errorf("%s: %d %v, want %d with an error saying %q", c.name, code, body, c.want, c.inError)
		}
	}
	// The control.
	if code, body := fetch(url.Values{"account": {alina.acct.ID}, "message": {heldID}}); code != http.StatusOK || body["hash"] == "" {
		t.Errorf("the control, a message whose file is held: %d %v", code, body)
	}
}
