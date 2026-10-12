package internalui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// pageCanary is driver text a failed action could carry; no page may show it.
const pageCanary = "pq: relation contacts_canary_7f3a does not exist"

// shown is the message a form's redirect carries to the page (`err`), and the notice (`added`).
func shown(t *testing.T, rr *httptest.ResponseRecorder) (errMsg, notice string) {
	t.Helper()
	loc, err := url.Parse(rr.Header().Get("Location"))
	if rr.Code != http.StatusSeeOther || err != nil {
		t.Fatalf("not a redirect: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	return loc.Query().Get("err"), loc.Query().Get("added")
}

// The portal's add-contact and send forms show the node's own sentence for a refusal it coded and
// a fixed phrase for anything else, never a store's text: both showed err.Error(). The control, an
// action that works, shows no error.
func TestThePortalsFormsShowNoStoreText(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	storeFailure := fmt.Errorf("reading contact: %w", errors.New(pageCanary))
	_, internal := refusal.Of(storeFailure)
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"a store failure", storeFailure, internal},
		{"a marked sentence", refusal.BadRequest("the invite link answered HTTP 404", errors.New(pageCanary)), "the invite link answered HTTP 404"},
		{"the control", nil, ""},
	} {
		mux := http.NewServeMux()
		MountContactPages(mux, ContactsDeps{Store: e.st,
			AddContact: func(context.Context, string, string, string, string, string) (string, string, error) {
				return "sha256:friend", "active", c.err
			}})
		form := url.Values{"invite_url": {"https://friend.example/i/tok"}, "account": {acct.ID}}
		req := httptest.NewRequest("POST", "/contacts/add?account="+acct.ID, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		got, notice := shown(t, rr)
		if got != c.want || strings.Contains(got, pageCanary) || strings.Contains(got, "sql:") {
			t.Errorf("add-contact, %s: the page shows %q, want %q", c.name, got, c.want)
		}
		if c.err == nil && notice == "" {
			t.Errorf("add-contact, the control: no notice")
		}
	}
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"a store failure", storeFailure, internal},
		{"an unknown contact", node.ErrUnknownContact, "send: unknown contact"},
		{"a refused message", fmt.Errorf("%w: text over 16 KiB", messaging.ErrTooLarge), "too_large: text over 16 KiB"},
		{"the control", nil, ""},
	} {
		mux := http.NewServeMux()
		MountMessagePages(mux, MessagesDeps{Store: e.st,
			Send: func(context.Context, string, string, messaging.Input) (messaging.Result, error) {
				return messaging.Result{}, c.err
			}})
		form := url.Values{"text": {"hi"}, "contact": {"sha256:friend"}, "account": {acct.ID}}
		req := httptest.NewRequest("POST", "/messages/send?account="+acct.ID, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if got, _ := shown(t, rr); got != c.want || strings.Contains(got, pageCanary) {
			t.Errorf("send, %s: the page shows %q, want %q", c.name, got, c.want)
		}
	}
}
