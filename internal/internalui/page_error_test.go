package internalui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
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

// A message recorded and not delivered is shown as such on all three of the portal's sends — the
// conversation form, the thread form and the file upload: "recorded, not delivered: <why>", with the
// upload still saying it was recorded, and no text of the error behind it. They showed the error's
// text ("recorded, but delivery failed: <dial error>"). The control, a delivered send, shows no error.
func TestThePortalsSendsSayARecordedMessageWasNotDelivered(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	const want = "recorded, not delivered: unreachable"
	undelivered := refusal.Undelivered("unreachable", fmt.Errorf("dial: %w", errors.New(pageCanary)))
	for _, fail := range []bool{true, false} {
		res, sendErr := messaging.Result{ThreadID: "t1", Status: "delivered"}, error(nil)
		if fail {
			res, sendErr = messaging.Result{ThreadID: "t1", Status: "pending"}, undelivered
		}
		send := func(context.Context, string, string, messaging.Input) (messaging.Result, error) { return res, sendErr }
		sendMedia := func(context.Context, string, string, messaging.Input, string, string, []byte) (messaging.Result, error) {
			return res, sendErr
		}
		mux := http.NewServeMux()
		MountMessagePages(mux, MessagesDeps{Store: e.st, Send: send, SendMedia: sendMedia})
		MountInboxPages(mux, InboxDeps{Store: e.st, Send: send})

		form := func(path string, v url.Values) *httptest.ResponseRecorder {
			req := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			return rr
		}
		conv, _ := shown(t, form("/messages/send?account="+acct.ID, url.Values{"text": {"hi"}, "contact": {"sha256:friend"}, "account": {acct.ID}}))
		thread := form("/thread/send?account="+acct.ID, url.Values{"text": {"hi"}, "contact": {"sha256:friend"}, "thread_id": {"t1"}, "msg_id": {"m1"}, "account": {acct.ID}})

		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("contact", "sha256:friend")
		_ = mw.WriteField("msg_id", "m2")
		fw, _ := mw.CreateFormFile("file", "a.txt")
		_, _ = fw.Write([]byte("hello"))
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/messages/send_media?account="+acct.ID, &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		media := httptest.NewRecorder()
		mux.ServeHTTP(media, req)

		all := conv + " " + thread.Body.String() + " " + media.Body.String()
		if strings.Contains(all, pageCanary) || strings.Contains(all, "dial") {
			t.Errorf("the error's text on a page: %s", all)
		}
		if !fail {
			if conv != "" || thread.Code != http.StatusSeeOther || !strings.Contains(media.Body.String(), `"ok":true`) {
				t.Errorf("the control: %q, %d %s, %s", conv, thread.Code, thread.Body, media.Body)
			}
			continue
		}
		if conv != want {
			t.Errorf("the conversation form shows %q, want %q", conv, want)
		}
		if thread.Code != http.StatusBadGateway || strings.TrimSpace(thread.Body.String()) != want {
			t.Errorf("the thread form answered %d %q, want 502 %q", thread.Code, thread.Body, want)
		}
		if media.Code != http.StatusBadGateway || !strings.Contains(media.Body.String(), `"error":"`+want+`"`) ||
			!strings.Contains(media.Body.String(), `"recorded":true`) {
			t.Errorf("the upload answered %d %s", media.Code, media.Body)
		}
	}
}
