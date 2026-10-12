package ownermcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// failingStore is the real store with one method made to fail with driver text. Every method it
// overrides records that it was reached, so a row whose refusal came from somewhere else (scope,
// a missing argument) cannot pass for a store failure.
type failingStore struct {
	store.Store
	fail   string
	called map[string]bool
}

func (f *failingStore) hit(m string) error {
	f.called[m] = true
	if f.fail == m {
		return fmt.Errorf("%s: %w", m, errors.New(storeCanary))
	}
	return nil
}

func (f *failingStore) ListContacts(ctx context.Context, a string) ([]store.Contact, error) {
	if err := f.hit("ListContacts"); err != nil {
		return nil, err
	}
	return f.Store.ListContacts(ctx, a)
}

func (f *failingStore) ListThreadsByAccount(ctx context.Context, a string) ([]store.Thread, error) {
	if err := f.hit("ListThreadsByAccount"); err != nil {
		return nil, err
	}
	return f.Store.ListThreadsByAccount(ctx, a)
}

func (f *failingStore) ListInvites(ctx context.Context, a string) ([]store.Invite, error) {
	if err := f.hit("ListInvites"); err != nil {
		return nil, err
	}
	return f.Store.ListInvites(ctx, a)
}

func (f *failingStore) SetContactPetname(ctx context.Context, a, fpr, name string) error {
	if err := f.hit("SetContactPetname"); err != nil {
		return err
	}
	return f.Store.SetContactPetname(ctx, a, fpr, name)
}

func (f *failingStore) UpdateContactTrust(ctx context.Context, a, fpr, trust string) error {
	if err := f.hit("UpdateContactTrust"); err != nil {
		return err
	}
	return f.Store.UpdateContactTrust(ctx, a, fpr, trust)
}

func (f *failingStore) UpdateContactPermissions(ctx context.Context, a, fpr string, perms []string, preset string) error {
	if err := f.hit("UpdateContactPermissions"); err != nil {
		return err
	}
	return f.Store.UpdateContactPermissions(ctx, a, fpr, perms, preset)
}

func (f *failingStore) ChangeBounds(ctx context.Context) (int64, int64, error) {
	if err := f.hit("ChangeBounds"); err != nil {
		return 0, 0, err
	}
	return f.Store.ChangeBounds(ctx)
}

func (f *failingStore) ListOpenPendingRequests(ctx context.Context, a string, now int64) ([]store.PendingRequest, error) {
	if err := f.hit("ListOpenPendingRequests"); err != nil {
		return nil, err
	}
	return f.Store.ListOpenPendingRequests(ctx, a, now)
}

func (f *failingStore) GetAccountPendingRequest(ctx context.Context, a, id string) (store.PendingRequest, error) {
	if err := f.hit("GetAccountPendingRequest"); err != nil {
		return store.PendingRequest{}, err
	}
	return f.Store.GetAccountPendingRequest(ctx, a, id)
}

// noStoreText fails when a tool's answer carries the canary or the database's own words, and
// decodes the refusal it must be.
func noStoreText(t *testing.T, name, body string, isErr bool) map[string]string {
	t.Helper()
	if strings.Contains(body, storeCanary) || strings.Contains(body, "sql:") {
		t.Errorf("%s: store text on the wire: %s", name, body)
	}
	var got map[string]string
	if !isErr || json.Unmarshal([]byte(body), &got) != nil {
		t.Errorf("%s: not a coded refusal: %s (IsError %v)", name, body, isErr)
	}
	return got
}

// Every owner tool that reads or writes the store answers a store failure as internal with the
// fixed detail: the error's text, the driver's words, stays off the wire. Each row's control is the
// same tool on the same store with nothing failing, which must get through.
func TestAStoreFailureAnswersInternalWithNoStoreText(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:c", Status: "active",
		CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	contact := map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:c"}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range contact {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	account := map[string]any{"account_id": e.acctA}
	for _, c := range []struct {
		tool, method string
		args         map[string]any
	}{
		{"list_contacts", "ListContacts", account},
		{"get_inbox", "ListThreadsByAccount", account},
		{"list_invites", "ListInvites", account},
		{"rename_contact", "SetContactPetname", with(map[string]any{"petname": "C"})},
		{"set_trust_flag", "UpdateContactTrust", with(map[string]any{"trust": "messages_only"})},
		{"set_permissions", "UpdateContactPermissions", with(map[string]any{"permissions": []string{"message.text"}})},
		{"wait_for_updates", "ChangeBounds", account},
		{"digest", "ListThreadsByAccount", account},
		{"list_pending", "ListOpenPendingRequests", account},
		{"answer_request", "GetAccountPendingRequest", map[string]any{"account_id": e.acctA, "request_id": "r1", "result": "x"}},
	} {
		run := func(fail string) (*failingStore, string, bool) {
			fs := &failingStore{Store: e.st, fail: fail, called: map[string]bool{}}
			d := e.deps
			d.Store = fs
			d.Pending = &integrations.AgentAnswered{Store: fs, Bus: e.deps.Bus, WaitBudget: time.Second}
			srv := NewServerWithExtra(d, Extra{Log: func(string, string, string) {}}, auth.Identity{OwnerID: e.owner})
			body, isErr := callParityResult(t, ctx, srv, c.tool, c.args)
			return fs, body, isErr
		}
		fs, body, isErr := run(c.method)
		if !fs.called[c.method] {
			t.Errorf("%s: never reached %s: %s", c.tool, c.method, body)
			continue
		}
		got := noStoreText(t, c.tool, body, isErr)
		if got["code"] != "internal" || got["detail"] != refusal.InternalDetail {
			t.Errorf("%s: answered %s, want internal with %q", c.tool, body, refusal.InternalDetail)
		}
		if c.tool == "answer_request" {
			// Its control is an id that names nothing: not_found, which a store failure used to
			// pass for.
			_, body, isErr := run("")
			if got := noStoreText(t, c.tool, body, isErr); got["code"] != "not_found" {
				t.Errorf("answer_request of a missing id answered %s, want not_found", body)
			}
			continue
		}
		if _, body, isErr := run(""); isErr {
			t.Errorf("%s: the control did not get through: %s", c.tool, body)
		}
	}
}

// The owner tools that act through the node's own functions (Extra) answer those functions'
// failures the same way: internal with the fixed detail, never the error's text. Each tool's
// control, the function answering, gets through.
func TestAnExtraFailureAnswersInternalWithNoStoreText(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	canary := fmt.Errorf("reading: %w", errors.New(storeCanary))
	for _, c := range []struct {
		tool string
		args map[string]any
		ex   func(err error) Extra
	}{
		{"export_card", map[string]any{"account_id": e.acctA}, func(err error) Extra {
			return Extra{Card: func(context.Context, string) (string, error) { return "", err }}
		}},
		{"identity_certificate", map[string]any{"account_id": e.acctA}, func(err error) Extra {
			return Extra{Certificate: func(context.Context, string) (identity.CertificateInfo, error) {
				return identity.CertificateInfo{}, err
			}}
		}},
		{"list_passkeys", map[string]any{}, func(err error) Extra {
			return Extra{Passkeys: func(context.Context) ([]auth.PasskeyInfo, error) { return nil, err }}
		}},
		{"remove_passkey", map[string]any{"id": "pk1"}, func(err error) Extra {
			return Extra{RemovePasskey: func(context.Context, string) error { return err }}
		}},
		{"list_integrations", map[string]any{"account_id": e.acctA}, func(err error) Extra {
			return Extra{Integrations: func(context.Context, string) ([]IntegrationView, error) { return nil, err }}
		}},
		{"audit_query", map[string]any{}, func(err error) Extra {
			return Extra{Audit: func(context.Context, string, int, func(string) bool) ([]store.AuditRow, error) { return nil, err }}
		}},
	} {
		answer := func(err error) (string, bool) {
			ex := c.ex(err)
			ex.Log = func(string, string, string) {}
			srv := NewServerWithExtra(e.deps, ex, auth.Identity{OwnerID: e.owner})
			return callParityResult(t, ctx, srv, c.tool, c.args)
		}
		body, isErr := answer(canary)
		if got := noStoreText(t, c.tool, body, isErr); got["code"] != "internal" || got["detail"] != refusal.InternalDetail {
			t.Errorf("%s: answered %s, want internal with %q", c.tool, body, refusal.InternalDetail)
		}
		if c.tool == "export_card" {
			continue // its control needs a real card; the other rows hold the shape
		}
		if body, isErr := answer(nil); isErr {
			t.Errorf("%s: the control did not get through: %s", c.tool, body)
		}
	}
}

// set_exposure and add_contact answer a sentence the node wrote about the arguments as
// bad_request with that sentence alone, a store failure as internal with the fixed detail, and
// neither carries the error behind it. Both answered every failure as bad_request with the
// error's text, and not as an error result. The control, a call that works, gets through.
func TestSetExposureAndAddContactKeepStoreTextOffTheWire(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sentence := `slack does not offer a tool called "x"`
	for _, c := range []struct {
		tool string
		args map[string]any
		ex   func(err error) Extra
	}{
		{"set_exposure", map[string]any{"account_id": e.acctA, "integration_id": "i1", "tools": []string{"x"}}, func(err error) Extra {
			return Extra{SetExposure: func(context.Context, string, string, []string) error { return err }}
		}},
		{"add_contact", map[string]any{"account_id": e.acctA, "invite_url": "https://peer.example/i/t"}, func(err error) Extra {
			return Extra{AddContact: func(context.Context, string, string, string, string, string) (AddContactResult, error) {
				return AddContactResult{Fingerprint: "sha256:p", Status: "pending_out"}, err
			}}
		}},
	} {
		answer := func(err error) (string, bool) {
			ex := c.ex(err)
			ex.Log = func(string, string, string) {}
			srv := NewServerWithExtra(e.deps, ex, auth.Identity{OwnerID: e.owner})
			return callParityResult(t, ctx, srv, c.tool, c.args)
		}
		body, isErr := answer(fmt.Errorf("publishing: %w", errors.New(storeCanary)))
		if got := noStoreText(t, c.tool, body, isErr); got["code"] != "internal" || got["detail"] != refusal.InternalDetail {
			t.Errorf("%s, a store failure: answered %s, want internal with %q", c.tool, body, refusal.InternalDetail)
		}
		body, isErr = answer(refusal.BadRequest(sentence, errors.New(storeCanary)))
		if got := noStoreText(t, c.tool, body, isErr); got["code"] != "bad_request" || got["detail"] != sentence {
			t.Errorf("%s, a refused argument: answered %s, want bad_request with %q", c.tool, body, sentence)
		}
		if body, isErr := answer(nil); isErr || strings.Contains(body, "code") {
			t.Errorf("%s: the control did not get through: %s", c.tool, body)
		}
	}
}

// send_to_contact answers the node's send refusals by code with the node's sentence: a contact
// the account does not hold not_found, one that is not active conflict. With no sentinel behind
// them they answered internal. The control, a send that is recorded, gets through.
func TestSendToContactAnswersTheNodesRefusalsByCode(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, c := range []struct {
		err        error
		code, want string
	}{
		{node.ErrUnknownContact, "not_found", "send: unknown contact"},
		{node.ErrNotActive, "conflict", "send: contact is not active"},
		{fmt.Errorf("recording: %w", errors.New(storeCanary)), "internal", refusal.InternalDetail},
		{nil, "", ""},
	} {
		d := e.deps
		d.Send = func(context.Context, string, string, messaging.Input) (messaging.Result, error) {
			return messaging.Result{Status: "delivered"}, c.err
		}
		srv := NewServerWithExtra(d, Extra{Log: func(string, string, string) {}}, auth.Identity{OwnerID: e.owner})
		body, isErr := callParityResult(t, ctx, srv, "send_to_contact", map[string]any{
			"account_id": e.acctA, "contact_fpr": "sha256:c", "msg_id": "m1", "text": "hi"})
		if c.err == nil {
			if isErr {
				t.Errorf("the control did not get through: %s", body)
			}
			continue
		}
		if got := noStoreText(t, "send_to_contact", body, isErr); got["code"] != c.code || got["detail"] != c.want {
			t.Errorf("%v: answered %s, want %s with %q", c.err, body, c.code, c.want)
		}
	}
}
