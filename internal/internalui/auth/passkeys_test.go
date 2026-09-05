package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

var testRP = RelyingParty{ID: rpID, Origin: origin}

const (
	rpID   = "localhost"
	origin = "http://localhost:8080"
)

type testEnv struct {
	svc   *Service
	st    *store.SQLite
	rp    virtualwebauthn.RelyingParty
	authn virtualwebauthn.Authenticator
	clock *time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := New(st)
	clock := time.Unix(1756000000, 0)
	svc.Now = func() time.Time { return clock }
	return &testEnv{
		svc:   svc,
		st:    st,
		rp:    virtualwebauthn.RelyingParty{Name: "pact-gateway", ID: rpID, Origin: origin},
		authn: virtualwebauthn.NewAuthenticator(),
		clock: &clock,
	}
}

// register drives a full registration ceremony through the virtual authenticator.
func (e *testEnv) register(t *testing.T, ownerID, ownerName, tag string) string {
	t.Helper()
	ctx := context.Background()
	opts, ceremony, err := e.svc.BeginRegistration(ctx, testRP, ownerID, ownerName)
	if err != nil {
		t.Fatal(err)
	}
	optsJSON, _ := json.Marshal(opts)
	parsed, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		t.Fatal(err)
	}
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	response := virtualwebauthn.CreateAttestationResponse(e.rp, e.authn, cred, *parsed)
	req := httptest.NewRequest("POST", "/auth/register/finish", bytes.NewReader([]byte(response)))
	req.Header.Set("Content-Type", "application/json")
	newOwnerID, err := e.svc.FinishRegistration(ctx, ceremony, ownerID, ownerName, tag, req)
	if err != nil {
		t.Fatal(err)
	}
	// the authenticator retains the credential (with the user handle) for logins
	e.authn.AddCredential(cred)
	e.authn.Options.UserHandle = []byte(newOwnerID)
	return newOwnerID
}

func (e *testEnv) login(t *testing.T) (string, error) {
	t.Helper()
	ctx := context.Background()
	opts, ceremony, err := e.svc.BeginLogin(ctx, testRP)
	if err != nil {
		return "", err
	}
	optsJSON, _ := json.Marshal(opts)
	parsed, err := virtualwebauthn.ParseAssertionOptions(string(optsJSON))
	if err != nil {
		t.Fatal(err)
	}
	cred := e.authn.Credentials[0]
	response := virtualwebauthn.CreateAssertionResponse(e.rp, e.authn, cred, *parsed)
	req := httptest.NewRequest("POST", "/auth/login/finish", bytes.NewReader([]byte(response)))
	req.Header.Set("Content-Type", "application/json")
	return e.svc.FinishLogin(ctx, ceremony, req)
}

func TestRegisterLoginSessionLifecycle(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	ownerID := e.register(t, "", "Sumit", "phone")
	if ownerID == "" {
		t.Fatal("no owner created on first registration")
	}
	n, _ := e.st.CountCredentialsByKind(ctx, "passkey")
	if n != 1 {
		t.Fatalf("passkeys stored: %d", n)
	}

	token, err := e.login(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.svc.SessionOwner(ctx, token); got != ownerID {
		t.Fatalf("session owner = %q, want %q", got, ownerID)
	}

	// expiry
	*e.clock = e.clock.Add(13 * time.Hour)
	if got := e.svc.SessionOwner(ctx, token); got != "" {
		t.Fatal("expired session still valid")
	}

	// logout kills a fresh session immediately
	*e.clock = e.clock.Add(-13 * time.Hour)
	token2, err := e.login(t)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Logout(ctx, token2)
	if got := e.svc.SessionOwner(ctx, token2); got != "" {
		t.Fatal("logged-out session still valid")
	}
}

func TestMultipleTaggedPasskeysAndRemoval(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	ownerID := e.register(t, "", "Sumit", "phone")
	_ = e.register(t, ownerID, "Sumit", "yubikey")

	keys, err := e.svc.ListPasskeys(ctx)
	if err != nil || len(keys) != 2 {
		t.Fatalf("list: %v %d", err, len(keys))
	}
	tags := map[string]bool{}
	for _, k := range keys {
		tags[k.Tag] = true
		if k.OwnerID != ownerID {
			t.Fatalf("wrong owner on %+v", k)
		}
	}
	if !tags["phone"] || !tags["yubikey"] {
		t.Fatalf("tags lost: %v", tags)
	}
	if err := e.svc.RemovePasskey(ctx, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.st.CountCredentialsByKind(ctx, "passkey"); n != 1 {
		t.Fatalf("removal failed: %d", n)
	}
}

func TestCeremonyIDsAreSingleUse(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_, ceremony, err := e.svc.BeginRegistration(ctx, testRP, "", "X")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte("{}")))
	_, _ = e.svc.FinishRegistration(ctx, ceremony, "", "X", "t", req) // consumes (fails to parse, still burns)
	if _, err := e.svc.FinishRegistration(ctx, ceremony, "", "X", "t", req); err == nil {
		t.Fatal("ceremony id reusable")
	}
	var _ = http.StatusOK
}

// AC (P7-03a): "the first passkey is the owner" is the trust root, so exactly
// one may win a race. The gate reads a count and the insert happens in a
// separate request, so without a critical section two concurrent finishes can
// both pass it.
func TestConcurrentFirstRegistrationYieldsOneOwner(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	// two ceremonies started before either finishes — the realistic race
	type ready struct {
		ceremony string
		body     []byte
	}
	var prepared []ready
	for i := 0; i < 2; i++ {
		opts, ceremony, err := e.svc.BeginRegistration(ctx, testRP, "", "owner")
		if err != nil {
			t.Fatal(err)
		}
		optsJSON, _ := json.Marshal(opts)
		parsed, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
		if err != nil {
			t.Fatal(err)
		}
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		resp := virtualwebauthn.CreateAttestationResponse(e.rp, e.authn, cred, *parsed)
		prepared = append(prepared, ready{ceremony: ceremony, body: []byte(resp)})
	}

	var wg sync.WaitGroup
	results := make([]error, len(prepared))
	for i, p := range prepared {
		wg.Add(1)
		go func(i int, p ready) {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/setup/finish", bytes.NewReader(p.body))
			req.Header.Set("Content-Type", "application/json")
			_, results[i] = e.svc.FinishRegistration(ctx, p.ceremony, "", "owner", "k", req)
		}(i, p)
	}
	wg.Wait()

	owners, err := e.svc.Store.ListOwners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 {
		t.Fatalf("%d owners were created by concurrent first registrations; "+
			"the first passkey decides who owns this node (errors: %v)", len(owners), results)
	}
}
