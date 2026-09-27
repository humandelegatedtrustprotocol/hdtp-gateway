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

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"os"
	"strings"
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

// ValidRelyingPartyID is what refuses an `internal_host` when the config is read, and it says it
// refuses EXACTLY what a ceremony would have refused later. That is a claim about two code paths, so
// they are asked the same question about the same names.
func TestTheConfigCheckAndTheCeremonyAgreeAboutARelyingParty(t *testing.T) {
	for _, host := range []string{
		"pact.example.com", "node.tail1234.ts.net", "localhost", "a_b.example.com",
		"nas", "raspberrypi", "192.168.1.10", "::1", "pact.example.com.", "-pact.example.com", "pact-.example.com",
		"pact.example.123", "bücher.example", " pact.example.com",
		// NOT the empty name: there the two DISAGREE (the library's constructor takes an empty relying
		// party and objects only when a ceremony begins). The config check is never asked about it —
		// an empty `internal_host` means "loopback only" — so the claim is about every name it IS asked.
	} {
		_, ceremony := webauthnFor(RelyingParty{ID: strings.ToLower(host), Origin: "https://" + strings.ToLower(host)})
		config := ValidRelyingPartyID(host)
		if (ceremony == nil) != (config == nil) {
			t.Errorf("%q: the config check says %v and a ceremony says %v", host, config, ceremony)
		}
	}
}

// A passkey the PREVIOUS library stored must still sign its owner in. go-webauthn 0.18 announced
// breaking changes and a changed `Credential`; its migration guide says a 0.17 record decodes with a
// zero `Extensions`. That is a sentence in a guide, and an owner locked out of their own node is what
// it costs to be wrong — so here is a record 0.17.4 really wrote (testdata, made on 2026-09-21 by
// running this suite's own registration in a checkout from before the bump, a3b69ac, with the virtual
// authenticator's key beside it), and today's library is asked to log in with it.
func TestAPasskeyStoredByThePreviousLibraryStillSignsItsOwnerIn(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "passkey-webauthn-0.17.4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		OwnerID   string `json:"owner_id"`
		OwnerName string `json:"owner_name"`
		Row       struct {
			ID, Kind, Tag string
			OwnerID       string          `json:"owner_id"`
			Data          json.RawMessage `json:"data"`
			CreatedAt     int64           `json:"created_at"`
		} `json:"row"`
		Authenticator struct {
			CredentialID []byte `json:"credential_id"`
			KeyType      string `json:"key_type"`
			KeyData      []byte `json:"key_data"`
			Counter      uint32 `json:"counter"`
			UserHandle   []byte `json:"user_handle"`
			AAGUID       []byte `json:"aaguid"`
		} `json:"authenticator"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(f.Row.Data, []byte(`"extensions"`)) {
		t.Fatal("the fixture already has the member 0.18 added: it is not a 0.17 record")
	}

	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.st.CreateOwnerWithID(ctx, f.OwnerID, f.OwnerName); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertCredential(ctx, store.Credential{ID: f.Row.ID, OwnerID: f.Row.OwnerID, Kind: f.Row.Kind, Tag: f.Row.Tag, Data: f.Row.Data, CreatedAt: f.Row.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	cred := virtualwebauthn.NewCredentialWithImportedKey(virtualwebauthn.KeyType(f.Authenticator.KeyType), f.Authenticator.KeyData)
	cred.ID, cred.Counter = f.Authenticator.CredentialID, f.Authenticator.Counter
	e.authn.Aaguid = [16]byte(f.Authenticator.AAGUID)
	e.authn.AddCredential(cred)
	e.authn.Options.UserHandle = f.Authenticator.UserHandle

	session, err := e.login(t)
	if err != nil {
		t.Fatalf("a passkey stored by go-webauthn 0.17.4 no longer signs its owner in: %v", err)
	}
	if owner := e.svc.SessionOwner(ctx, session); owner != f.OwnerID {
		t.Fatalf("the session is %q's, and the passkey is %q's", owner, f.OwnerID)
	}
	// …and once more, so whatever this library wrote back over the old record still reads.
	if _, err := e.login(t); err != nil {
		t.Fatalf("the second login, after 0.18 rewrote the record: %v", err)
	}
}

// A stored credential that will not decode must be an error with the row's id in it, not a
// row quietly stepped over. Skipping it made two readers of one table disagree: the count
// behind `needs_setup` still saw the row, so the portal would not offer the enrolment
// wizard, while `BeginLogin` saw an empty list and answered "no passkeys registered".
// Somebody whose only passkey row was corrupt was locked out and told the opposite of what
// the node knew, with nothing recorded anywhere.
func TestAStoredCredentialThatWillNotDecodeIsAnErrorAndNotAnAbsence(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	owner, err := e.st.CreateOwnerWithID(ctx, "own-corrupt", "Corrupt Row")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertCredential(ctx, store.Credential{
		ID: "cred-broken", OwnerID: owner.ID, Kind: "passkey", Tag: "laptop",
		Data: []byte(`{"cred": "this is not a credential object"}`), CreatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// The count — what `needs_setup` is computed from — still sees it, which is why the
	// portal will not send this person to the wizard and why the silence was a dead end.
	n, err := e.st.CountCredentialsByKind(ctx, "passkey")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the count behind needs_setup sees %d rows, want 1", n)
	}

	_, _, err = e.svc.BeginLogin(ctx, testRP)
	if err == nil {
		t.Fatal("a credential that will not decode was stepped over: BeginLogin reported no error")
	}
	if !strings.Contains(err.Error(), "cred-broken") {
		t.Fatalf("the error does not name the row an operator has to fix: %v", err)
	}
	if strings.Contains(err.Error(), "no passkeys registered") {
		t.Fatalf("a row that will not read was reported as nothing being registered: %v", err)
	}
}

// Login is discoverable (BeginLogin: BeginDiscoverableLogin, no allowCredentials), so the browser
// can offer only a credential the authenticator can find by itself. Registration must therefore ask
// for a discoverable credential: with the library's empty selection the browser's default is
// residentKey "discouraged", and an authenticator that honours it (Chrome's virtual authenticator,
// measured 2026-09-28; a physical security key is not measured) makes a credential that registers,
// signs the owner in once, and can never sign in again — found when a public URL change renamed the session cookie and the
// portal's own sign-in page refused the only passkey the node had.
func TestRegistrationAsksForTheDiscoverableCredentialThatLoginNeeds(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	opts, _, err := e.svc.BeginRegistration(ctx, testRP, "", "Sumit")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(opts)
	var reg struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				ResidentKey        string `json:"residentKey"`
				RequireResidentKey *bool  `json:"requireResidentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	sel := reg.PublicKey.AuthenticatorSelection
	if sel.ResidentKey != "required" || sel.RequireResidentKey == nil || !*sel.RequireResidentKey {
		t.Fatalf("registration asks residentKey=%q requireResidentKey=%v; login is discoverable, so it must require one\n%s", sel.ResidentKey, sel.RequireResidentKey, raw)
	}

	// The control: login really does offer no credential list, which is why the above matters.
	e.register(t, "", "Sumit", "phone")
	lopts, _, err := e.svc.BeginLogin(ctx, testRP)
	if err != nil {
		t.Fatal(err)
	}
	lraw, _ := json.Marshal(lopts)
	var login struct {
		PublicKey struct {
			AllowCredentials []json.RawMessage `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(lraw, &login); err != nil {
		t.Fatal(err)
	}
	if len(login.PublicKey.AllowCredentials) != 0 {
		t.Fatalf("login now names %d credentials; this test's premise (discoverable login) no longer holds — revisit it", len(login.PublicKey.AllowCredentials))
	}
	if _, err := e.login(t); err != nil {
		t.Fatalf("the registered passkey does not sign its owner in: %v", err)
	}
}
