package settings

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/ingress"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// accountsFailOnce is the store with its ListAccounts call numbered call (from 1) refused: what an
// apply reads, the seal's to re-seal every account and the public URL's to name the accounts that
// need a move. fired says whether the refusal happened.
type accountsFailOnce struct {
	store.Store
	call  int
	mu    sync.Mutex
	calls int
	fired bool
}

func (f *accountsFailOnce) ListAccounts(ctx context.Context) ([]store.Account, error) {
	f.mu.Lock()
	f.calls++
	refuse := f.calls == f.call
	if refuse {
		f.fired = true
	}
	f.mu.Unlock()
	if refuse {
		return nil, errors.New("injected: the store refused the read")
	}
	return f.Store.ListAccounts(ctx)
}

// A save whose first knob cannot be applied to the running node still applies the second and
// announces both, since both are stored; the portal says what was saved and what was not applied,
// and audits the write ok beside the failed apply.
func TestAKnobThatCannotBeAppliedLeavesTheOthersApplied(t *testing.T) {
	dir := t.TempDir()
	a, _, aRows, bus := processOver(t, dir, true, func(st store.Store) store.Store { return &accountsFailOnce{Store: st, call: 1} })
	b, _, _ := process(t, dir, false)
	events, unsubscribe := bus.SubscribeSized("", 64)
	defer unsubscribe()

	mux := http.NewServeMux()
	internalui.MountSettingsPages(mux, a.Deps())
	form := url.Values{"seal": {"required"}, "limit.contacts": {"7"}}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var page struct {
		Notice string `json:"notice"`
		Error  bool   `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
	}
	if want := "Saved seal, limit.contacts; could not apply seal: the node could not complete this."; page.Notice != want || !page.Error {
		t.Errorf("notice %q (error %v), want %q (error true)", page.Notice, page.Error, want)
	}
	aRows.mu.Lock()
	audited := slices.Clone(aRows.rows)
	aRows.mu.Unlock()
	for _, want := range []string{"settings_save keys:seal,limit.contacts ok", "settings_apply keys:seal error"} {
		if !slices.Contains(audited, want) {
			t.Errorf("audit %v has no %q", audited, want)
		}
	}
	if slices.Contains(audited, "settings_save keys:seal,limit.contacts error") {
		t.Errorf("audit %v says the stored save failed", audited)
	}
	if now := settingValues(t, a.store); now["seal"] != "required" || now["limit.contacts"] != "7" {
		t.Errorf("stored %v, want both", now)
	}
	if n := a.ContactCap(); n != 7 {
		t.Errorf("the saving process's contact cap is %d: it did not apply limit.contacts, saved after the seal it could not apply", n)
	}
	published := map[string]bool{}
	eventually(t, "both stored keys announced", func() bool {
		for {
			select {
			case e := <-events:
				if e.Kind == messaging.EventSettings {
					published[e.Ref] = true
				}
				continue
			default:
			}
			return published["seal"] && published["limit.contacts"]
		}
	})
	eventually(t, "the other process taking limit.contacts", func() bool { return b.ContactCap() == 7 })
}

// A pairing the ingress completed is stored, selected and its token spent even when the running node
// cannot take the new public URL: the portal says it paired and what was not applied, with error set
// and 200, and audits the pairing beside the failed apply. It said "pairing refused" over the stored
// rows, with no pairing audited. The second ListAccounts of the post is the public URL's apply (the
// first is Pair's own account list); the wrapper records that its refusal fired.
func TestAPairingWhosePublicURLCannotBeAppliedIsStillPaired(t *testing.T) {
	ctx := context.Background()
	ingKP, ingCert := selfSignedCert(t, "ingress")
	reg := ingress.NewMemoryRegistry(nil)
	ps := &ingress.PairingServer{Registry: reg, Domain: "example.test", IngressFingerprint: ingKP.Fingerprint,
		DataPlaneAddr: "127.0.0.1", DataPlanePort: 7000, DataPlaneToken: "dp-token"}
	srv := httptest.NewUnstartedServer(ps.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ingCert}, ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	token, err := reg.MintToken(time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// The node serves the account only with a leaf, and the ingress pairs only a node that presents one.
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	alice, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	csr, err := idm.IssueCSR(ctx, alice.ID, identity.PurposeSignup, identity.EndpointFor("https://old.example", "alice"), now)
	if err != nil {
		t.Fatal(err)
	}
	w := testid.NewWallet(t, "Alice")
	iss, err := hdtpidentity.IssueFromCSR(csr.CSR, hdtpidentity.IssueOpts{Root: testid.Root(t, w.RootDER), RootKey: w.Key,
		RootSPKIs: [][]byte{w.Key.Public().SPKI}, Now: now, PreviousNotBefore: csr.PreviousNotBefore, ValidDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idm.InstallLeaf(ctx, alice.ID, [][]byte{iss.DER, w.RootDER}, now); err != nil {
		t.Fatal(err)
	}

	var accounts *accountsFailOnce
	a, _, aRows, _ := processOver(t, dir, false, func(st store.Store) store.Store {
		accounts = &accountsFailOnce{Store: st, call: 2}
		return accounts
	})
	mux := http.NewServeMux()
	internalui.MountSettingsPages(mux, a.Deps())
	form := url.Values{"pair_url": {srv.URL + "/pair"}, "token": {token}, "subdomain": {"alice"},
		"mode": {"passthrough"}, "ingress_fingerprint": {ingKP.Fingerprint}, "account": {alice.ID}}
	req := httptest.NewRequest(http.MethodPost, "/settings/pair", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	accounts.mu.Lock()
	fired := accounts.fired
	accounts.mu.Unlock()
	if !fired {
		t.Fatal("the injected ListAccounts refusal never fired: the public URL's apply was not reached")
	}
	var page struct {
		Notice string `json:"notice"`
		Error  bool   `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
	}
	want := "Paired as alice.example.test over ingress-passthrough; could not apply public_url: " +
		"the node could not complete this. Restart the node to serve there."
	if rec.Code != http.StatusOK || page.Notice != want || !page.Error {
		t.Errorf("%d notice %q (error %v), want 200 %q (error true)", rec.Code, page.Notice, page.Error, want)
	}
	if strings.Contains(page.Notice, "pairing refused") {
		t.Errorf("a stored pairing was told as refused: %q", page.Notice)
	}
	values := settingValues(t, st)
	if values["tunnel"] != "ingress-passthrough" || values["public_url"] != "https://alice.example.test" ||
		values["tunnel.ingress-passthrough.subdomain"] != "alice" || values["tunnel.ingress-passthrough.ingress_fpr"] != ingKP.Fingerprint {
		t.Errorf("stored tunnel %q, public_url %q, subdomain %q, ingress_fpr %q", values["tunnel"], values["public_url"],
			values["tunnel.ingress-passthrough.subdomain"], values["tunnel.ingress-passthrough.ingress_fpr"])
	}
	aRows.mu.Lock()
	audited := slices.Clone(aRows.rows)
	aRows.mu.Unlock()
	for _, want := range []string{"ingress_pair ingress:" + ingKP.Fingerprint + " name:alice.example.test paired",
		"settings_apply keys:public_url error"} {
		if !slices.Contains(audited, want) {
			t.Errorf("audit %v has no %q", audited, want)
		}
	}
}

// awaitingFirst is the store with the accounts that have no leaf listed first, so the seal's apply
// meets the one the node does not serve before the one it does.
type awaitingFirst struct{ store.Store }

func (s awaitingFirst) ListAccounts(ctx context.Context) ([]store.Account, error) {
	accts, err := s.Store.ListAccounts(ctx)
	slices.SortStableFunc(accts, func(a, b store.Account) int {
		switch {
		case !a.HasRoot() && b.HasRoot():
			return -1
		case a.HasRoot() && !b.HasRoot():
			return 1
		}
		return 0
	})
	return accts, err
}

// certify gives an account a leaf from a test wallet, as `account install-leaf` does.
func certify(t *testing.T, idm *identity.Manager, acct store.Account) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	csr, err := idm.IssueCSR(ctx, acct.ID, identity.PurposeSignup, identity.EndpointFor("https://old.example", acct.Slug), now)
	if err != nil {
		t.Fatal(err)
	}
	w := testid.NewWallet(t, acct.DisplayName)
	iss, err := hdtpidentity.IssueFromCSR(csr.CSR, hdtpidentity.IssueOpts{Root: testid.Root(t, w.RootDER), RootKey: w.Key,
		RootSPKIs: [][]byte{w.Key.Public().SPKI}, Now: now, PreviousNotBefore: csr.PreviousNotBefore, ValidDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idm.InstallLeaf(ctx, acct.ID, [][]byte{iss.DER, w.RootDER}, now); err != nil {
		t.Fatal(err)
	}
}

// #226: on a node holding an identity that awaits its wallet's leaf — the quickstart's state between
// `account create` and `account install-leaf` — saving Settings answered "could not apply seal: the
// node could not complete this", on every save, since the form posts every knob. The seal's apply
// stopped at the account the node does not serve, so a served account listed after it kept its old
// seal at the gate. Now the served account takes the seal at once, the waiting one's row holds it
// and it serves under it once certified, and each is audited once.
func TestASaveBesideAnAccountAwaitingItsLeafAppliesTheSeal(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	alice, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	certify(t, idm, alice)
	bob, err := idm.CreateAccount(ctx, "bob", "Bob", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}

	a, n, aRows, _ := processOver(t, dir, false, func(st store.Store) store.Store { return awaitingFirst{st} })
	if got := n.AwaitingLeaf(); len(got) != 1 || got[0] != "bob" {
		t.Fatalf("awaiting %v, want [bob]", got)
	}
	mux := http.NewServeMux()
	internalui.MountSettingsPages(mux, a.Deps())
	form := url.Values{"seal": {"none"}, "limit.contacts": {"7"}}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var page struct {
		Notice string `json:"notice"`
		Error  bool   `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
	}
	if want := "Saved seal, limit.contacts."; page.Notice != want || page.Error {
		t.Errorf("notice %q (error %v), want %q (error false)", page.Notice, page.Error, want)
	}
	if card, err := n.Card(ctx, alice.ID); err != nil || !strings.Contains(card, "X-HDTP-SEAL:none") {
		t.Errorf("the served identity's card after the save: %v\n%s", err, card)
	}
	if row, err := st.GetAccountByID(ctx, bob.ID); err != nil || row.Seal != "none" {
		t.Errorf("the waiting identity's row: seal %q, %v; want none", row.Seal, err)
	}
	aRows.mu.Lock()
	audited := slices.Clone(aRows.rows)
	aRows.mu.Unlock()
	for _, want := range []string{"settings_save keys:seal,limit.contacts ok", "settings_seal account:" + alice.ID + " none",
		"settings_seal account:" + bob.ID + " not_served none"} {
		if got := slices.Index(audited, want); got < 0 || slices.Index(audited[got+1:], want) >= 0 {
			t.Errorf("audit %v has %q other than once", audited, want)
		}
	}
	for _, row := range audited {
		if strings.HasPrefix(row, "settings_apply") {
			t.Errorf("audit %v says the save was not applied", audited)
		}
	}

	certify(t, idm, bob)
	if err := n.AdoptAccount(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if card, err := n.Card(ctx, bob.ID); err != nil || !strings.Contains(card, "X-HDTP-SEAL:none") {
		t.Errorf("the identity certified after the save: %v\n%s", err, card)
	}
}
