package settings

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/ingress"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

type accountsFail struct{ store.Store }

func (accountsFail) ListAccounts(context.Context) ([]store.Account, error) {
	return nil, errors.New("pq: relation contacts_canary_7f3a does not exist")
}

// A pairing whose account list could not be read is a failure of the node, internal, not "create
// an account before pairing": a store that failed has not said there are no accounts. The control,
// a node with no account, is told to create one.
func TestAPairingWhoseAccountsCannotBeReadIsAFailure(t *testing.T) {
	svc, st := presetSvc(t)
	in := internalui.PairInput{PairURL: "https://ingress.example/pair", Token: "t", Subdomain: "me"}
	svc.store = accountsFail{st}
	_, err := svc.Deps().Pair(context.Background(), in)
	if code, detail := refusal.Of(err); code != "internal" || detail != refusal.InternalDetail {
		t.Errorf("an account list that failed: %v → %s %q", err, code, detail)
	}
	svc.store = st
	_, err = svc.Deps().Pair(context.Background(), in)
	if code, s := refusal.Of(err); code != "bad_request" || s != "create an account before pairing" {
		t.Errorf("the control, no account: %v", err)
	}
}

// A pairing or an unpairing the target's state or holdings refuse answers the code of that truth,
// not bad_request: an account the caller named that the node does not hold is not_found, a node
// not serving yet and the selected tunnel are conflict. Each keeps its sentence. The control, an
// unpairing of an adapter that is not selected, gets through.
func TestPairAndUnpairRefusalsAnswerTheTargetsCode(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alice", DisplayName: "Alice", Algo: "ed25519"}); err != nil {
		t.Fatal(err)
	}
	cfg := &core.Config{DataDir: dir, Tunnel: "ingress-terminate"}
	svc := New(st, openKeyringAt(t, dir), cfg, func(string, string, string) {})
	in := internalui.PairInput{PairURL: "https://ingress.example/pair", Token: "t", Subdomain: "me"}

	named := in
	named.Account = "nosuch"
	_, err := svc.Deps().Pair(ctx, named)
	if code, s := refusal.Of(err); code != "not_found" || s != "unknown account" {
		t.Errorf("an account the node does not hold: %v → %s %q", err, code, s)
	}
	_, err = svc.Deps().Pair(ctx, in)
	if code, s := refusal.Of(err); code != "conflict" || s != "the node is not serving yet" {
		t.Errorf("a node not serving yet: %v → %s %q", err, code, s)
	}
	err = svc.Deps().Unpair(ctx, "ingress-terminate")
	if code, s := refusal.Of(err); code != "conflict" || !strings.HasPrefix(s, "ingress-terminate is the selected tunnel") {
		t.Errorf("the running selection: %v → %s %q", err, code, s)
	}
	if err := st.PutSetting(ctx, store.Setting{Key: "tunnel", Value: "ingress-passthrough"}); err != nil {
		t.Fatal(err)
	}
	err = svc.Deps().Unpair(ctx, "ingress-passthrough")
	if code, s := refusal.Of(err); code != "conflict" || !strings.HasPrefix(s, "ingress-passthrough is the selected tunnel") {
		t.Errorf("the stored selection: %v → %s %q", err, code, s)
	}
	if err := st.PutSetting(ctx, store.Setting{Key: "tunnel", Value: "ingress-terminate"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Deps().Unpair(ctx, "ingress-passthrough"); err != nil {
		t.Errorf("the control, an adapter not selected: %v", err)
	}
}

// selfSignedCert is a fresh P-256 identity's self-signed certificate.
func selfSignedCert(t *testing.T, cn string) (*identity.Keypair, tls.Certificate) {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := identity.SelfSignedCert(kp, cn)
	if err != nil {
		t.Fatal(err)
	}
	return kp, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
}

// A pairing the ingress refused answers the code the ingress answered, with the node's own
// sentence, where every one was bad_request "the ingress did not pair this node": a spent token,
// a taken subdomain, a node without a certificate, a malformed subdomain and an ingress that could
// not record the pairing each read the ingress's real answer (ingress.PairingServer, over TLS);
// an answer that is not an ingress's (a wrong path), a served certificate that is not the one
// pinned and an ingress not reached are told as what they are. No sentence carries the ingress's
// body or the dial's error.
func TestAPairingTheIngressRefusedAnswersTheIngresssCode(t *testing.T) {
	book := filepath.Join(t.TempDir(), "book")
	if err := os.Mkdir(book, 0o700); err != nil {
		t.Fatal(err)
	}
	reg, err := ingress.NewFileRegistry(filepath.Join(book, "nodes.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ingKP, ingCert := selfSignedCert(t, "ingress")
	ps := &ingress.PairingServer{Registry: reg, Domain: "example.test", IngressFingerprint: ingKP.Fingerprint,
		DataPlaneAddr: "127.0.0.1", DataPlanePort: 7000, DataPlaneToken: "dp"}
	srv := httptest.NewUnstartedServer(ps.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ingCert}, ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, mine := selfSignedCert(t, "node")
	_, theirs := selfSignedCert(t, "other")
	mint := func() string {
		tok, err := reg.MintToken(time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	pair := func(url string, cert tls.Certificate, pin, token, sub string) error {
		_, _, err := ingress.Pair(nil, url, cert, pin, ingress.PairRequest{Token: token, Subdomain: sub, Mode: ingress.ModePassthrough})
		if err == nil {
			t.Fatalf("pairing %s at %s got through", sub, url)
		}
		return err
	}
	spent := mint()
	if _, _, err := ingress.Pair(nil, srv.URL+"/pair", mine, "", ingress.PairRequest{Token: spent, Subdomain: "taken", Mode: ingress.ModePassthrough}); err != nil {
		t.Fatal(err)
	}
	// an ingress whose refusal is plain text, not a JSON code
	plain := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "subdomain taken", http.StatusConflict)
	}))
	defer plain.Close()
	gone := httptest.NewTLSServer(http.NotFoundHandler())
	goneURL := gone.URL + "/pair"
	gone.Close()

	unwritable := func() error {
		if err := os.Chmod(book, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(book, 0o700) }()
		return pair(srv.URL+"/pair", mine, "", mint(), "fresh")
	}
	cases := []struct {
		name      string
		err       error
		code, why string
	}{
		{"a spent token", pair(srv.URL+"/pair", mine, "", spent, "again"), "bad_request", "the pairing token is unknown, used or expired"},
		{"a taken subdomain", pair(srv.URL+"/pair", theirs, "", mint(), "taken"), "conflict", "that subdomain is paired to another node"},
		{"no certificate", pair(srv.URL+"/pair", tls.Certificate{}, "", mint(), "nocert"), "bad_request", "the ingress did not accept this node's certificate"},
		{"a malformed subdomain", pair(srv.URL+"/pair", mine, "", mint(), "Not_A_Label"), "bad_request",
			"the ingress refused the subdomain or the mode: a subdomain is one DNS label of lowercase letters, digits and hyphens, and the mode passthrough or terminate"},
		{"an ingress that could not record it", unwritable(), "unavailable", "the ingress could not record the pairing; try again with a new token"},
		{"not an ingress's answer", pair(srv.URL+"/elsewhere", mine, "", mint(), "lost"), "bad_request", "the pairing URL answered HTTP 404 without a code this node reads"},
		{"a refusal in plain text", pair(plain.URL+"/pair", mine, "", "pair_x", "plain"), "bad_request", "the pairing URL answered HTTP 409 without a code this node reads"},
		{"another ingress's certificate", pair(srv.URL+"/pair", mine, "sha256:not-this-ingress", mint(), "pinned"), "bad_request", "the ingress served a certificate whose fingerprint is not the one given"},
		{"an ingress not reached", pair(goneURL, mine, "", "pair_x", "dark"), "unavailable", "the ingress could not be reached"},
	}
	for _, c := range cases {
		if code, why := refusal.Of(pairRefusal(c.err)); code != c.code || why != c.why {
			t.Errorf("%s: %v → %s %q, want %s %q", c.name, c.err, code, why, c.code, c.why)
		}
	}
}

type settingsListFail struct{ store.Store }

func (settingsListFail) ListSettings(context.Context) ([]store.Setting, error) {
	return nil, errors.New("pq: relation settings_canary_5c1e does not exist")
}

// An unpairing whose stored selection could not be read is a failure of the node, and deletes
// nothing: the failed read was taken for "not selected", so the pairing the next start would boot
// with was deleted. The control, the same unpairing on a store that answers, gets through.
func TestAnUnpairingThatCannotReadTheSelectionDeletesNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, k := range pairingKeys {
		if err := st.PutSetting(ctx, store.Setting{Key: "tunnel.ingress-passthrough." + k, Value: "v"}); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(settingsListFail{st}, openKeyringAt(t, dir), &core.Config{DataDir: dir, Tunnel: "cloudflare"}, func(string, string, string) {})
	err := svc.Deps().Unpair(ctx, "ingress-passthrough")
	if code, detail := refusal.Of(err); code != "internal" || detail != refusal.InternalDetail {
		t.Errorf("a selection that could not be read: %v → %s %q", err, code, detail)
	}
	if n := len(settingValues(t, st)); n != len(pairingKeys) {
		t.Errorf("an unpairing that could not read the selection left %d of %d rows", n, len(pairingKeys))
	}
	svc.store = st
	if err := svc.Deps().Unpair(ctx, "ingress-passthrough"); err != nil {
		t.Errorf("the control: %v", err)
	}
}
