package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// rotatingProvider is a token endpoint that rotates refresh tokens, as providers do: each refresh
// token works once, and a second use of one is refused invalid_grant.
type rotatingProvider struct {
	mu        sync.Mutex
	current   string
	n         int
	refreshes int
	refused   int
}

func (p *rotatingProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	time.Sleep(50 * time.Millisecond) // a refresh takes a moment: long enough for another to try
	if r.Form.Get("refresh_token") != p.current {
		p.refused++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	p.refreshes++
	p.n++
	p.current = "rt-" + string(rune('0'+p.n))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at-" + string(rune('0'+p.n)), "token_type": "Bearer",
		"refresh_token": p.current, "expires_in": 3600,
	})
}

// Two node processes sharing a store hold one integration whose token has expired, and each asks
// for it at once (SPEC §6.3, §11.1). Exactly one refreshes it — the provider sees one refresh and
// no reuse of the rotated refresh token — and both serve the token that refresh sealed. Refreshing
// in each process spent the refresh token twice, and the provider refused the second: the
// integration then needed its owner to sign in again.
func TestAnExpiredTokenIsRefreshedByOneProcessAndServedByAll(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shared.db")
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	open := func() *store.SQLite {
		st, err := store.OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}
	a, b := open(), open()
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := a.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := a.InsertIntegration(ctx, store.Integration{AccountID: acct.ID, Slug: "cal", Transport: "streamable-http",
		Endpoint: "https://cal.example/mcp", AuthKind: "oauth"})
	if err != nil {
		t.Fatal(err)
	}
	provider := &rotatingProvider{current: "rt-0"}
	srv := httptest.NewServer(provider)
	defer srv.Close()
	oc := &oauth2.Config{ClientID: "node", Endpoint: oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInParams}}
	expired := &oauth2.Token{AccessToken: "at-0", RefreshToken: "rt-0", TokenType: "Bearer", Expiry: time.Now().Add(-time.Minute)}
	if err := SealOAuth(a, kr, in.ID, expired, oc); err != nil {
		t.Fatal(err)
	}

	sources := []*persistingSource{
		OAuthSetup{Store: a, Keyring: kr, Leases: a, Holder: "process-a"}.source(ctx, in.ID, oc),
		OAuthSetup{Store: b, Keyring: kr, Leases: b, Holder: "process-b"}.source(ctx, in.ID, oc),
	}
	tokens := make([]*oauth2.Token, len(sources))
	errs := make([]error, len(sources))
	var wg sync.WaitGroup
	for i, s := range sources {
		wg.Go(func() { tokens[i], errs[i] = s.Token() })
	}
	wg.Wait()
	for i := range sources {
		if errs[i] != nil {
			t.Fatalf("process %d: %v", i, errs[i])
		}
	}
	provider.mu.Lock()
	refreshes, refused := provider.refreshes, provider.refused
	provider.mu.Unlock()
	if refreshes != 1 || refused != 0 {
		t.Fatalf("the provider saw %d refreshes and %d reuses of a spent refresh token; want one and none", refreshes, refused)
	}
	if tokens[0].AccessToken != "at-1" || tokens[1].AccessToken != "at-1" {
		t.Fatalf("the processes served %q and %q; want the one refreshed token", tokens[0].AccessToken, tokens[1].AccessToken)
	}
	// And the store holds it, with the rotated refresh token, for the next process that asks.
	if tok, err := sources[1].stored(); err != nil || tok.RefreshToken != "rt-1" {
		t.Fatalf("the store holds %+v (%v)", tok, err)
	}

	// A process that read the token expired, and takes the lease only after another refreshed and
	// let go, reads the token again under the lease and serves it, spending nothing.
	late := OAuthSetup{Store: b, Keyring: kr, Leases: b, Holder: "process-late"}.source(ctx, in.ID, oc)
	tok, err := late.refresh("oauth-refresh:" + in.ID)
	provider.mu.Lock()
	refreshes, refused = provider.refreshes, provider.refused
	provider.mu.Unlock()
	if err != nil || tok.AccessToken != "at-1" || refreshes != 1 || refused != 0 {
		t.Fatalf("a late lease holder served %v (%v) after %d refreshes and %d refusals; want at-1, one and none", tok, err, refreshes, refused)
	}
}
