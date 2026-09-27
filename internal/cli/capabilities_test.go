package cli

import (
	"context"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/services/integrationchain"
)

// AC (P10-04e): the embedded recipe corpus is readable by shipped code, and a
// mapped exposure binds a live provider to the account's core capabilities.
//
// internal/integrations/recipes was not in the binary's dependency graph at all,
// and providers.Calendar/Status/ManagerCaller had no production constructors —
// so the three verified Google Calendar recipes SPEC §6.7 tabulates existed only
// on paper.
func TestMappedExposureBindsACoreCapability(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	chain := integrationchain.Build(st, nil, nil, "", func(string, string, string) {}, nil, nil, nil)
	b := &capabilityBinder{store: st, chain: chain, auditFn: func(string, string, string) {}}

	// The corpus must actually decode, from the binary.
	corpus := b.recipeCorpus()
	if b.corpErr != nil {
		t.Fatalf("the embedded recipes do not decode: %v", b.corpErr)
	}
	if len(corpus) == 0 {
		t.Fatal("no recipes are embedded — mapped mode has nothing to bind")
	}
	var recipeName string
	for n, r := range corpus {
		if _, ok := r.Capabilities["check_availability"]; ok {
			recipeName = n
			break
		}
	}
	if recipeName == "" {
		t.Fatalf("no embedded recipe binds check_availability: %v", keysOf(corpus))
	}

	acct, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	// resolve, not forAccount: this test is about what resolution FINDS, and
	// forAccount caches — mixing the two would make it a cache test that looks
	// like a binding test, which is how a stale answer hides.
	if cal, _ := b.resolve(acct.ID); cal != nil {
		t.Fatal("a calendar appeared with no integration configured")
	}

	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "gcal", Transport: "streamable-http",
		Endpoint: "https://upstream.invalid", AuthKind: "none", Status: "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertCatalog(ctx, store.Catalog{
		IntegrationID: in.ID, Version: 1,
		Tools: `[{"name":"freebusy","description":"","hash":"h1"}]`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertExposure(ctx, store.Exposure{
		IntegrationID: in.ID, Version: 1, CatalogVersion: 1,
		Entries: `[{"tool":"check_availability","mode":"mapped","exposed_name":"check_availability",` +
			`"recipe":"` + recipeName + `","confirmed_hash":"h1"}]`,
	}); err != nil {
		t.Fatal(err)
	}

	cal, _ := b.resolve(acct.ID)
	if cal == nil {
		t.Fatal("a mapped exposure did not bind a calendar provider")
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// AC (P11-04): resolving an account's capabilities is cached, and the cache is
// dropped when the exposure state changes.
//
// `get_status` is a contact-tier call a peer may make sixty times an hour, and
// resolving walked every integration and read its exposure set — N+1 queries to
// usually answer "available". Correctness is the harder half: a cache that does
// not drop would keep answering with an integration the owner has withdrawn.
func TestCapabilityResolutionIsCachedAndInvalidated(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := &countingStore{Store: migrated(t, dir)}
	defer st.Close()

	chain := integrationchain.Build(st, nil, nil, "", func(string, string, string) {}, nil, nil, nil)
	clock := time.Unix(1756000000, 0)
	b := &capabilityBinder{store: st, chain: chain, auditFn: func(string, string, string) {},
		Now: func() time.Time { return clock }}

	acct, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}

	st.n = 0
	for i := 0; i < 5; i++ {
		b.forAccount(acct.ID)
	}
	if st.n != 1 {
		t.Fatalf("five resolutions cost %d ListIntegrations queries, want 1", st.n)
	}

	// An exposure change must drop it, or a withdrawn integration keeps serving.
	b.invalidate()
	st.n = 0
	b.forAccount(acct.ID)
	if st.n != 1 {
		t.Fatalf("after invalidation the resolution was not redone (%d queries)", st.n)
	}

	// An account with NO mapped capability is a real answer, not a cache miss:
	// caching it is the whole point, so it must not re-resolve every call.
	st.n = 0
	for i := 0; i < 3; i++ {
		if cal, _ := b.forAccount(acct.ID); cal != nil {
			t.Fatal("a calendar appeared with no integration configured")
		}
	}
	if st.n != 0 {
		t.Fatalf("a cached empty answer re-resolved %d times", st.n)
	}

	// The TTL is the floor under the hook: a mutation made some other way must
	// not keep the node serving a capability the owner withdrew forever.
	clock = clock.Add(capTTL + time.Second)
	st.n = 0
	b.forAccount(acct.ID)
	if st.n != 1 {
		t.Fatalf("the cache outlived its TTL (%d queries)", st.n)
	}
}

// countingStore counts the query the resolver makes first.
type countingStore struct {
	store.Store
	n int
}

func (c *countingStore) ListIntegrations(ctx context.Context, accountID string) ([]store.Integration, error) {
	c.n++
	return c.Store.ListIntegrations(ctx, accountID)
}
