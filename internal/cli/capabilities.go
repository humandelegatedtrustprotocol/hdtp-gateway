package cli

// Mapped mode: binding PACT's core capabilities to a live upstream (SPEC §6.6,
// §6.7).
//
// `internal/integrations/recipes` was not in the binary's dependency graph at
// all — the reachability gate found it — so the three verified Google Calendar
// recipes §6.7 tabulates could not be read by shipped code. `providers.Calendar`
// and `providers.Status` had no production constructor, and
// `providers.ManagerCaller` none either. Mapped mode existed entirely on paper.
//
// The §6.6 rule this file implements: mapped capabilities are NOT gated by
// `integration.<slug>`. They serve PACT's own vocabulary — `check_availability`,
// `book_slot`, `cancel_booking`, `get_status` — and are gated by the matching
// core permission, which the built-in tool entries already carry. So binding a
// recipe does not add tools; it makes the tools that always existed answer with
// something other than `unavailable`.

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/integrations/providers"
	"github.com/tech-sumit/pact-gateway/internal/integrations/recipes"
	"github.com/tech-sumit/pact-gateway/internal/public"
)

// capabilityBinder answers "which provider serves this account's core
// capabilities right now". It is consulted per call (escalation E5, option B),
// so an integration connected or withheld after startup is reflected without a
// restart.
type capabilityBinder struct {
	store   store.Store
	chain   *integrationChain
	auditFn func(action, resource, outcome string)
	// settings is the DECRYPTING reader: a per-install parameter may be sealed at
	// rest (isSecretKey seals anything whose last segment looks like a
	// credential), and the raw row would then be base64 ciphertext.
	settings func(context.Context) (map[string]string, error)

	mu      sync.RWMutex
	corpus  map[string]integrations.Recipe
	corpErr error
	loaded  bool

	// resolved caches the per-account answer. Resolving walks every integration
	// and reads its exposure set, and `get_status` is a cheap contact-tier call
	// a peer may make sixty times an hour (PACT §12) — so doing that work per
	// call is N+1 queries to usually answer "available". The answer only changes
	// when an exposure, an availability or an integration does, and that already
	// has a hook: invalidate() is called from it.
	cacheMu  sync.RWMutex
	resolved map[string]capSet
	// Now is a clock seam for tests.
	Now func() time.Time
}

func (b *capabilityBinder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// capTTL bounds how stale a cached resolution may be.
//
// The change hook is the fast path and covers every mutation that goes through
// Exposures or the availability cycle. It does NOT cover a mutation made some
// other way — an integration disabled or deleted by a path that does not
// republish, say — and a cache that only a hook can clear turns any such gap
// into "the node keeps serving a capability the owner withdrew". A few seconds
// of staleness is a far smaller thing to be wrong about than that, so the TTL is
// the floor under the hook rather than a substitute for it.
const capTTL = 5 * time.Second

// capSet is one account's resolved providers. A cached entry with both nil is
// meaningful — "this account has no mapped capability" — so presence in the map
// is what distinguishes cached from unknown, not a nil check.
type capSet struct {
	cal public.Calendar
	st  public.StatusSource
	at  time.Time
}

// invalidate drops the cache. It is deliberately account-wide: the hook that
// fires carries an integration id, and mapping that back to an account is
// another query to save a map clear that costs nothing.
func (b *capabilityBinder) invalidate() {
	b.cacheMu.Lock()
	b.resolved = nil
	b.cacheMu.Unlock()
}

// recipeCorpus decodes the embedded recipes once.
func (b *capabilityBinder) recipeCorpus() map[string]integrations.Recipe {
	b.mu.RLock()
	if b.loaded {
		defer b.mu.RUnlock()
		return b.corpus
	}
	b.mu.RUnlock()

	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded {
		b.corpus, b.corpErr = recipes.All()
		b.loaded = true
		if b.corpErr != nil {
			b.auditFn("recipe_corpus", "embedded", "error")
		}
	}
	return b.corpus
}

// forAccount resolves the calendar and status providers for one account.
//
// The FIRST mapped entry naming a recipe wins per capability. Two integrations
// both claiming `book_slot` would otherwise be resolved by map iteration order,
// which is to say arbitrarily and differently on each call.
func (b *capabilityBinder) forAccount(accountID string) (public.Calendar, public.StatusSource) {
	b.cacheMu.RLock()
	hit, ok := b.resolved[accountID]
	b.cacheMu.RUnlock()
	if ok && b.now().Sub(hit.at) < capTTL {
		return hit.cal, hit.st
	}
	cal, st := b.resolve(accountID)
	b.cacheMu.Lock()
	if b.resolved == nil {
		b.resolved = map[string]capSet{}
	}
	b.resolved[accountID] = capSet{cal: cal, st: st, at: b.now()}
	b.cacheMu.Unlock()
	return cal, st
}

// params reads this install's recipe parameters, stored as settings rows named
// `integration.<slug>.<name>` — the same shape adapter settings already use
// (`tunnel.<adapter>.<setting>`), so there is no new storage and no migration.
// A recipe reaches them as `$cfg.<name>`.
func (b *capabilityBinder) params(ctx context.Context, slug string) map[string]string {
	if b.settings == nil {
		return nil
	}
	all, err := b.settings(ctx)
	if err != nil {
		return nil
	}
	prefix := "integration." + slug + "."
	out := map[string]string{}
	for k, v := range all {
		name := strings.TrimPrefix(k, prefix)
		// `env.` under the same prefix is the CHILD's environment, not a recipe
		// parameter. Letting it through would put a credential into an upstream
		// tool argument, where it would be logged as one.
		if name == k || v == "" || strings.HasPrefix(name, stdioEnvPrefix) {
			continue
		}
		out[name] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (b *capabilityBinder) resolve(accountID string) (public.Calendar, public.StatusSource) {
	ctx := context.Background()
	list, err := b.store.ListIntegrations(ctx, accountID)
	if err != nil {
		return nil, nil
	}
	corpus := b.recipeCorpus()

	var cal public.Calendar
	var st public.StatusSource
	for _, in := range list {
		if in.Status == "disabled" || b.chain.Manager.Withheld(in.ID) {
			continue
		}
		entries, err := b.chain.Exposures.ActiveEntries(ctx, in.ID)
		if err != nil {
			continue
		}
		for _, en := range entries {
			if en.Mode != integrations.ModeMapped || en.Recipe == "" {
				continue
			}
			r, ok := corpus[en.Recipe]
			if !ok {
				b.auditFn("recipe_bind", "account:"+in.AccountID+" integration:"+in.Slug+" recipe:"+en.Recipe, "unknown")
				continue
			}
			call := providers.ManagerCaller(b.chain.Manager, in.ID)
			switch en.Tool {
			case "get_status":
				if st == nil {
					st = &providers.Status{Call: call, Recipe: &r}
				}
			default:
				if cal == nil {
					cal = &providers.Calendar{
						Call: call, Recipe: r, Store: b.store, Account: accountID,
						Params: b.params(ctx, in.Slug),
					}
				}
			}
		}
	}
	return cal, st
}
