package settings

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/ingress"
)

// failingStore is the store with its n-th write under `tunnel.<adapter>.` refused.
type failingStore struct {
	store.Store
	writes, failAt int
}

var errInjected = errors.New("injected: the store refused the write")

// Atomically hands fn the transaction wrapped the same way, counting on this store's counter.
func (f *failingStore) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	return f.Store.Atomically(ctx, func(tx store.Store) error {
		inner := &failingStore{Store: tx, writes: f.writes, failAt: f.failAt}
		err := fn(inner)
		f.writes = inner.writes
		return err
	})
}

func (f *failingStore) PutSetting(ctx context.Context, s store.Setting) error {
	if strings.HasPrefix(s.Key, "tunnel.ingress-") {
		f.writes++
		if f.writes == f.failAt {
			return errInjected
		}
	}
	return f.Store.PutSetting(ctx, s)
}

func settingValues(t *testing.T, st store.Store) map[string]string {
	t.Helper()
	rows, err := st.ListSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Key] = r.Value
	}
	return out
}

// A pairing is eight rows under `tunnel.<adapter>.` plus the selection and the public URL, written in
// one transaction. They were written one at a time, so a re-pair that failed part-way left the
// rows already written beside the previous pairing's: a node pinned to one ingress holding another's
// credentials, still selected. A failure on any of the eight leaves every row as it was: nothing
// stored over an empty store, the previous pairing whole over a paired one. The control: every
// write lands, and the adapter is paired, selected and pinned to the new ingress.
func TestAPairingThatFailsOnAnyWriteLeavesEveryRowAsItWas(t *testing.T) {
	ctx := context.Background()
	const adapter = "ingress-terminate"
	before := ingress.PairResponse{IngressFingerprint: "sha256:old-ingress", Domain: "old.test", PublicName: "alice.old.test",
		DataPlaneAddr: "10.0.0.1", DataPlanePort: 7001, DataPlaneToken: "old-dp-token", NodeSecret: "old-node-secret"}
	res := ingress.PairResponse{IngressFingerprint: "sha256:ingress", Domain: "example.test", PublicName: "alice.example.test",
		DataPlaneAddr: "127.0.0.1", DataPlanePort: 7000, DataPlaneToken: "dp-token", NodeSecret: "node-secret"}
	service := func(t *testing.T, failAt int, paired bool) (*Service, store.Store) {
		t.Helper()
		dir := t.TempDir()
		st := openStoreAt(t, dir)
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		cfg := &core.Config{DataDir: dir, PublicURL: "https://old.example", Mode: core.ModeDirect}
		if paired {
			if err := New(st, openKeyringAt(t, dir), cfg, func(string, string, string) {}).storePairing(ctx, adapter, before, "sha256:node"); err != nil {
				t.Fatal(err)
			}
		}
		var writes store.Store = st
		if failAt > 0 {
			writes = &failingStore{Store: st, failAt: failAt}
		}
		return New(writes, openKeyringAt(t, dir), cfg, func(string, string, string) {}), st
	}

	for _, paired := range []bool{false, true} {
		for failAt := 1; failAt <= len(pairingKeys); failAt++ {
			s, st := service(t, failAt, paired)
			was := settingValues(t, st)
			if err := s.storePairing(ctx, adapter, res, "sha256:node"); !errors.Is(err, errInjected) {
				t.Fatalf("write %d: %v, want the injected failure", failAt, err)
			}
			now := settingValues(t, st)
			for k, v := range now {
				if was[k] != v {
					t.Errorf("paired=%v: a pairing whose write %d (%s) failed changed %s", paired, failAt, pairingKeys[failAt-1], k)
				}
			}
			if len(now) != len(was) {
				t.Errorf("paired=%v: a pairing whose write %d failed left %d rows where there were %d", paired, failAt, len(now), len(was))
			}
		}
	}

	s, st := service(t, 0, true)
	if err := s.storePairing(ctx, adapter, res, "sha256:node"); err != nil {
		t.Fatal(err)
	}
	paired, err := s.pairedAdapters(ctx)
	if err != nil || !paired[adapter] {
		t.Fatalf("a completed pairing is not selectable: %v %v", paired, err)
	}
	values := settingValues(t, st)
	if values["tunnel"] != adapter || values["public_url"] != "https://alice.example.test" || values["tunnel."+adapter+".subdomain"] != "alice" {
		t.Errorf("a completed pairing stored tunnel %q, public_url %q, subdomain %q", values["tunnel"], values["public_url"], values["tunnel."+adapter+".subdomain"])
	}
	if PinnedIngress(adapter, values) != "sha256:ingress" {
		t.Errorf("a completed pairing pins %q", PinnedIngress(adapter, values))
	}
}
