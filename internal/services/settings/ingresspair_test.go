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

// A pairing is eight rows under `tunnel.<adapter>.` written one at a time, with no transaction over
// them, so their order is the invariant: `subdomain`, the marker pairedAdapters reads, comes last.
// It was written seventh, before `ingress_fpr`, so a failure on the eighth write left an adapter
// that was selectable and would pin no ingress on the onward leg, while the comment beside the
// writes said subdomain was last. A failure on any of the eight leaves no selectable adapter and
// nothing selected; the way out of what it left is unpair, which deletes every row a pairing
// writes. The control: every write lands, and the adapter is paired, selected and pinned.
func TestAPairingThatFailsOnAnyWriteLeavesNoSelectableAdapter(t *testing.T) {
	ctx := context.Background()
	const adapter = "ingress-terminate"
	res := ingress.PairResponse{IngressFingerprint: "sha256:ingress", Domain: "example.test", PublicName: "alice.example.test",
		DataPlaneAddr: "127.0.0.1", DataPlanePort: 7000, DataPlaneToken: "dp-token", NodeSecret: "node-secret"}
	service := func(t *testing.T, failAt int) (*Service, store.Store) {
		t.Helper()
		dir := t.TempDir()
		st := openStoreAt(t, dir)
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		var writes store.Store = st
		if failAt > 0 {
			writes = &failingStore{Store: st, failAt: failAt}
		}
		cfg := &core.Config{DataDir: dir, PublicURL: "https://old.example", Mode: core.ModeDirect}
		return New(writes, openKeyringAt(t, dir), cfg, func(string, string, string) {}), st
	}

	for failAt := 1; failAt <= len(pairingKeys); failAt++ {
		s, st := service(t, failAt)
		if err := s.storePairing(ctx, adapter, res, "sha256:node"); !errors.Is(err, errInjected) {
			t.Fatalf("write %d: %v, want the injected failure", failAt, err)
		}
		paired, err := s.pairedAdapters(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if paired[adapter] {
			t.Errorf("a pairing whose write %d (%s) failed is selectable", failAt, pairingKeys[failAt-1])
		}
		if sel := settingValues(t, st)["tunnel"]; sel != "" {
			t.Errorf("a pairing whose write %d failed selected %q", failAt, sel)
		}
		if err := s.unpair(ctx, adapter); err != nil {
			t.Fatalf("unpair after a failed write %d: %v", failAt, err)
		}
		for k := range settingValues(t, st) {
			if strings.HasPrefix(k, "tunnel."+adapter+".") {
				t.Errorf("unpair left %s behind after a failed write %d", k, failAt)
			}
		}
	}

	s, st := service(t, 0)
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
