package settings

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
)

type rows struct {
	mu   sync.Mutex
	rows []string
}

func (r *rows) fn(action, resource, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, action+" "+resource+" "+outcome)
}

func (r *rows) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rows)
}

// process is one node process on dir's store: its own store handle, config, node, bus and
// settings service, with the bus reader and the settings follower running as serve runs them.
func process(t *testing.T, dir string, migrate bool) (*Service, *node.Node, *rows) {
	t.Helper()
	st := openStoreAt(t, dir)
	if migrate {
		if err := st.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &core.Config{DataDir: dir, PublicURL: "https://old.example", Mode: core.ModeDirect,
		Seal: core.SealOptional, ClientCert: core.ClientCertPreferred, LANConnections: true}
	aud := &rows{}
	s := New(st, openKeyringAt(t, dir), cfg, aud.fn)
	bus := messaging.NewBus(st)
	n, err := node.New(context.Background(), node.Options{Config: *cfg, Store: st, Bus: bus, Audit: aud.fn,
		SealPolicy: s.SealPolicy, Limits: limitstest.StartDefault(t).Client,
		Landing: func(node.LandingDeps) http.Handler { return http.NotFoundHandler() }})
	if err != nil {
		t.Fatal(err)
	}
	s.AttachNode(n)
	s.AttachBus(bus)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { bus.Run(ctx) })
	wg.Go(func() { s.Follow(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return s, n, aud
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s did not happen within 30 s", what)
}

// A setting the owner saves through one node process's portal is applied by every process on the
// store (SPEC §11.1): the seal an account will be built with, the LAN flag and the public URL.
// Only the process that saved them audits them.
func TestASettingSavedOnOneProcessIsAppliedByAnother(t *testing.T) {
	dir := t.TempDir()
	a, _, _ := process(t, dir, true)
	b, nb, bRows := process(t, dir, false)
	ctx := context.Background()

	for _, kv := range [][2]string{{"seal", "required"}, {"lan_connections", "false"}, {"public_url", "https://new.example"}} {
		if err := a.save(ctx, kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "B building accounts under the seal A saved", func() bool { return b.SealPolicy() == core.SealRequired })
	eventually(t, "B's listener taking the LAN flag A saved", func() bool { return !nb.LANAllowed() })
	eventually(t, "B advertising the public URL A saved", func() bool { return nb.PublicURL() == "https://new.example" })
	if n := bRows.count(); n != 0 {
		t.Fatalf("the process that did not save the settings audited %d rows: %v", n, bRows.rows)
	}
}
