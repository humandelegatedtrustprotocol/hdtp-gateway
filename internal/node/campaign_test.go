package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
)

// gatedLedger holds the walk's ledger write until released, and holds a progress read between its
// ledger read and whatever MoveProgress reads next.
type gatedLedger struct {
	store.Store
	upserting chan struct{}
	upsert    chan struct{}
	listed    chan struct{}
	list      chan struct{}
	armed     chan struct{}
	upserted  sync.Once
	held      sync.Once
}

func (g *gatedLedger) UpsertMoveFanout(ctx context.Context, f store.MoveFanout) error {
	g.upserted.Do(func() { close(g.upserting); <-g.upsert })
	return g.Store.UpsertMoveFanout(ctx, f)
}

func (g *gatedLedger) ListMoveFanout(ctx context.Context, accountID string) ([]store.MoveFanout, error) {
	rows, err := g.Store.ListMoveFanout(ctx, accountID)
	select {
	case <-g.armed:
		g.held.Do(func() { close(g.listed); <-g.list })
	default:
	}
	return rows, err
}

// A walk that writes its last row and ends while MoveProgress is reading must not be reported as
// ended over a ledger that lacks that row: whoever polls for the end reads the ledger as final.
func TestMoveProgressNeverReportsAnEndedWalkOverAnUnfinishedLedger(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	mover := startDemoNode(t, clock, dn, "mover", "Mover", 365)
	near := startDemoNode(t, clock, dn, "near", "Near", 365)
	mover.pinPeer(near)
	near.pinPeer(mover)

	mover.n.SetPublicURL("https://mover-new.test")
	dn.set("mover-new.test", dn.hosts[mover.host])
	mv := mover.install(identity.PurposeMove, identity.EndpointFor("https://mover-new.test", mover.slug), 365, clock.now())
	if !mv.Moved {
		t.Fatalf("the install did not count as a move: %+v", mv)
	}
	mover.host = "mover-new.test"

	g := &gatedLedger{Store: mover.n.idm.Store, upserting: make(chan struct{}), upsert: make(chan struct{}),
		listed: make(chan struct{}), list: make(chan struct{}), armed: make(chan struct{})}
	mover.n.idm.Store = g
	if !mover.n.ResumeMove(ctx, mover.acct.ID, mv.Kid) {
		t.Fatal("the campaign did not start")
	}
	<-g.upserting
	close(g.armed)
	type read struct {
		p   MoveProgress
		err error
	}
	got := make(chan read, 1)
	go func() {
		p, err := mover.n.MoveProgress(ctx, mover.acct.ID, mv.Kid)
		got <- read{p, err}
	}()
	<-g.listed
	close(g.upsert)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, walking := mover.n.campaigns.Load(mover.acct.ID); !walking {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the walk never ended")
		}
		time.Sleep(time.Millisecond)
	}
	close(g.list)
	r := <-got
	if r.err != nil {
		t.Fatal(r.err)
	}
	if !r.p.Walking && r.p.Told != 1 {
		t.Fatalf("the walk is reported ended over a ledger without its last row: %+v", r.p)
	}
	if p, err := mover.n.MoveProgress(ctx, mover.acct.ID, mv.Kid); err != nil || p.Walking || p.Told != 1 || p.Waiting != 0 {
		t.Fatalf("after the walk: %+v (%v), want it ended with the contact told", p, err)
	}
}
