package node

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	toxiproxy "github.com/Shopify/toxiproxy/v2"
	"github.com/rs/zerolog"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// The move campaign under a network partition (PACT §5.3, §9): one contact reachable, one cut off
// while the walk runs. The fault is injected with Toxiproxy, in process, between the mover and the
// contact it cannot reach — a `timeout` toxic, which passes the TCP connection and then lets no
// data through, as a link that drops packets does. The container harness covers the same ground
// with `tc netem` against a real image (harness/scenario/move_live_test.go); this is the tier that
// runs in `make check`.
//
// What must hold: the reachable contact is told and follows; the unreachable one is recorded as
// waiting with what went wrong; nothing the caller does waits for the walk; a second walk cannot
// start beside the first; and after the link heals a resume tells ONLY the contact that was
// missed, and the ledger says everyone has been told.
func TestAMoveCampaignSurvivesAPartitionAndResumes(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	mover := startDemoNode(t, clock, dn, "mover", "Mover", 365)
	near := startDemoNode(t, clock, dn, "near", "Near", 365)
	far := startDemoNode(t, clock, dn, "far", "Far", 365)
	for _, contact := range []*demoNode{near, far} {
		mover.pin20(contact)
		contact.pin20(mover)
	}

	// `far` is reached through the proxy from here on.
	srv := toxiproxy.NewServer(toxiproxy.NewMetricsContainer(nil), zerolog.Nop())
	link := toxiproxy.NewProxy(srv, "mover-to-far", "127.0.0.1:0", dn.hosts[far.host])
	if err := link.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(link.Stop)
	dn.set(far.host, link.Listen)

	// The partition. Both directions, so neither the request nor anything of an answer passes;
	// the proxy gives the connection up after a second and a half, which keeps this test short —
	// on a real link it is the caller that gives up, many seconds later.
	for _, stream := range []string{"upstream", "downstream"} {
		toxic := fmt.Sprintf(`{"name":"cut-%s","type":"timeout","stream":"%s","attributes":{"timeout":1500}}`, stream, stream)
		if _, err := link.Toxics.AddToxicJson(strings.NewReader(toxic)); err != nil {
			t.Fatal(err)
		}
	}

	// The move: the wallet issues a leaf for a new address, and the node installs it.
	mover.n.SetPublicURL("https://mover-new.test")
	dn.set("mover-new.test", dn.hosts[mover.host])
	newEndpoint := identity.EndpointFor("https://mover-new.test", mover.slug)
	mv := mover.install(identity.PurposeMove, newEndpoint, 365, clock.now())
	if !mv.Moved {
		t.Fatalf("the install did not count as a move: %+v", mv)
	}
	mover.host = "mover-new.test"

	started := time.Now()
	if !mover.n.ResumeMove(ctx, mover.acct.ID, mv.Kid) {
		t.Fatal("the campaign did not start")
	}
	if waited := time.Since(started); waited > 500*time.Millisecond {
		t.Fatalf("starting the campaign took %v: a caller must not wait for the walk", waited)
	}
	if mover.n.ResumeMove(ctx, mover.acct.ID, mv.Kid) {
		t.Fatal("a second walk started beside the first: each would call the contacts the other had not yet recorded")
	}
	progress := walkEnds(t, mover, mv.Kid)
	if progress.Told != 1 || progress.Waiting != 1 {
		t.Fatalf("under the partition: told=%d waiting=%d, want 1 and 1", progress.Told, progress.Waiting)
	}
	if len(progress.Unreached) != 1 || progress.Unreached[0].Contact != far.rootFpr() || progress.Unreached[0].Attempts != 1 || progress.Unreached[0].LastError == "" {
		t.Fatalf("the ledger must name the contact that was not reached, once, with why: %+v", progress.Unreached)
	}
	if c := near.contact(mover.rootFpr()); c.Endpoint != newEndpoint {
		t.Fatalf("the reachable contact did not follow the move: it holds %s", c.Endpoint)
	}
	if c := far.contact(mover.rootFpr()); c.Endpoint == newEndpoint {
		t.Fatal("the contact behind the partition was told anyway: the fault is not a fault")
	}
	toldNear := countLogged(near, "contact_new_address")

	// The link heals, and the operator resumes.
	for _, stream := range []string{"upstream", "downstream"} {
		if err := link.Toxics.RemoveToxic(ctx, "cut-"+stream); err != nil {
			t.Fatal(err)
		}
	}
	if !mover.n.ResumeMove(ctx, mover.acct.ID, mv.Kid) {
		t.Fatal("the resume did not start")
	}
	progress = walkEnds(t, mover, mv.Kid)
	if progress.Told != 2 || progress.Waiting != 0 || len(progress.Unreached) != 0 {
		t.Fatalf("after the heal: %+v, want both told and nobody waiting", progress)
	}
	if c := far.contact(mover.rootFpr()); c.Endpoint != newEndpoint {
		t.Fatalf("the contact that was cut off did not follow once it could be reached: it holds %s", c.Endpoint)
	}
	if again := countLogged(near, "contact_new_address"); again != toldNear {
		t.Fatalf("the resume told the contact that already knew: %d notices became %d", toldNear, again)
	}
	// And the conversation goes on at the new address, from the contact that was cut off.
	far.send(mover, mover.rootFpr(), "after-the-heal", "found you at the new address")
	if !mover.received("found you at the new address") {
		t.Fatal("the contact that was cut off cannot reach the mover at its new address")
	}
}

// walkEnds waits for the running walk to finish and returns the ledger as it then stands.
func walkEnds(t *testing.T, d *demoNode, kid string) MoveProgress {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		p, err := d.n.MoveProgress(context.Background(), d.acct.ID, kid)
		if err != nil {
			t.Fatal(err)
		}
		if !p.Walking {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("the walk never ended: %+v", p)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func countLogged(d *demoNode, action string) int {
	n := 0
	for _, line := range d.log {
		if strings.HasPrefix(line, action+" ") {
			n++
		}
	}
	return n
}
