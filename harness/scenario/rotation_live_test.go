package scenario

import (
	"context"
	"strings"
	"testing"
	"time"
)

// S10 — rotating an identity key while contacts are unreachable.
//
// Rotation is the one operation with a deadline attached: the old key is
// destroyed at grace expiry (SPEC §3.9 step 5), and a contact that never received
// the `update_contact` fan-out is lost at that moment. So the thing that must be
// true under partition is not "rotation succeeds" — it is that an incomplete
// fan-out is REPORTED, and that re-running resumes it.
//
// Rounding a partial fan-out up to success is the dangerous failure here: the
// owner believes everyone holds the new key, and finds out weeks later.
func TestRotationUnderPartitionReportsAndResumes(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	p, err := SetupPaired(ctx, "pactrot", Ports{Owner: "18671", Public: "18672"}, nodeImage)
	t.Cleanup(func() { p.Teardown("") })
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	before := execS(ctx, p.Fab, p.Node, "/pact-gateway", "account", "list")
	beforeFpr := field(before, "sha256:")
	if beforeFpr == "" {
		t.Fatalf("no fingerprint before rotation: %q", before)
	}

	// Cut the node off, so the fan-out cannot reach anybody.
	if err := p.Fab.Partition(ctx, p.Node); err != nil {
		t.Fatalf("partitioning: %v", err)
	}

	out, rerr := p.Fab.Exec(ctx, p.Node,
		"/pact-gateway", "account", "rotate-key", "--slug", "alice", "--grace", "48h")
	partitioned := string(out)
	t.Logf("rotate under partition -> err=%v out=%s", rerr, shorten(partitioned, 240))

	// The key itself must have rotated: rotation is local, delivery is not.
	afterFpr := field(execS(ctx, p.Fab, p.Node, "/pact-gateway", "account", "list"), "sha256:")
	if afterFpr == "" {
		t.Fatal("no fingerprint after rotation")
	}
	if afterFpr == beforeFpr {
		t.Errorf("the key did not rotate under partition (still %s) — rotation is a LOCAL "+
			"operation and must not depend on reaching contacts", shorten(beforeFpr, 24))
	}

	// And the outcome must not claim everyone was told. The CLI prints Done/Failed
	// counts; with the network cut, Done cannot be the whole contact list.
	if strings.Contains(partitioned, "Failed:0") || strings.Contains(partitioned, "Failed: 0") {
		t.Errorf("a rotation with no network reported zero failures — an owner would believe "+
			"every contact holds the new key: %s", shorten(partitioned, 240))
	}

	if err := p.Fab.Heal(ctx, p.Node); err != nil {
		t.Fatalf("healing: %v", err)
	}
	// Wait for the node to answer again before asking it to do more.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := p.Fab.Exec(ctx, p.Node, "/pact-gateway", "healthcheck"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the node never recovered after the partition was lifted")
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Re-running must be safe and must resume rather than rotate again — a second
	// rotation would invalidate the key the first one just published.
	resumed, rerr2 := p.Fab.Exec(ctx, p.Node,
		"/pact-gateway", "account", "rotate-key", "--slug", "alice", "--grace", "48h")
	t.Logf("re-run after healing -> err=%v out=%s", rerr2, shorten(string(resumed), 240))

	finalFpr := field(execS(ctx, p.Fab, p.Node, "/pact-gateway", "account", "list"), "sha256:")
	if finalFpr == "" {
		t.Fatal("no fingerprint after the resume")
	}
	// The property that matters. Re-running must FINISH the rotation already in
	// flight, not start another: a second rotation would invalidate the key the
	// first one published to whichever contacts did receive it.
	//
	// Before P14-10a this re-run was refused outright — "a rotation is still in
	// its grace period" — while the CLI's own error told the owner to re-run to
	// resume. A contact missed by the first attempt stayed missed and was lost
	// when the old key expired (§3.9 step 5).
	if finalFpr != afterFpr {
		t.Errorf("re-running rotated AGAIN (%s then %s) instead of resuming the first "+
			"rotation — contacts already re-pinned to %s would be stranded",
			shorten(afterFpr, 24), shorten(finalFpr, 24), shorten(afterFpr, 24))
	}
	if strings.Contains(string(resumed), "still in its grace period") {
		t.Error("the resume was refused; the CLI tells the owner to re-run to resume, so " +
			"there must be a way to actually do it")
	}
	// The audit chain must survive both attempts.
	if _, err := p.Fab.Raw(ctx, "docker", "stop", p.Node.Name); err != nil {
		t.Fatal(err)
	}
	verify, verr := p.Fab.Raw(ctx, "docker", "run", "--rm", "--volumes-from", p.Node.Name,
		nodeImage, "audit", "verify")
	if verr != nil || !strings.Contains(string(verify), "intact") {
		t.Fatalf("the audit chain did not survive rotation under partition: %v (%s)",
			verr, strings.TrimSpace(string(verify)))
	}
	t.Logf("audit after two rotations: %s", strings.TrimSpace(string(verify)))
}
