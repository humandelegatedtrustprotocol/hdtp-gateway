package scenario

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
)

// S10: the MOVE campaign under a network partition (PACT §5.3, §9).
//
// Three real nodes. One moves to a new address while one of its two contacts is behind a
// partition — `tc netem loss 100%` in that node's network namespace, so its packets are DROPPED
// and a caller is left waiting, which is what a dead link does and what a refused connection does
// not. The operator's tool for this is `pact-gateway account announce`, and it is driven here as
// an operator drives it: from a shell, inside the node.
//
// What must hold:
//   - the contact that can be reached is told, and follows the move;
//   - `account announce` ANSWERS while a contact is unreachable, in the time a person waits for
//     a command. It used to run the walk and answer when the walk ended: on this harness, 17
//     seconds with one contact behind the partition and 21 with two, of the thirty the admin
//     socket allows, and beside the walk the install had started rather than instead of it;
//   - it names the contact that was not reached, how often it was tried, and why;
//   - after the partition heals, a resume tells the contact that was missed and ONLY that one;
//   - and the conversation carries on at the new address.
//
// The in-process tier of the same ground is internal/node/move_partition_test.go (Toxiproxy).
func TestAMoveCampaignSurvivesAPartition(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S10", Name: "a MOVE campaign under a partition: announce answers, resume tells only the missed contact", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 20 * time.Minute,
	})

	f := w.Fab
	net, err := f.Network(ctx, "lan", fabric.NetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PACT_SEAL": "required"}
	newHost := w.Fab.Name("mover-new")
	mover, err := w.Node(ctx, NodeOpts{Slug: "mover", Net: net, Env: env, Aliases: []string{newHost}})
	if err != nil {
		t.Fatalf("mover: %v", err)
	}
	near, err := w.Node(ctx, NodeOpts{Slug: "near", Net: net, Env: env})
	if err != nil {
		t.Fatalf("near: %v", err)
	}
	far, err := w.Node(ctx, NodeOpts{Slug: "far", Net: net, Env: env})
	if err != nil {
		t.Fatalf("far: %v", err)
	}

	// Both become the mover's contacts through one invite.
	inviteRaw, err := mover.Owner.Call(ctx, "create_invite", map[string]any{
		"account_id": mover.AccountID, "label": "for the move scenario", "max_uses": 2, "auto_accept": true, "preset": "friend",
	})
	if err != nil {
		t.Fatalf("create_invite: %v", err)
	}
	var inv struct{ Token, URL string }
	_ = json.Unmarshal([]byte(inviteRaw), &inv)
	if inv.URL == "" {
		inv.URL = "https://" + mover.Node.Name + ":8443/i/" + inv.Token
	}
	for _, contact := range []*Owned{near, far} {
		raw, err := contact.Owner.Call(ctx, "add_contact", map[string]any{"account_id": contact.AccountID, "invite_url": inv.URL})
		if err != nil {
			t.Fatalf("%s add_contact: %v", contact.Node.Name, err)
		}
		var added struct{ Code, Detail string }
		_ = json.Unmarshal([]byte(raw), &added)
		if added.Code != "" {
			t.Fatalf("%s add_contact refused: %s — %s", contact.Node.Name, added.Code, added.Detail)
		}
	}
	sendAndExpectAs(ctx, t, near, mover, "near, before the move "+PlaintextCanary, "move-pre-near")
	sendAndExpectAs(ctx, t, far, mover, "far, before the move "+PlaintextCanary, "move-pre-far")
	oldEndpoint := pinnedEndpoint(ctx, t, near, mover.Fpr)
	if oldEndpoint == "" || pinnedEndpoint(ctx, t, far, mover.Fpr) != oldEndpoint {
		t.Fatalf("before the move both contacts must pin the mover at one address: near %q", oldEndpoint)
	}

	// The partition, then the move.
	if err := f.Partition(ctx, far.Node); err != nil {
		t.Fatalf("partitioning far: %v", err)
	}
	healed := false
	defer func() {
		if !healed {
			_ = f.Heal(context.Background(), far.Node)
		}
	}()
	newEndpoint := "https://" + newHost + ":8443/a/mover/mcp"
	if _, err := mover.Wallet.Certify(ctx, topology.NodeOf(w.Fab, mover.Node), "mover", "move", newEndpoint); err != nil {
		t.Fatalf("the move (csr, issue, install-leaf): %v", err)
	}

	// The operator asks how it is going, again and again, and every time is ANSWERED.
	var report announceReport
	deadline := time.Now().Add(3 * time.Minute)
	for {
		report = announce(ctx, t, f, mover)
		if report.resumed || report.waiting == 0 {
			break // the first walk has ended: the ledger this call read is its result
		}
		if time.Now().After(deadline) {
			t.Fatalf("the first walk never ended: %+v", report)
		}
		time.Sleep(3 * time.Second)
	}
	if report.told != 1 || report.waiting != 1 {
		t.Fatalf("under the partition the ledger says told=%d waiting=%d, want 1 and 1\n%s", report.told, report.waiting, report.raw)
	}
	if !strings.Contains(report.raw, "not reached: "+far.Fpr) || !strings.Contains(report.raw, "(tried 1)") {
		t.Fatalf("the report must name the contact that was not reached and how often it was tried:\n%s", report.raw)
	}
	if got := pinnedEndpoint(ctx, t, near, mover.Fpr); got != newEndpoint {
		t.Fatalf("the reachable contact did not follow the move: it pins %q, want %q", got, newEndpoint)
	}
	toldNear := countAudit(ctx, t, near, "contact_new_address")
	if toldNear != 1 {
		t.Fatalf("the reachable contact recorded %d new-address notices, want 1", toldNear)
	}

	// The partition heals. Until the mover tries again, far still holds the old address.
	if err := f.Heal(ctx, far.Node); err != nil {
		t.Fatalf("healing far: %v", err)
	}
	healed = true
	deadline = time.Now().Add(4 * time.Minute)
	for {
		report = announce(ctx, t, f, mover)
		if report.waiting == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the campaign never finished after the heal: %+v\n%s", report, report.raw)
		}
		time.Sleep(3 * time.Second)
	}
	if report.told != 2 {
		t.Fatalf("after the heal told=%d, want 2\n%s", report.told, report.raw)
	}
	if got := pinnedEndpoint(ctx, t, far, mover.Fpr); got != newEndpoint {
		t.Fatalf("the contact that was cut off did not follow once it could be reached: it pins %q", got)
	}
	if again := countAudit(ctx, t, near, "contact_new_address"); again != toldNear {
		t.Fatalf("resuming told the contact that already knew: %d notices became %d", toldNear, again)
	}
	// And the conversation carries on, from the contact that was cut off, at the new address.
	sendAndExpectAs(ctx, t, far, mover, "far, after the move "+PlaintextCanary, "move-post-far")
}

type announceReport struct {
	told, waiting int
	resumed       bool
	raw           string
}

var announceCounts = regexp.MustCompile(`told=(\d+) waiting=(\d+)`)

// announce runs `account announce` inside the node, as an operator does, and requires an answer
// in a time a person would wait: far less than the thirty seconds one unreachable contact costs
// the walk itself.
func announce(ctx context.Context, t *testing.T, f *fabric.Fabric, o *Owned) announceReport {
	t.Helper()
	started := time.Now()
	out, err := f.Exec(ctx, o.Node, "/pact-gateway", "account", "announce", "-slug", "mover")
	took := time.Since(started)
	if err != nil {
		t.Fatalf("`account announce` failed after %v: %v\n%s", took.Round(time.Second), err, out)
	}
	if took > 10*time.Second {
		t.Fatalf("`account announce` took %v to answer: it must report the ledger, not wait for the walk", took.Round(time.Second))
	}
	m := announceCounts.FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("`account announce` printed no counts:\n%s", out)
	}
	r := announceReport{raw: string(out), resumed: strings.Contains(string(out), "resumed:")}
	r.told, _ = strconv.Atoi(m[1])
	r.waiting, _ = strconv.Atoi(m[2])
	return r
}

// pinnedEndpoint is the address `o` holds for the contact with that root.
func pinnedEndpoint(ctx context.Context, t *testing.T, o *Owned, root string) string {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "list_contacts", map[string]any{"account_id": o.AccountID})
	if err != nil {
		t.Fatalf("%s list_contacts: %v", o.Node.Name, err)
	}
	var contacts []struct{ Fingerprint, Endpoint string }
	if err := json.Unmarshal([]byte(raw), &contacts); err != nil {
		t.Fatalf("%s list_contacts is not a list: %v\n%s", o.Node.Name, err, shorten(raw, 200))
	}
	for _, c := range contacts {
		if c.Fingerprint == root {
			return c.Endpoint
		}
	}
	return ""
}

// countAudit counts the rows of one action in a node's trail.
func countAudit(ctx context.Context, t *testing.T, o *Owned, action string) int {
	t.Helper()
	return countAuditOutcome(ctx, t, o, action, "")
}
