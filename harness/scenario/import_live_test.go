package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
)

// S16 and S17: the handshake after an import (PACT §9.2, design §4.8), between real nodes.
//
// An identity leaves one node the way a person moves it: `export` on the old host, offline, then
// `import FILE.zip -slug S -yes` on a new host that has never held it, offline, then the wallet's
// first leaf on the new host. Installing that leaf sends every imported contact this host's
// handshake: `update_contact` to a peer that pins the identity, and `request_contact` to one that
// refuses that — which then decides under its own policy.
//
//   - S16: the peer pins the identity and follows it to the new host.
//   - S17: the peer has blocked the identity. `update_contact` is contact-tier, so it is refused;
//     the fallback request meets the peer's block, which answers as it answers a stranger, and
//     the peer's pin does not move.
//
// The in-process tier of the same ground is internal/node/handshake_test.go.

func TestAPeerFollowsAnIdentityImportedOntoANewHost(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S16", Name: "after export and import onto a new host, a peer that pins the identity follows it", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 20 * time.Minute,
	})
	m := importedMove(ctx, t, w, false)
	deadline := time.Now().Add(3 * time.Minute)
	for pinnedEndpoint(ctx, t, m.peer, m.mover.Fpr) != m.newEndpoint {
		if time.Now().After(deadline) {
			t.Fatalf("the peer never followed the imported identity to %s: it pins %q\n%s", m.newEndpoint,
				pinnedEndpoint(ctx, t, m.peer, m.mover.Fpr), execS(ctx, w.Fab, m.dest, "/pact-gateway", "account", "announce", "-slug", "mover"))
		}
		time.Sleep(3 * time.Second)
	}
	if n := countAudit(ctx, t, m.peer, "contact_new_address"); n != 1 {
		t.Fatalf("the peer recorded %d new-address notices, want 1", n)
	}
	// The new host's ledger says the contact was told.
	report := execS(ctx, w.Fab, m.dest, "/pact-gateway", "account", "announce", "-slug", "mover")
	if !strings.Contains(report, "told=1 waiting=0") {
		t.Fatalf("the new host's campaign: %s", report)
	}
}

func TestAPeerThatBlockedTheIdentityDecidesUnderItsOwnPolicy(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S17", Name: "after export and import, a peer that blocked the identity is asked, and its block answers", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 20 * time.Minute,
	})
	m := importedMove(ctx, t, w, true)
	// The fallback request reaches the peer, whose block answers it as it answers a stranger
	// (SPEC §9.1): the peer's audit trail is the only place that knows.
	deadline := time.Now().Add(3 * time.Minute)
	for countAuditOutcome(ctx, t, m.peer, "request_contact", "blocked_silent") == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the blocked peer never received the handshake's request_contact\n%s",
				execS(ctx, w.Fab, m.dest, "/pact-gateway", "account", "announce", "-slug", "mover"))
		}
		time.Sleep(3 * time.Second)
	}
	// Its own policy stands: still blocked, and its pin stays where it was.
	if got := pinnedEndpoint(ctx, t, m.peer, m.mover.Fpr); got != m.oldEndpoint {
		t.Fatalf("a peer that blocked the identity moved its pin to %q", got)
	}
	if status := contactStatus(ctx, t, m.peer, m.mover.Fpr); status != "blocked" {
		t.Fatalf("the peer holds the identity as %q after the handshake, want blocked", status)
	}
	if n := countAudit(ctx, t, m.peer, "contact_new_address"); n != 0 {
		t.Fatalf("a peer that blocked the identity recorded %d new-address notices", n)
	}
}

// importMove is what the two scenarios share.
type importMove struct {
	mover, peer              *Owned
	dest                     *fabric.Container
	oldEndpoint, newEndpoint string
}

// importedMove pairs the mover and a peer, blocks the mover on the peer when asked, exports the
// mover offline, imports it offline onto a new host that never held it, and installs the wallet's
// first leaf there. Everything after that is the campaign's.
func importedMove(ctx context.Context, t *testing.T, w *World, peerBlocks bool) importMove {
	t.Helper()
	f := w.Fab
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PACT_SEAL": "required"}
	mover, err := w.Node(ctx, NodeOpts{Slug: "mover", Net: net, Env: env})
	if err != nil {
		t.Fatalf("mover: %v", err)
	}
	peerNode, err := w.Node(ctx, NodeOpts{Slug: "peer", Net: net, Env: env})
	if err != nil {
		t.Fatalf("peer: %v", err)
	}
	inviteRaw, err := mover.Owner.Call(ctx, "create_invite", map[string]any{
		"account_id": mover.AccountID, "label": "for the import scenario", "max_uses": 1, "auto_accept": true, "preset": "friend",
	})
	if err != nil {
		t.Fatalf("create_invite: %v", err)
	}
	var inv struct{ URL string }
	_ = json.Unmarshal([]byte(inviteRaw), &inv)
	if inv.URL == "" {
		t.Fatalf("create_invite answered no link: %s", shorten(inviteRaw, 200))
	}
	raw, err := peerNode.Owner.Call(ctx, "add_contact", map[string]any{"account_id": peerNode.AccountID, "invite_url": inv.URL})
	if err != nil {
		t.Fatalf("add_contact: %v", err)
	}
	var added struct{ Code, Detail string }
	_ = json.Unmarshal([]byte(raw), &added)
	if added.Code != "" {
		t.Fatalf("add_contact refused: %s — %s", added.Code, added.Detail)
	}
	sendAndExpectAs(ctx, t, peerNode, mover, "before the move "+PlaintextCanary, "import-pre")
	m := importMove{mover: mover, peer: peerNode, oldEndpoint: pinnedEndpoint(ctx, t, peerNode, mover.Fpr)}
	if m.oldEndpoint == "" {
		t.Fatal("the peer does not pin the mover before the move")
	}
	if peerBlocks {
		if _, err := peerNode.Owner.Call(ctx, "block_contact", map[string]any{"account_id": peerNode.AccountID, "contact_fpr": mover.Fpr}); err != nil {
			t.Fatalf("block_contact: %v", err)
		}
	}

	// The new host: a node that has never held the identity.
	destName := f.Name("dest")
	m.newEndpoint = fmt.Sprintf("https://%s:%d/a/mover/mcp", destName, topology.PublicPort)
	if m.dest, err = topology.Serve(ctx, f, fabric.Spec{Name: "dest", Image: images.Node, Network: net, Cmd: []string{"serve"},
		Env: mergeEnv(topology.NodeEnv(fmt.Sprintf("https://%s:%d", destName, topology.PublicPort)), env)}); err != nil {
		t.Fatalf("dest: %v", err)
	}
	if err := topology.WaitHealthy(ctx, f, m.dest); err != nil {
		t.Fatal(err)
	}

	// Export, offline: the old host is stopped, and the export runs over its data directory.
	dir := t.TempDir()
	file := filepath.Join(dir, "mover.zip")
	docker(ctx, t, f, "stop", mover.Node.Name)
	docker(ctx, t, f, "run", "--rm", "--volumes-from", mover.Node.Name, images.Node, "export", "-slug", "mover", "-out", "/data/mover.zip")
	docker(ctx, t, f, "cp", mover.Node.Name+":/data/mover.zip", file)
	if err := os.Chmod(file, 0o644); err != nil { // docker cp keeps the mode; the node runs as nonroot
		t.Fatal(err)
	}

	// Import, offline, on the new host: reviewed, then written.
	docker(ctx, t, f, "stop", m.dest.Name)
	docker(ctx, t, f, "cp", file, m.dest.Name+":/data/mover.zip")
	review := docker(ctx, t, f, "run", "--rm", "--volumes-from", m.dest.Name, images.Node, "import", "/data/mover.zip", "-slug", "mover")
	if !strings.Contains(review, "write "+peerNode.Fpr) || !strings.Contains(review, "nothing was written") {
		t.Fatalf("the import's review:\n%s", review)
	}
	done := docker(ctx, t, f, "run", "--rm", "--volumes-from", m.dest.Name, images.Node, "import", "/data/mover.zip", "-slug", "mover", "-yes")
	if !strings.Contains(done, "not served yet: mover") {
		t.Fatalf("the import:\n%s", done)
	}
	docker(ctx, t, f, "start", m.dest.Name)
	if err := topology.WaitHealthy(ctx, f, m.dest); err != nil {
		t.Fatal(err)
	}

	// The wallet's first leaf on the new host. Its install starts the handshake.
	if _, err := mover.Wallet.Certify(ctx, topology.NodeOf(f, m.dest), "mover", "move", m.newEndpoint); err != nil {
		t.Fatalf("the new host's first leaf: %v", err)
	}
	return m
}

func docker(ctx context.Context, t *testing.T, f *fabric.Fabric, args ...string) string {
	t.Helper()
	out, err := f.Raw(ctx, "docker", args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func mergeEnv(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// countAuditOutcome counts the rows of one action in a node's trail with one outcome, or with
// any when outcome is "".
func countAuditOutcome(ctx context.Context, t *testing.T, o *Owned, action, outcome string) int {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "audit_query", map[string]any{"limit": 1000})
	if err != nil {
		t.Fatalf("%s audit_query: %v", o.Node.Name, err)
	}
	type row struct{ Action, Outcome string }
	var rows []row
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		var wrapped struct{ Rows []row }
		if err2 := json.Unmarshal([]byte(raw), &wrapped); err2 != nil {
			t.Fatalf("%s audit_query is neither a list nor {rows}: %v\n%s", o.Node.Name, err, shorten(raw, 200))
		}
		rows = wrapped.Rows
	}
	n := 0
	for _, r := range rows {
		if r.Action == action && (outcome == "" || r.Outcome == outcome) {
			n++
		}
	}
	return n
}
