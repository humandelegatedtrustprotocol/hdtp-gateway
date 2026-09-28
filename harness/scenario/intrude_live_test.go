package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/registry"
)

// S18 — the live intrusion battery of pact-identity against a real node.
//
// `pact vectors intrude --against` is ONE definition of the attacks a stranger can mount on the
// wire (pact-identity js/live-scenarios.json: forged, tampered, replayed and expired envelopes,
// every chain shape, a key-pinned card's retired header, a small form without a chain), with one
// control that must get THROUGH, last, from an attacker whose keys are new on every run. The cloud
// is measured with it on staging; until this scenario nothing aimed it at the node, whose own
// tests cover the same refusals one package at a time.
//
// What the tool judges, this scenario takes as it is: the tool exits non-zero on a scenario that
// REPRODUCES, one that never reached a PACT answer (UNREACHED), and a control that was refused or
// whose answer did not open. What it adds is what only the host can show: that each refusal is on
// the node's audit trail (build rule 7), and that the node still serves its contact afterwards.
func TestTheIntrusionBatteryIsRefusedByANode(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S18", Name: "the intrusion battery (pact vectors intrude) against a node: every attack refused, the control through, each refusal audited", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome, registry.PactCLI},
		Timeout: 12 * time.Minute,
	})
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := w.Node(ctx, NodeOpts{Slug: "alice", Net: net, PublishPublic: true})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}

	card := exportCard(ctx, t, alice)
	cardFile := filepath.Join(t.TempDir(), "alice.vcf")
	if err := os.WriteFile(cardFile, []byte(card), 0o600); err != nil {
		t.Fatal(err)
	}
	against := dialable(t, alice)
	before := auditRows(ctx, t, alice)

	out, code := intrude(ctx, t, against, cardFile)
	t.Logf("pact vectors intrude --against %s\n%s", against, out)
	summary := intrudeSummary.FindStringSubmatch(out)
	if summary == nil {
		t.Fatalf("the battery printed no summary (exit %d): it never ran", code)
	}
	total, _ := strconv.Atoi(summary[1])
	blocked, _ := strconv.Atoi(summary[2])
	if code != 0 {
		t.Fatalf("the battery failed against the node (exit %d): %s", code, summary[0])
	}
	// The control is the one scenario that is not a refusal; the rest must all be blocked. The
	// count is the tool's own, read from its battery, never a number written here.
	if blocked != total {
		t.Fatalf("%d of %d blocked, and the tool still exited 0", blocked, total)
	}

	t.Run("each refusal is on the node's audit trail", func(t *testing.T) {
		var fresh []auditRow
		for _, r := range auditRows(ctx, t, alice) {
			if r.Seq > lastSeq(before) {
				fresh = append(fresh, r)
			}
		}
		refused, kinds := 0, map[string]int{}
		for _, r := range fresh {
			kinds[r.Action+" "+r.Outcome]++
			// Every scenario but the control reaches the node as one sealed_call; its refusal is
			// that tool's row with the code it was answered.
			if r.Action == "sealed_call" && r.Outcome != "ok" {
				refused++
			}
		}
		t.Logf("audit rows written during the battery: %v", kinds)
		// A replayed scenario is posted twice, and the control is not a refusal, so the floor is
		// the refusals the tool counted: total minus the control.
		if refused < total-1 {
			t.Errorf("%d refused calls reached the audit trail for %d refused scenarios; new rows: %+v",
				refused, total-1, fresh)
		}
	})
}

// intrudeSummary is the tool's last line: "<n> scenarios: <b> blocked, <r> reproduce, <u> never
// reached a PACT answer…".
var intrudeSummary = regexp.MustCompile(`(\d+) scenarios: (\d+) blocked, (\d+) reproduce, (\d+) never reached`)

// intrude runs the battery and returns what it printed and its exit status.
func intrude(ctx context.Context, t *testing.T, against, cardFile string) (string, int) {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Getenv(registry.PactCLIEnv),
		"vectors", "intrude", "--against", against, "--card", cardFile, "--allow-insecure")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		}
		t.Fatalf("running %s: %v", cmd, err)
	}
	return string(out), 0
}

// dialable is the node's endpoint with its host replaced by the published loopback port: the
// leaf names https://alice.harness.example:<port>, which only the harness's own dialer resolves.
// The envelopes are sealed to the card's key from a FILE, so what reaches the node is judged the
// same whatever carried it (the reason --allow-insecure requires --card).
func dialable(t *testing.T, o *Owned) string {
	t.Helper()
	u, err := url.Parse(o.Pin.Endpoint)
	if err != nil {
		t.Fatalf("the pin's endpoint %q: %v", o.Pin.Endpoint, err)
	}
	u.Host = "127.0.0.1:" + o.PublicPort
	return u.String()
}

// exportCard is the account's signed card, as the owner's export_card tool gives it.
func exportCard(ctx context.Context, t *testing.T, o *Owned) string {
	t.Helper()
	var got struct{ Card string }
	if err := o.Owner.CallJSON(ctx, "export_card", map[string]any{"account_id": o.AccountID}, &got); err != nil {
		t.Fatalf("export_card: %v", err)
	}
	if !strings.Contains(got.Card, "X-PACT-CERT") {
		t.Fatalf("export_card gave no 2.0 card: %q", got.Card)
	}
	return got.Card
}

// auditRow is what audit_query returns of one row (store.AuditRow, which carries no JSON tags).
type auditRow struct {
	Seq       int64
	AccountID string
	ActorKind string
	ActorID   string
	Action    string
	Resource  string
	Outcome   string
	Details   string
}

// auditRows reads the audit trail the owner may see, up to the tool's ceiling of 1000 rows.
func auditRows(ctx context.Context, t *testing.T, o *Owned) []auditRow {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "audit_query", map[string]any{"limit": 1000})
	if err != nil {
		t.Fatalf("audit_query: %v", err)
	}
	var rows []auditRow
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("audit_query answered %s: %v", trim(raw), err)
	}
	return rows
}

// lastSeq is the highest sequence number among rows, 0 for none.
func lastSeq(rows []auditRow) int64 {
	var n int64
	for _, r := range rows {
		n = max(n, r.Seq)
	}
	return n
}

func trim(s string) string {
	if len(s) > 400 {
		return s[:400] + fmt.Sprintf("… (%d bytes)", len(s))
	}
	return s
}
