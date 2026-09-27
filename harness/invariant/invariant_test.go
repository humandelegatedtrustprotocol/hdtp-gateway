package invariant

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/topology"
)

func TestAFailedInvariantFailsTheReport(t *testing.T) {
	r := Report{{Name: "a", Status: Pass}, {Name: "b", Status: Fail, Detail: "broke"}}
	if r.OK() {
		t.Error("a failing invariant did not fail the report")
	}
	if !(Report{{Name: "a", Status: Pass}}).OK() {
		t.Error("a passing report is not OK")
	}
}

// A recorder that answers `audit verify` per node: what each node's chain says.
type verifier struct {
	calls   []string
	verdict map[string]string // container -> what audit verify prints
	stopErr map[string]bool
}

func (v *verifier) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	v.calls = append(v.calls, line)
	if len(args) >= 2 && args[0] == "stop" && v.stopErr[args[1]] {
		return nil, errors.New("no such container")
	}
	if len(args) >= 4 && args[0] == "run" && args[2] == "--volumes-from" {
		out := v.verdict[args[3]]
		if !strings.Contains(out, "intact") {
			return []byte(out), errors.New("exit status 1")
		}
		return []byte(out), nil
	}
	return []byte("ok"), nil
}

func twoNodes() *topology.Topo {
	return &topology.Topo{Image: "img", Nodes: []*topology.Node{
		{Slug: "alice", Container: &fabric.Container{Name: "x-alice"}},
		{Slug: "bob", Container: &fabric.Container{Name: "x-bob"}},
	}}
}

// The one built invariant reads each node's own verdict: it passes only when every chain says
// intact, and a broken or unstoppable node fails it by name. The control is the all-intact case,
// so an invariant that failed everything would not pass this.
func TestTheAuditChainInvariantReadsEveryNodesVerdict(t *testing.T) {
	ctx := context.Background()
	intact := &verifier{verdict: map[string]string{"x-alice": "audit chain intact (12 rows)", "x-bob": "audit chain intact (3 rows)"}}
	rep := All(ctx, fabric.New("x", intact.run), twoNodes())
	if !rep.OK() || !strings.Contains(rep[0].Detail, "2 node(s)") {
		t.Fatalf("two intact chains did not pass: %s", rep)
	}
	for _, c := range []string{"docker stop x-alice", "docker run --rm --volumes-from x-bob img audit verify"} {
		if !strings.Contains(strings.Join(intact.calls, "\n"), c) {
			t.Errorf("the invariant never ran %q: %v", c, intact.calls)
		}
	}

	broken := &verifier{verdict: map[string]string{"x-alice": "audit chain intact", "x-bob": "chain broken at row 2"}}
	if rep := All(ctx, fabric.New("x", broken.run), twoNodes()); rep.OK() || !strings.Contains(rep[0].Detail, "bob: chain broken at row 2") {
		t.Errorf("a broken chain did not fail the invariant by name: %s", rep)
	}

	stuck := &verifier{verdict: map[string]string{"x-alice": "audit chain intact", "x-bob": "audit chain intact"},
		stopErr: map[string]bool{"x-bob": true}}
	if rep := All(ctx, fabric.New("x", stuck.run), twoNodes()); rep.OK() || !strings.Contains(rep[0].Detail, "bob: could not stop") {
		t.Errorf("a node that could not be stopped was not reported: %s", rep)
	}
}
