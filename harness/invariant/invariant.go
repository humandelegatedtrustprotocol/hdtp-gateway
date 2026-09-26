// Package invariant holds the properties checked against a finished topology.
//
// One is built: the audit chain verifies (P12-14 is the regression it guards). Three more were
// designed — no session-binding growth (P12-10), nothing withdrawn still callable (P12-02,
// P12-05), the store passing conformance after a scenario's writes — and never built. They sat
// here as checks that always answered "not observable", in a report nothing but their own unit
// test read; they were removed on 2026-09-27 (docs/harness-design.md §2) rather than kept as
// names for work that does not exist.
package invariant

import (
	"context"
	"fmt"
	"strings"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
	"github.com/tech-sumit/pact-gateway/harness/topology"
)

type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
)

type Result struct {
	Name   string
	Status Status
	Detail string
}

type Report []Result

// OK reports whether nothing failed.
func (r Report) OK() bool {
	for _, x := range r {
		if x.Status != Pass {
			return false
		}
	}
	return true
}

func (r Report) String() string {
	var b strings.Builder
	for _, x := range r {
		fmt.Fprintf(&b, "%-6s %-12s %s\n", x.Status, x.Name, x.Detail)
	}
	return b.String()
}

// All runs every invariant against a finished topology.
func All(ctx context.Context, f *fabric.Fabric, top *topology.Topo) Report {
	return Report{auditChainVerifies(ctx, f, top)}
}

// auditChainVerifies stops each node and verifies its hash chain with a sidecar.
//
// `audit verify` is deliberately offline — it refuses while the data dir is locked
// by a running node — so the node is stopped first. That is safe as a
// postcondition: the scenario is over by the time this runs.
func auditChainVerifies(ctx context.Context, f *fabric.Fabric, top *topology.Topo) Result {
	res := Result{Name: "audit-chain"}
	var bad []string
	for _, n := range top.Nodes {
		if _, err := f.Raw(ctx, "docker", "stop", n.Container.Name); err != nil {
			bad = append(bad, n.Slug+": could not stop: "+err.Error())
			continue
		}
		out, err := f.Raw(ctx, "docker", "run", "--rm", "--volumes-from", n.Container.Name,
			top.Image, "audit", "verify")
		text := strings.TrimSpace(string(out))
		if err != nil || !strings.Contains(text, "intact") {
			bad = append(bad, n.Slug+": "+text)
		}
	}
	if len(bad) > 0 {
		res.Status, res.Detail = Fail, strings.Join(bad, "; ")
		return res
	}
	res.Status = Pass
	res.Detail = fmt.Sprintf("%d node(s) verified intact", len(top.Nodes))
	return res
}
