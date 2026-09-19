// Package invariant holds the checks that run after EVERY scenario.
//
// They are postconditions rather than a suite of their own because each one is a
// regression this project has already shipped and had to correct (P12-02, P12-05,
// P12-10, P12-14). A property that broke once, silently, is a property worth
// re-asserting at the end of every scenario rather than in one test somebody
// remembers to run.
//
// The status vocabulary matters. A check that CANNOT observe its property reports
// NotObservable, never Pass. Reporting an unimplemented check as green is exactly
// the "hollow done" this project spent four review passes correcting, and it is
// worse here because a green invariant is what a scenario's credibility rests on.
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
	// NotObservable means the harness cannot yet see this property. It is not a
	// pass, and OK() does not treat it as one.
	NotObservable Status = "not-observable"
)

type Result struct {
	Name   string
	Status Status
	Detail string
}

type Report []Result

// OK reports whether nothing FAILED. NotObservable does not fail a scenario — it
// would block every run until the last check is built — but String() names it so
// the gap is visible in every report rather than forgotten.
func (r Report) OK() bool {
	for _, x := range r {
		if x.Status == Fail {
			return false
		}
	}
	return true
}

// Unobserved counts the properties this report could not actually check.
func (r Report) Unobserved() int {
	n := 0
	for _, x := range r {
		if x.Status == NotObservable {
			n++
		}
	}
	return n
}

func (r Report) String() string {
	var b strings.Builder
	for _, x := range r {
		fmt.Fprintf(&b, "%-14s %-16s %s\n", x.Status, x.Name, x.Detail)
	}
	if n := r.Unobserved(); n > 0 {
		fmt.Fprintf(&b, "NOTE: %d invariant(s) could not be observed — this run proves less than a full pass\n", n)
	}
	return b.String()
}

// All runs every invariant against a finished topology.
func All(ctx context.Context, f *fabric.Fabric, top *topology.Topo) Report {
	return Report{
		auditChainVerifies(ctx, f, top),
		sessionBindingsBounded(),
		withdrawnToolsAreUncallable(),
		storeConformance(),
	}
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

// The remaining three need machinery that later P14 tasks build. They report
// NotObservable rather than Pass, so no run can claim more than it proved.

func sessionBindingsBounded() Result {
	return Result{Name: "session-bindings", Status: NotObservable,
		Detail: "needs an in-node metric the product does not expose yet (P12-10 is unit-pinned)"}
}

func withdrawnToolsAreUncallable() Result {
	return Result{Name: "withdrawn-tools", Status: NotObservable,
		Detail: "needs the peer driver to call a withdrawn tool over mTLS (P14-05)"}
}

func storeConformance() Result {
	return Result{Name: "store-conformance", Status: NotObservable,
		Detail: "needs the store file extracted and run against the conformance suite (P14-10)"}
}
