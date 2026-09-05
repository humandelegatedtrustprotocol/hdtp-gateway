// Package preflight reports whether this host can run each of the harness fabrics,
// and says precisely what is missing when it cannot.
//
// It exists because the harness has two fabrics with different requirements
// (docs/harness-design.md §2, §5). Five topologies run on containers; the
// long-horizon suite runs in QEMU/HVF virtual machines, because only a guest with
// its own kernel has its own CLOCK_REALTIME. A host may have one, both, or neither,
// and the honest answer is per-fabric rather than a single verdict — reporting a
// blanket "not ready" on a machine with Docker but no QEMU would strand five of the
// six topologies for no reason.
package preflight

import (
	"context"
	"fmt"
	"strings"
)

// Fabric names one way of standing scenarios up.
type Fabric string

const (
	// FabricContainer runs topologies T1-T6 as containers on a bridge network.
	FabricContainer Fabric = "container"
	// FabricVM runs the time-travelling topology as QEMU guests, each with its own
	// wall clock set by -rtc base.
	FabricVM Fabric = "vm"
)

// Runner executes one probe command. It is injected so the checks are testable
// without the tools being present: a preflight that only passes on the author's
// machine is worse than none.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Check is one capability question and its answer.
type Check struct {
	Name string
	// Fabric is the fabric this check gates. A failed check disables that fabric
	// and no other.
	Fabric Fabric
	OK     bool
	// Detail is what a person needs in order to act — the tool found, the version,
	// or why it did not answer. Never empty.
	Detail string
}

// Report is the outcome of a probe.
type Report struct{ Checks []Check }

// Ready reports whether every check gating this fabric passed.
func (r Report) Ready(f Fabric) bool {
	seen := false
	for _, c := range r.Checks {
		if c.Fabric != f {
			continue
		}
		seen = true
		if !c.OK {
			return false
		}
	}
	return seen
}

func (r Report) String() string {
	var b strings.Builder
	for _, c := range r.Checks {
		mark := "FAIL"
		if c.OK {
			mark = "ok  "
		}
		fmt.Fprintf(&b, "%s %-12s [%s] %s\n", mark, c.Name, c.Fabric, c.Detail)
	}
	for _, f := range []Fabric{FabricContainer, FabricVM} {
		verdict := "NOT READY"
		if r.Ready(f) {
			verdict = "ready"
		}
		fmt.Fprintf(&b, "fabric %-10s %s\n", f, verdict)
	}
	return b.String()
}

// Probe runs every check under the caller's context.
func Probe(ctx context.Context, run Runner) Report {
	return Report{Checks: []Check{
		dockerCheck(ctx, run),
		qemuAccelCheck(ctx, run),
	}}
}

func dockerCheck(ctx context.Context, run Runner) Check {
	c := Check{Name: "docker", Fabric: FabricContainer}
	out, err := run(ctx, "docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}")
	if err != nil {
		c.Detail = "no Docker daemon answered: " + err.Error()
		return c
	}
	c.OK, c.Detail = true, "daemon "+strings.TrimSpace(string(out))
	return c
}

// qemuAccelCheck is deliberately one check rather than two. QEMU without hardware
// acceleration still runs, roughly ten times slower under TCG, which is not a fabric
// anyone should be handed silently — but the DETAIL must distinguish "absent" from
// "present but unaccelerated", because those need different actions.
func qemuAccelCheck(ctx context.Context, run Runner) Check {
	c := Check{Name: "qemu-accel", Fabric: FabricVM}
	out, err := run(ctx, "qemu-system-aarch64", "-accel", "help")
	if err != nil {
		c.Detail = "qemu-system-aarch64 not runnable: " + err.Error()
		return c
	}
	accels := parseAccelerators(string(out))
	switch {
	case has(accels, "hvf"):
		c.OK, c.Detail = true, "hardware acceleration available (hvf)"
	case has(accels, "kvm"):
		c.OK, c.Detail = true, "hardware acceleration available (kvm)"
	case has(accels, "tcg"):
		c.Detail = "only tcg (software emulation) — QEMU is installed but unaccelerated, " +
			"which boots roughly 10x slower; on macOS this usually means the binary lacks " +
			"the com.apple.security.hypervisor entitlement"
	default:
		c.Detail = "qemu reported no usable accelerator: " + oneLine(string(out))
	}
	return c
}

// parseAccelerators reads `qemu-system-aarch64 -accel help`, whose output is a
// header line followed by one accelerator per line.
func parseAccelerators(out string) []string {
	var got []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.TrimSpace(line)
		if f == "" || strings.HasSuffix(f, ":") {
			continue
		}
		got = append(got, strings.ToLower(f))
	}
	return got
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
