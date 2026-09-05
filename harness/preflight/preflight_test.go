package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner answers a fixed script, so these tests say nothing about the machine
// they run on. A preflight that only passes on the author's laptop is worse than none.
func fakeRunner(out map[string]string, fail map[string]bool) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		if fail[key] {
			return nil, errors.New("not found")
		}
		if s, ok := out[key]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("unscripted: " + key)
	}
}

func fullyCapable() Runner {
	return fakeRunner(map[string]string{
		"docker version --format {{.Server.Os}}/{{.Server.Arch}}": "linux/arm64",
		"qemu-system-aarch64 -accel help":                         "Accelerators supported in QEMU binary:\nhvf\ntcg\n",
	}, nil)
}

func TestAFullyCapableHostIsReadyForEveryFabric(t *testing.T) {
	r := Probe(context.Background(), fullyCapable())
	if !r.Ready(FabricContainer) {
		t.Fatalf("container fabric reported not ready on a host with docker: %s", r)
	}
	if !r.Ready(FabricVM) {
		t.Fatalf("VM fabric reported not ready on a host with qemu+hvf: %s", r)
	}
}

// The fabrics are independent: a host with Docker but no QEMU can still run the
// container topologies. Reporting a blanket "not ready" would strand five of the six.
func TestMissingQEMUBlocksOnlyTheVMFabric(t *testing.T) {
	run := fakeRunner(
		map[string]string{"docker version --format {{.Server.Os}}/{{.Server.Arch}}": "linux/arm64"},
		map[string]bool{"qemu-system-aarch64 -accel help": true},
	)
	r := Probe(context.Background(), run)
	if !r.Ready(FabricContainer) {
		t.Errorf("a missing QEMU disabled the container fabric: %s", r)
	}
	if r.Ready(FabricVM) {
		t.Error("the VM fabric reported ready with no QEMU present")
	}
	if !strings.Contains(r.String(), "qemu") {
		t.Errorf("the report does not name the missing tool, so nobody can act on it:\n%s", r)
	}
}

func TestMissingDockerBlocksOnlyTheContainerFabric(t *testing.T) {
	run := fakeRunner(
		map[string]string{"qemu-system-aarch64 -accel help": "Accelerators supported in QEMU binary:\nhvf\ntcg\n"},
		map[string]bool{"docker version --format {{.Server.Os}}/{{.Server.Arch}}": true},
	)
	r := Probe(context.Background(), run)
	if r.Ready(FabricContainer) {
		t.Error("the container fabric reported ready with no Docker present")
	}
	if !r.Ready(FabricVM) {
		t.Errorf("a missing Docker disabled the VM fabric: %s", r)
	}
}

// QEMU without hardware acceleration still runs, ~10x slower under TCG. That is a
// usable-but-degraded state, and conflating it with "absent" would send someone
// hunting for an install that is already there.
func TestQEMUWithoutAccelerationIsDegradedNotAbsent(t *testing.T) {
	run := fakeRunner(map[string]string{
		"docker version --format {{.Server.Os}}/{{.Server.Arch}}": "linux/arm64",
		"qemu-system-aarch64 -accel help":                         "Accelerators supported in QEMU binary:\ntcg\n",
	}, nil)
	r := Probe(context.Background(), run)
	if r.Ready(FabricVM) {
		t.Error("an unaccelerated QEMU was reported as ready for the VM fabric")
	}
	var accel *Check
	for i := range r.Checks {
		if r.Checks[i].Name == "qemu-accel" {
			accel = &r.Checks[i]
		}
	}
	if accel == nil {
		t.Fatal("no qemu-accel check in the report")
	}
	if accel.OK {
		t.Error("qemu-accel reported OK with only tcg available")
	}
	if !strings.Contains(strings.ToLower(accel.Detail), "tcg") {
		t.Errorf("the detail does not explain that only tcg is available: %q", accel.Detail)
	}
}

// A Probe must never hang the caller: every check runs under the caller's context.
func TestProbeHonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	seen := false
	run := Runner(func(c context.Context, _ string, _ ...string) ([]byte, error) {
		seen = true
		if err := c.Err(); err != nil {
			return nil, err
		}
		return []byte("linux/arm64"), nil
	})
	r := Probe(ctx, run)
	if !seen {
		t.Fatal("Probe did not pass the caller's context to the runner")
	}
	if r.Ready(FabricContainer) || r.Ready(FabricVM) {
		t.Error("a cancelled probe reported a fabric as ready")
	}
}
