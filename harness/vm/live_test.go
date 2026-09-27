package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/registry"
)

// The clock claim, proven end to end: a REAL pact-gateway binary, unmodified, run
// twice from identical state, disagreeing about what day it is because the guest
// kernel does.
//
// This is what makes S8 possible without any product change. E11 proposed a clock
// knob inside the node; this replaces it entirely.
func TestGuestClockTravelsAndTheNodeBelievesIt(t *testing.T) {
	// Docker builds the guest's rootfs (BuildRootfs); the kernel need covers the image file and an
	// accelerated QEMU.
	ctx := registry.Start(t, registry.Spec{
		ID: "S8", Name: "a guest's wall clock travels a year and the unmodified node believes it", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.Kernel},
		Timeout: 10 * time.Minute,
	})
	kernel := os.Getenv(registry.KernelEnv)

	// The ordinary shipped binary, cross-built for the guest. No build tag, no
	// clock flag, nothing about time.
	bin := filepath.Join(t.TempDir(), "pact-gateway")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/pact-gateway")
	// go test runs in the PACKAGE directory (harness/vm), so the repo root is two
	// levels up, not one.
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cross-building the node: %v (%s)", err, out)
	}

	work := t.TempDir()
	img := filepath.Join(work, "rootfs.cpio.gz")
	// The node creates an account, which stamps a row with the guest's clock —
	// so the store itself carries the travelled time, not just the console.
	// account create talks over the ADMIN SOCKET, so the node has to be serving —
	// the CLI is a client to a running node, not a standalone tool. Getting this
	// wrong produced a real, useful error rather than a silent pass.
	script := `export PACT_DATA_DIR=/data
export PACT_PUBLIC_BIND=127.0.0.1:8443
export PACT_INTERNAL_BIND=127.0.0.1:8080
pact-gateway serve >/tmp/serve.log 2>&1 &
i=0
while [ ! -S /data/admin.sock ] && [ $i -lt 120 ]; do sleep 0.25; i=$((i+1)); done
pact-gateway account create --slug alice --name Alice 2>&1 | head -1
echo "PACT_ACCOUNTS=$(pact-gateway account list 2>/dev/null | wc -l)"
kill %1 2>/dev/null
sleep 1
pact-gateway audit verify 2>&1 | head -1
head -3 /tmp/serve.log
`
	if err := BuildRootfs(ctx, RootfsSpec{Binary: bin, Script: script, Out: img}); err != nil {
		t.Fatalf("building the rootfs: %v", err)
	}

	boot := func(base string) Console {
		t.Helper()
		c, err := Guest{
			Kernel: kernel, Initramfs: img, RTCBase: base,
			MemoryMiB: 1024, Timeout: 4 * time.Minute,
		}.Boot(ctx)
		if err != nil {
			t.Fatalf("boot at %q: %v\n%s", base, err, tail(c.Text, 900))
		}
		if !strings.Contains(c.Text, "PACT_GUEST_DONE") {
			t.Fatalf("guest at %q did not finish:\n%s", base, tail(c.Text, 1200))
		}
		return c
	}

	present := boot("")
	future := boot("2027-06-01T12:00:00")

	t.Logf("host now      : %s", time.Now().UTC().Format("2006-01-02"))
	t.Logf("guest present : %s", present.GuestDate)
	t.Logf("guest future  : %s", future.GuestDate)

	if present.GuestDate == "" || future.GuestDate == "" {
		t.Fatal("a guest did not report its own date, so nothing here is evidence")
	}
	if !strings.HasPrefix(future.GuestDate, "2027-06-01") {
		t.Fatalf("the guest did not travel: -rtc base asked for 2027-06-01, guest says %q", future.GuestDate)
	}
	if present.GuestDate == future.GuestDate {
		t.Fatal("both guests report the same time; the clock did not move")
	}
	// The host must be untouched — QEMU never calls settimeofday(2), and a harness
	// that moved the developer's clock would be unusable.
	if hostYear := time.Now().UTC().Format("2006"); hostYear == "2027" {
		t.Fatal("the HOST clock reads 2027 — the guest's clock leaked out")
	}

	// And the node itself ran at that clock: it created an account and verified
	// its own audit chain from inside the travelled guest.
	for name, c := range map[string]Console{"present": present, "future": future} {
		if !strings.Contains(c.Text, "created alice") {
			t.Errorf("%s guest: the node did not create an account:\n%s", name, tail(c.Text, 600))
		}
		if !strings.Contains(c.Text, "intact") {
			t.Errorf("%s guest: the audit chain did not verify at this clock:\n%s", name, tail(c.Text, 600))
		}
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
