// Package vm runs a pact-gateway node inside a QEMU/HVF guest so a scenario can
// give it an arbitrary WALL CLOCK.
//
// This exists because containers cannot do it. Linux time namespaces deliberately
// do not virtualize CLOCK_REALTIME (only CLOCK_MONOTONIC and CLOCK_BOOTTIME), so
// every container on a host shares one wall clock; `libfaketime` cannot help
// either, because Go reads the clock through the vDSO and bypasses the libc
// symbols it hooks — measured, not assumed. A guest has its own kernel, so
// `-rtc base=<datetime>` gives it its own CLOCK_REALTIME and touches nothing else.
//
// It is HARNESS SETUP, not a product feature. The node is the ordinary static
// binary with no flags, no build tag and no configuration for time: it simply
// asks the kernel what time it is and gets a different answer. Escalation E11 —
// which proposed a clock knob inside the product — was withdrawn precisely so
// that no such control ever reaches a security surface.
package vm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Guest describes one boot.
type Guest struct {
	// Kernel is an aarch64 Linux kernel image (Alpine's vmlinuz-virt works as-is;
	// QEMU loads its EFI-stub form directly, no decompression step).
	Kernel string
	// Initramfs holds busybox, the node binary and a seeded /data.
	Initramfs string
	// RTCBase is the guest's wall clock at boot, e.g. "2026-11-23T10:00:00".
	// Empty means the host clock.
	RTCBase string
	// Memory in MiB. The node is a 72 MB static binary living in a tmpfs
	// initramfs, so this is not the place to economise.
	MemoryMiB int
	// Timeout bounds the whole boot.
	Timeout time.Duration
}

// Console is what the guest printed, plus how it ended.
type Console struct {
	Text string
	// GuestDate is the wall clock the guest itself reported, which is the
	// evidence that the clock actually moved rather than the flag being accepted.
	GuestDate string
}

const qemuBin = "qemu-system-aarch64"

// Boot runs the guest to completion and returns its console.
func (g Guest) Boot(ctx context.Context) (Console, error) {
	if g.MemoryMiB == 0 {
		g.MemoryMiB = 1024
	}
	if g.Timeout == 0 {
		g.Timeout = 3 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, g.Timeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "pact-vm")
	if err != nil {
		return Console{}, err
	}
	defer os.RemoveAll(dir)
	serial := filepath.Join(dir, "console.log")

	args := []string{
		"-machine", "virt,accel=hvf", "-cpu", "host",
		"-smp", "2", "-m", fmt.Sprint(g.MemoryMiB),
		"-kernel", g.Kernel, "-initrd", g.Initramfs,
		"-append", "console=ttyAMA0 rdinit=/init quiet",
		"-display", "none", "-serial", "file:" + serial, "-no-reboot",
	}
	if g.RTCBase != "" {
		// The whole point. QEMU applies base as an offset when the guest reads the
		// emulated PL031 RTC; it never calls settimeofday(2), so the HOST clock is
		// untouched and two guests can hold different times at once.
		args = append(args, "-rtc", "base="+g.RTCBase)
	}

	runErr := exec.CommandContext(runCtx, qemuBin, args...).Run()
	raw, readErr := os.ReadFile(serial)
	if readErr != nil {
		return Console{}, fmt.Errorf("vm: no console output (%v); qemu: %w", readErr, runErr)
	}
	c := Console{Text: string(raw)}
	for _, line := range strings.Split(c.Text, "\n") {
		if i := strings.Index(line, guestDateMarker); i >= 0 {
			c.GuestDate = strings.TrimSpace(line[i+len(guestDateMarker):])
		}
	}
	if runErr != nil && c.Text == "" {
		return c, fmt.Errorf("vm: guest produced no output: %w", runErr)
	}
	return c, nil
}

// guestDateMarker is what /init prints so the host can read the guest's own clock
// back. Asserting on the guest's report rather than on the flag we passed is the
// difference between testing QEMU and testing our own argv.
const guestDateMarker = "PACT_GUEST_DATE="
