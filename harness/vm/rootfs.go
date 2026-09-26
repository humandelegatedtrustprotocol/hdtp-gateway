package vm

// Building the guest's root filesystem.
//
// The node is CGO_ENABLED=0 static, so the guest needs no libc, no runtime and no
// Docker inside it — just busybox, an init, and the binary. That is what keeps a
// VM topology proportionate: an initramfs, not a disk image.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tech-sumit/pact-gateway/harness/images"
)

// RootfsSpec describes the guest image to build.
type RootfsSpec struct {
	// Binary is a linux/arm64 static pact-gateway.
	Binary string
	// SeedDir, when set, is copied to /data in the guest — a store prepared on the
	// host so the scenario starts from known state at a known timestamp.
	SeedDir string
	// Script runs after the guest clock is set. It has busybox and
	// /bin/pact-gateway on PATH, and its stdout reaches the host console.
	Script string
	// Out is where the .cpio.gz is written.
	Out string
}

// initTemplate sets the clock from the emulated RTC before anything else runs.
//
// `hwclock -s` is the step that matters: the kernel reads the PL031 QEMU has
// offset by -rtc base, so everything after this line — including the node — sees
// the travelled time. Without it the guest would boot at the epoch and the whole
// exercise would prove nothing.
const initTemplate = `#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null
mount -t tmpfs none /tmp 2>/dev/null
hwclock -s 2>/dev/null || true
echo "PACT_GUEST_DATE=$(date -u '+%%Y-%%m-%%dT%%H:%%M:%%SZ')"
%s
echo "PACT_GUEST_DONE"
poweroff -f
`

// BuildRootfs assembles the initramfs. It uses an arm64 Alpine container for
// busybox and cpio rather than requiring either on the host.
func BuildRootfs(ctx context.Context, s RootfsSpec) error {
	if s.Binary == "" || s.Out == "" {
		return fmt.Errorf("vm: BuildRootfs needs Binary and Out")
	}
	stage, err := os.MkdirTemp("", "pact-rootfs")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	payload := filepath.Join(stage, "payload")
	// The mountpoints must EXIST in the image: `mount -t tmpfs none /tmp` fails
	// silently when /tmp is not there, and the first thing to notice is a node
	// that cannot write its log.
	for _, d := range []string{"bin", "proc", "sys", "tmp", "etc"} {
		if err := os.MkdirAll(filepath.Join(payload, d), 0o777); err != nil {
			return err
		}
	}
	bin, err := os.ReadFile(s.Binary)
	if err != nil {
		return fmt.Errorf("vm: reading %s: %w", s.Binary, err)
	}
	if err := os.WriteFile(filepath.Join(payload, "bin", "pact-gateway"), bin, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(payload, "init"),
		[]byte(fmt.Sprintf(initTemplate, s.Script)), 0o755); err != nil {
		return err
	}
	if s.SeedDir != "" {
		if err := copyTree(s.SeedDir, filepath.Join(payload, "data")); err != nil {
			return fmt.Errorf("vm: seeding /data: %w", err)
		}
	} else if err := os.MkdirAll(filepath.Join(payload, "data"), 0o777); err != nil {
		return err
	}

	outDir, outName := filepath.Split(s.Out)
	if outDir == "" {
		outDir = "."
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	script := `set -e
apk add --no-cache busybox-static cpio >/dev/null 2>&1
cp /bin/busybox.static /payload/bin/busybox
cd /payload && find . | cpio -o -H newc 2>/dev/null | gzip -1 > /out/` + outName
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--platform", "linux/arm64",
		"-v", payload+":/payload", "-v", absOut+":/out",
		images.Alpine, "sh", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("vm: building initramfs: %w (%s)", err, out)
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o777)
		}
		if !info.Mode().IsRegular() {
			// Sockets and the like are runtime state, never seed state — and a
			// stale admin.sock in the image would confuse the node on boot.
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o666)
	})
}
