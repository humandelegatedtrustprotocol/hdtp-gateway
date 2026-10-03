package registry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The cloud-battery need is provided by a checkout of the battery that can be aimed at a node, and
// by nothing less: a batondeck from before the battery took a target is a Go module too, and
// aimed at a node it fails for its own reasons.
func TestTheCloudBatteryNeedsABatteryThatTakesATarget(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(CloudBatteryEnv, dir)
	if err := probe(ctx, CloudBattery); err == nil {
		t.Error("an empty directory provided the battery")
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probe(ctx, CloudBattery); err == nil {
		t.Error("a battery with no target_test.go provided the need")
	}
	if err := os.WriteFile(filepath.Join(dir, "target_test.go"), []byte(`package x // targetKind = env("HDTP_LIVE_TARGET", "cloud")`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probe(ctx, CloudBattery); err != nil {
		t.Errorf("a battery that takes a target was refused: %v", err)
	}
	t.Setenv(CloudBatteryEnv, "")
	if err := probe(ctx, CloudBattery); err == nil {
		t.Error("an unset variable provided the battery")
	}
}
