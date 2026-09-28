package core

import (
	"testing"
	"time"
)

// Two `serve` processes share one data dir: the first is alone and migrates, then shares; the
// second joins beside it; an offline command is refused while either runs and runs once both are
// gone. flock locks belong to the open file, so two locks taken here behave as two processes do.
func TestServesShareTheDataDirAndOfflineCommandsWaitForThemAll(t *testing.T) {
	dir := t.TempDir()
	first, err := AcquireServeLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Exclusive() {
		t.Fatal("the first serve on an idle data dir is not alone with it, so it may not migrate")
	}
	if _, err := AcquireLock(dir); err == nil {
		t.Fatal("an offline command ran beside a serve")
	}
	if err := first.Share(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireServeLock(dir)
	if err != nil {
		t.Fatalf("a second serve could not join the first: %v", err)
	}
	if second.Exclusive() {
		t.Fatal("a serve beside another was told it is alone, and would migrate under it")
	}
	if _, err := AcquireLock(dir); err == nil {
		t.Fatal("an offline command ran beside two serves")
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(dir); err == nil {
		t.Fatal("an offline command ran beside the serve still running")
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	offline, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("an offline command was refused an idle data dir: %v", err)
	}
	offline.Release()
}

// A serve that finds the lock held alone — another serve migrating — waits for it to be shared
// rather than failing at once, and then joins as a sharer.
func TestAServeWaitsOutAnotherServesMigration(t *testing.T) {
	dir := t.TempDir()
	migrating, err := AcquireServeLock(dir)
	if err != nil || !migrating.Exclusive() {
		t.Fatalf("setup: %v", err)
	}
	shared := make(chan error, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		shared <- migrating.Share()
	}()
	joined, err := AcquireServeLock(dir)
	if err != nil {
		t.Fatalf("a serve gave up while another migrated: %v", err)
	}
	if joined.Exclusive() {
		t.Fatal("the joining serve was told it is alone")
	}
	if err := <-shared; err != nil {
		t.Fatal(err)
	}
	joined.Release()
	migrating.Release()
}
