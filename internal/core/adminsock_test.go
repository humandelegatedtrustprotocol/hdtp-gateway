package core

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAdminSocketRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	srv := NewAdminServer(sock)
	srv.Handle("ping", func(args map[string]string) (any, error) {
		return map[string]string{"pong": args["who"]}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var out map[string]string
	if err := AdminCall(sock, "ping", map[string]string{"who": "cli"}, &out); err != nil {
		t.Fatal(err)
	}
	if out["pong"] != "cli" {
		t.Fatalf("round trip: %+v", out)
	}
}

func TestAdminSocketUnknownCommand(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	srv := NewAdminServer(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	var out any
	err := AdminCall(sock, "nope", nil, &out)
	if err == nil {
		t.Fatal("unknown command must error")
	}
}

func TestStoreLockExcludes(t *testing.T) {
	dir := t.TempDir()
	l1, err := AcquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(dir); err == nil {
		t.Fatal("second lock acquisition must fail while held")
	}
	if err := l1.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("lock not reacquirable after release: %v", err)
	}
	l2.Release()
}

func TestAdminSocketPathFallsBackForLongDirs(t *testing.T) {
	short := "/tmp/pact-data"
	if got := AdminSocketPath(short); got != filepath.Join(short, "admin.sock") {
		t.Fatalf("short dir should use in-dir socket: %q", got)
	}
	long := "/very" // build a >100-byte path
	for len(long) < 150 {
		long += "/deeply-nested-component"
	}
	got := AdminSocketPath(long)
	if len(got) > 100 {
		t.Fatalf("fallback path still too long: %q (%d)", got, len(got))
	}
	if got != AdminSocketPath(long) {
		t.Fatal("fallback path must be deterministic")
	}
}
