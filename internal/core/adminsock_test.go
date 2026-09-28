package core

import (
	"context"
	"os"
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

// Two serves on one data dir share its socket path. The first to start serves the socket; the
// second serves none and leaves the first's alone (it used to remove whatever was at the path and
// bind its own, so the first went on running with no admin socket). The first's two Closes — the
// context's and the deferred one — do not remove a socket a later holder bound.
func TestTwoServesDoNotTakeEachOthersAdminSocket(t *testing.T) {
	sock := AdminSocketPath(t.TempDir())
	t.Cleanup(func() { _ = os.Remove(sock + ".lock") })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, second := NewAdminServer(sock), NewAdminServer(sock)
	first.Handle("who", func(map[string]string) (any, error) { return "first", nil })
	second.Handle("who", func(map[string]string) (any, error) { return "second", nil })
	if err := first.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !first.Serving() || second.Serving() {
		t.Fatalf("serving: first %v, second %v; want the first alone", first.Serving(), second.Serving())
	}
	var who string
	if err := AdminCall(sock, "who", nil, &who); err != nil || who != "first" {
		t.Fatalf("the socket answered %q (%v), want the first serve", who, err)
	}
	second.Close()
	if err := AdminCall(sock, "who", nil, &who); err != nil || who != "first" {
		t.Fatalf("closing the serve that holds no socket took the other's: %q %v", who, err)
	}

	first.Close()
	third := NewAdminServer(sock)
	third.Handle("who", func(map[string]string) (any, error) { return "third", nil })
	if err := third.Start(ctx); err != nil || !third.Serving() {
		t.Fatalf("a serve could not take the socket once its holder left: %v", err)
	}
	defer third.Close()
	first.Close()
	if err := AdminCall(sock, "who", nil, &who); err != nil || who != "third" {
		t.Fatalf("a second Close of the first holder removed the new holder's socket: %q %v", who, err)
	}
}
