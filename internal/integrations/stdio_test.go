package integrations

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

func TestSplitCommandTokenizesAndRefusesShell(t *testing.T) {
	argv, err := SplitCommand(`npx -y "@some/mcp server" --flag 'a b'`)
	if err != nil || len(argv) != 5 || argv[2] != "@some/mcp server" || argv[4] != "a b" {
		t.Fatalf("argv=%v err=%v", argv, err)
	}
	for _, bad := range []string{
		"sh -c 'x' | tee /tmp/x", "echo $HOME", "a && b", "cmd > out", "cmd `id`", "a;b", "",
		`unterminated "quote`,
	} {
		if _, err := SplitCommand(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestBackoffLadder(t *testing.T) {
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second,
	}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Fatalf("Backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
}

// AC: env not in the allow-list never reaches the child — proven by running the
// child itself as an env echo (/usr/bin/env prints exactly its environment).
func TestChildEnvIsExactlyTheAllowList(t *testing.T) {
	t.Setenv("HDTP_NODE_SECRET", "must-not-leak")
	sup := &Supervisor{Config: StdioConfig{
		Command: "/usr/bin/env",
		Env:     map[string]string{"FOO": "bar"},
		Shim:    testShim(), // caps applied via the shim — env must STILL be exactly the allow-list
	}}
	cmd, err := sup.BuildCmd()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(out))
	if got != "FOO=bar" {
		t.Fatalf("child environment = %q, want exactly FOO=bar", got)
	}
	// empty allow-list = empty environment, not inherited
	sup2 := &Supervisor{Config: StdioConfig{Command: "/usr/bin/env", Shim: testShim()}}
	cmd2, _ := sup2.BuildCmd()
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out2)) != "" {
		t.Fatalf("empty allow-list leaked environment: %q", out2)
	}
}

// AC: a crash-looping child walks the backoff ladder to the ceiling and then
// surfaces `unavailable` without launching further processes.
func TestCrashLoopHitsCeilingThenUnavailable(t *testing.T) {
	st, err := store.OpenSQLite(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, _ := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "crashy", Transport: "stdio-supervised", Command: "/usr/bin/false",
	})

	var mu sync.Mutex
	var slept []time.Duration
	aud := &auditRec{}
	m := &Manager{
		Store: st, Audit: aud.fn, PingEvery: -1,
		StdioSleep: func(d time.Duration) { mu.Lock(); slept = append(slept, d); mu.Unlock() },
		StdioConfigFor: func(row store.Integration) StdioConfig {
			return StdioConfig{Command: row.Command, MaxRestarts: 8, TerminateDuration: time.Second, Shim: testShim()}
		},
	}
	for i := 0; i < 8; i++ {
		if err := m.Connect(ctx, in.ID); err == nil {
			t.Fatalf("attempt %d connected to /usr/bin/false", i+1)
		} else if errors.Is(err, ErrUnavailable) {
			t.Fatalf("gave up early on attempt %d", i+1)
		}
	}
	mu.Lock()
	wantSleeps := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second,
	}
	if len(slept) != len(wantSleeps) {
		t.Fatalf("sleeps = %v", slept)
	}
	for i := range wantSleeps {
		if slept[i] != wantSleeps[i] {
			t.Fatalf("sleep %d = %v, want %v (ladder %v)", i, slept[i], wantSleeps[i], slept)
		}
	}
	n := len(slept)
	mu.Unlock()

	// past the threshold: unavailable, and no further launch (no further sleep)
	err = m.Connect(ctx, in.ID)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("want unavailable, got %v", err)
	}
	mu.Lock()
	if len(slept) != n {
		t.Fatal("gave-up attempt still slept/launched")
	}
	mu.Unlock()
	row, _ := st.GetIntegrationByID(ctx, in.ID)
	if row.Status != "unreachable" || m.Available(in.ID) {
		t.Fatalf("status=%s available=%v", row.Status, m.Available(in.ID))
	}
	if !aud.hasRow("integration_child_crash", "integration:crashy", "error") {
		t.Fatalf("crashes not audited: %v", aud.rows)
	}

	// A plain Connect — startup, the health cycle — stays given up.
	if err := m.Connect(ctx, in.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a Connect that is not the owner's re-armed a child that gave up: %v", err)
	}
	// The owner's reconnect clears give-up and a launch happens again.
	if err := m.Reconnect(ctx, in.ID); errors.Is(err, ErrUnavailable) {
		t.Fatal("the owner's reconnect did not clear give-up")
	}
}
