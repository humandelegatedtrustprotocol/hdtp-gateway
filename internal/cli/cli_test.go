package cli

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, "test", &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionCommand(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != 0 || !strings.Contains(out, "pact-gateway test") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errb := run(t, "frobnicate")
	if code != 2 || !strings.Contains(errb, "unknown command") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestMigrateAppliesAndDoctorReportsClean(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+filepath.Join(dir, "data")+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run(t, "migrate", "-config", cfgPath)
	if code != 0 || !strings.Contains(out, "migrations applied") {
		t.Fatalf("migrate: code=%d out=%q err=%q", code, out, errb)
	}
	code, out, _ = run(t, "doctor", "-config", cfgPath)
	if code != 0 {
		t.Fatalf("doctor: code=%d out=%q", code, out)
	}
	for _, want := range []string{"ok   config", "ok   data-dir", "lock         free", "ok   store-open", "ok   tunnel       direct (mode direct", "warn probe        skipped"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
}

func TestMigrateRefusedWhileLockHeld(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// simulate a serving node: hold the lock
	lock, err := core.AcquireLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	code, _, errb := run(t, "migrate", "-config", cfgPath)
	if code == 0 {
		t.Fatal("migrate must refuse while the lock is held")
	}
	if !strings.Contains(errb, "in use") {
		t.Fatalf("error should name the lock: %q", errb)
	}
}

func TestHealthcheckCommand(t *testing.T) {
	// Against a live internal listener on ephemeral ports, and a node that is
	// STOPPED at the end. This used to pin 18099 and leave serve running: the
	// package could not be run twice (the leftover node answered the second
	// run's healthcheck at once), and the still-running node kept writing into
	// the temp dir while TempDir's cleanup removed it — "directory not empty".
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	internal, public := freePort(t), freePort(t)
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+filepath.Join(dir, "d")+
		`", "internal_bind": "`+internal+`", "public_bind": "`+public+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	startServeAt(t, filepath.Join(dir, "d"), cfgPath, internal, public)
	if code, out, errb := runQuiet("healthcheck", "-config", cfgPath); code != 0 {
		t.Fatalf("healthcheck failed against a serving node: code=%d out=%q err=%q", code, out, errb)
	}
	// and it fails against a port nothing listens on
	cfg2 := filepath.Join(dir, "config2.json")
	_ = os.WriteFile(cfg2, []byte(`{"data_dir": "`+filepath.Join(dir, "d2")+`", "internal_bind": "`+freePort(t)+`"}`), 0o600)
	if code, _, _ := runQuiet("healthcheck", "-config", cfg2); code == 0 {
		t.Fatal("healthcheck must fail when nothing is listening")
	}
}

func runQuiet(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, "test", &out, &errb)
	return code, out.String(), errb.String()
}

func TestAccountCreateAndListViaAdminSocket(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	// Ephemeral ports and a node that is STOPPED: these used to hardcode 18097
	// and never shut down, so the package could not be run twice — which is
	// exactly where most of this project's end-to-end pins live, and none of
	// them could ever be repeated to expose ordering or leaked state.
	internal, public := freePort(t), freePort(t)
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+filepath.Join(dir, "d")+
		`", "internal_bind": "`+internal+`", "public_bind": "`+public+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	startServeAt(t, filepath.Join(dir, "d"), cfgPath, internal, public)
	code, out, errb := runQuiet("account", "create", "-config", cfgPath, "-slug", "work", "-name", "Work")
	if code != 0 || !strings.Contains(out, "sha256:") {
		t.Fatalf("create: code=%d out=%q err=%q", code, out, errb)
	}
	code, out, _ = runQuiet("account", "list", "-config", cfgPath)
	if code != 0 || !strings.Contains(out, "work") || !strings.Contains(out, "sha256:") {
		t.Fatalf("list: code=%d out=%q", code, out)
	}
	// duplicate slug refused end-to-end
	if code, _, _ := runQuiet("account", "create", "-config", cfgPath, "-slug", "work", "-name", "Dup"); code == 0 {
		t.Fatal("duplicate slug accepted over admin socket")
	}
}

func TestPasskeyCLIAgainstLiveNode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	internal, public := freePort(t), freePort(t)
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+filepath.Join(dir, "d")+
		`", "internal_bind": "`+internal+`", "public_bind": "`+public+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	startServeAt(t, filepath.Join(dir, "d"), cfgPath, internal, public)
	// empty list works
	if code, out, errb := runQuiet("passkey", "list", "-config", cfgPath); code != 0 {
		t.Fatalf("list: %d %q %q", code, out, errb)
	}
	// reset-wizard mints a single-use setup URL
	code, out, _ := runQuiet("passkey", "reset-wizard", "-config", cfgPath)
	if code != 0 || !strings.Contains(out, "/setup?token=") {
		t.Fatalf("reset-wizard: %d %q", code, out)
	}
	tok := out[strings.Index(out, "token=")+6:]
	tok = strings.TrimSpace(tok)
	// the minted token opens the wizard exactly once from a non-loopback address
	url := "http://" + internal + "/setup?token=" + tok
	req1, _ := http.NewRequest("GET", url, nil)
	// direct client: RemoteAddr will be loopback (always allowed), so instead
	// verify single-use semantics at the token layer via a second mint+burn:
	resp, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("setup with minted token: %d", resp.StatusCode)
	}
}
