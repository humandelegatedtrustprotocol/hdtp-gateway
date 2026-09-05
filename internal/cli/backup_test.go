package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/audit"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// AC: backup → wipe → restore round-trip — accounts, the audit chain (still
// verifying), blobs and the master key all come back.
func TestBackupRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "data")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := run(t, "migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate: %s", errb)
	}
	// populate: an account, audit rows, a blob, the master key
	st, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	w := &audit.Writer{Sink: st, Now: func() time.Time { return time.Unix(1756000000, 0) }}
	for i := 0; i < 3; i++ {
		if err := w.Append(ctx, a.ID, "owner", "o1", "settings_update", "account:me", "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	if _, err := core.OpenKeyring(filepath.Join(dataDir, "keyring.key"), func(string) (string, bool) { return "", false }); err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.ReadFile(filepath.Join(dataDir, "keyring.key"))
	if err := os.MkdirAll(filepath.Join(dataDir, "blobs", "ab"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "blobs", "ab", "abcdef"), []byte("media-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(dir, "backup.tar.gz")
	code, out, errb := run(t, "backup", "create", "-config", cfgPath, "-out", archive)
	if code != 0 || !strings.Contains(out, "backup written") {
		t.Fatalf("create: code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(out, "warning: the archive contains keyring.key") {
		t.Fatal("key-in-archive warning missing")
	}

	// wipe everything
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	// restore refuses to clobber an existing store without -yes; on an empty
	// dir it just proceeds
	if code, _, errb := run(t, "backup", "restore", "-config", cfgPath, "-from", archive); code != 0 {
		t.Fatalf("restore: %s", errb)
	}
	if code, _, errb := run(t, "migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate after restore: %s", errb)
	}

	st2, err := store.OpenSQLite(filepath.Join(dataDir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if got, err := st2.GetAccountByID(ctx, a.ID); err != nil || got.Slug != "me" {
		t.Fatalf("account lost: %+v %v", got, err)
	}
	if code, out, _ := run(t, "audit", "verify", "-config", cfgPath); code != 0 || !strings.Contains(out, "3 events, intact") {
		t.Fatalf("audit chain after restore: %d %q", code, out)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, "blobs", "ab", "abcdef")); err != nil || string(b) != "media-bytes" {
		t.Fatalf("blob lost: %v", err)
	}
	if keyAfter, _ := os.ReadFile(filepath.Join(dataDir, "keyring.key")); string(keyAfter) != string(keyBefore) {
		t.Fatal("master key not restored byte-for-byte")
	}
	// a second restore over the live store is refused without -yes
	if code, _, errb := run(t, "backup", "restore", "-config", cfgPath, "-from", archive); code == 0 || !strings.Contains(errb, "-yes") {
		t.Fatalf("overwrite without -yes: code=%d err=%q", code, errb)
	}
	if code, _, _ := run(t, "backup", "restore", "-config", cfgPath, "-from", archive, "-yes"); code != 0 {
		t.Fatal("restore with -yes failed")
	}
}

func TestBackupWithoutMasterKeyAndRefusalsWhileRunning(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "data")
	_ = os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+`"}`), 0o600)
	if code, _, errb := run(t, "migrate", "-config", cfgPath); code != 0 {
		t.Fatalf("migrate: %s", errb)
	}
	archive := filepath.Join(dir, "nokey.tar.gz")
	code, out, errb := run(t, "backup", "create", "-config", cfgPath, "-out", archive, "-without-master-key")
	if code != 0 || strings.Contains(out, "warning: the archive contains") {
		t.Fatalf("without key: code=%d out=%q err=%q", code, out, errb)
	}
	// a running node holds the lock: both directions refuse
	lock, err := core.AcquireLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if code, _, errb := run(t, "backup", "create", "-config", cfgPath, "-out", archive); code == 0 || !strings.Contains(errb, "in use") {
		t.Fatalf("create under lock: %d %q", code, errb)
	}
	if code, _, errb := run(t, "backup", "restore", "-config", cfgPath, "-from", archive, "-yes"); code == 0 || !strings.Contains(errb, "in use") {
		t.Fatalf("restore under lock: %d %q", code, errb)
	}
}
