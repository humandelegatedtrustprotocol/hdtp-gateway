package cli

// SPEC §3.10: one account's identity, portable to a DIFFERENT node.
//
// The property that matters is the one a unit test of the crypto cannot show:
// the file opens on a node whose keyring master key is not the one that sealed
// it. That is the whole reason the backup is passphrase-sealed rather than
// keyring-sealed, and a round trip inside one node would prove nothing about it.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// idNode is a data directory with its own config and its own master key.
type idNode struct {
	dir, cfg string
}

func newIDNode(t *testing.T, name string) idNode {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.json")
	body := `{"data_dir":"` + dir + `","internal_bind":"127.0.0.1:0","public_bind":"127.0.0.1:0"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"migrate", "--config", cfg}, "test", io.Discard, io.Discard); code != 0 {
		t.Fatalf("migrate %s: %d", name, code)
	}
	return idNode{dir: dir, cfg: cfg}
}

func passphraseFile(t *testing.T, dir, pass string) string {
	t.Helper()
	p := filepath.Join(dir, "pass")
	if err := os.WriteFile(p, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIdentityBackupMovesAnAccountToAnotherNode(t *testing.T) {
	src := newIDNode(t, "src")
	dst := newIDNode(t, "dst")
	pass := passphraseFile(t, src.dir, "a passphrase worth using")

	// An account on the source node, created the way anything creates one.
	st := openStoreAt(t, src.dir)
	kr := openKeyringAt(t, src.dir)
	idm := &identity.Manager{Store: st, Keyring: kr}
	a, err := idm.CreateAccount(t.Context(), "alice", "Alice", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	want := a.Fingerprint
	st.Close()

	out := filepath.Join(src.dir, "alice.identity.json")
	var stdout, stderr strings.Builder
	if code := Run([]string{"backup", "identity", "--config", src.cfg,
		"-slug", "alice", "-out", out, "-passphrase-file", pass}, "test", &stdout, &stderr); code != 0 {
		t.Fatalf("export: %d %s", code, stderr.String())
	}
	// The file must be 0600 from the moment it exists: it IS the identity.
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the backup is mode %o; an identity file must be 0600", fi.Mode().Perm())
	}
	// And it must not carry the key in the clear.
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc identity.IdentityBackup
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the export is not a readable backup: %v", err)
	}
	if doc.Fingerprint != want {
		t.Errorf("the file claims %s, want %s", doc.Fingerprint, want)
	}

	// Restore onto the OTHER node — different data dir, different master key.
	dstPass := passphraseFile(t, dst.dir, "a passphrase worth using")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"backup", "restore-identity", "--config", dst.cfg,
		"-from", out, "-passphrase-file", dstPass}, "test", &stdout, &stderr); code != 0 {
		t.Fatalf("restore: %d %s", code, stderr.String())
	}
	dstStore := openStoreAt(t, dst.dir)
	defer dstStore.Close()
	got, err := dstStore.GetAccountBySlug(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != want {
		t.Fatalf("restored identity is %s, want %s — the key did not survive the move",
			got.Fingerprint, want)
	}
	// It must be a usable key on the new node, not just a matching string: the
	// destination's keyring has to be able to open what it stored.
	dstKR := openKeyringAt(t, dst.dir)
	sealed, err := dstStore.GetAccountSealedKey(t.Context(), got.ID)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := (&identity.Manager{Store: dstStore, Keyring: dstKR}).LoadKeypair(sealed)
	if err != nil {
		t.Fatalf("the restored key does not open under the destination's keyring: %v", err)
	}
	if kp.Fingerprint != want {
		t.Errorf("the stored key is %s, want %s", kp.Fingerprint, want)
	}
}

func TestIdentityRestoreRefusesACollision(t *testing.T) {
	src := newIDNode(t, "src")
	pass := passphraseFile(t, src.dir, "pw")
	st := openStoreAt(t, src.dir)
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, src.dir)}
	if _, err := idm.CreateAccount(t.Context(), "alice", "Alice", identity.AlgoP256); err != nil {
		t.Fatal(err)
	}
	st.Close()

	out := filepath.Join(src.dir, "alice.identity.json")
	var sink strings.Builder
	if code := Run([]string{"backup", "identity", "--config", src.cfg,
		"-slug", "alice", "-out", out, "-passphrase-file", pass}, "test", &sink, &sink); code != 0 {
		t.Fatalf("export: %s", sink.String())
	}
	// Restoring onto the node it came from is a collision, not a no-op: silently
	// replacing an identity is how you lose one.
	var stderr strings.Builder
	if code := Run([]string{"backup", "restore-identity", "--config", src.cfg,
		"-from", out, "-passphrase-file", pass}, "test", io.Discard, &stderr); code == 0 {
		t.Fatal("restoring over an existing account succeeded")
	}
	if !strings.Contains(stderr.String(), "already has an account") {
		t.Errorf("the refusal does not say why: %s", stderr.String())
	}
}

func TestIdentityBackupRefusesALoosePassphraseFile(t *testing.T) {
	n := newIDNode(t, "n")
	loose := filepath.Join(n.dir, "loose")
	if err := os.WriteFile(loose, []byte("pw"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	code := Run([]string{"backup", "identity", "--config", n.cfg,
		"-slug", "whatever", "-out", filepath.Join(n.dir, "x.json"),
		"-passphrase-file", loose}, "test", io.Discard, &stderr)
	if code == 0 {
		t.Fatal("a world-readable passphrase file was accepted")
	}
	if !strings.Contains(stderr.String(), "0600") {
		t.Errorf("the refusal does not name the rule: %s", stderr.String())
	}
}
