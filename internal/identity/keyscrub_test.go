package identity

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// H2 (review 2026-09-28). HDTP §9 and rule 5: a leaf's private key is DESTROYED — at expiry, and
// when the person leaves. A DELETE or an UPDATE to NULL takes the row out of the table and leaves
// its bytes on disk: in SQLite's free pages and freed cell space, and in the write-ahead log, until
// something overwrites them. These tests read the database's files, byte for byte, after the key
// is gone and while the store is still open (closing it would checkpoint the log for them).

// sealedKeys is every sealed copy of a key the account holds: each leaf's, and the account's own.
func sealedKeys(t *testing.T, m *Manager, accountID string) [][]byte {
	t.Helper()
	ctx := context.Background()
	leaves, err := m.Store.ListLeaves(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, l := range leaves {
		if len(l.KeySealed) > 0 {
			out = append(out, l.KeySealed)
		}
	}
	if acct, err := m.Store.GetAccountSealedKey(ctx, accountID); err == nil && len(acct) > 0 {
		out = append(out, acct)
	}
	return out
}

// residue names each sealed key a fragment of which (24 bytes at any 24-byte boundary of it) is
// still in the database file or its write-ahead log.
func residue(t *testing.T, dbPath string, keys [][]byte) []string {
	t.Helper()
	var found []string
	for _, f := range []string{dbPath, dbPath + "-wal"} {
		disk, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		for i, k := range keys {
			for off := 0; off+24 <= len(k); off += 24 {
				if bytes.Contains(disk, k[off:off+24]) {
					found = append(found, filepath.Base(f)+": key "+string(rune('A'+i)))
					break
				}
			}
		}
	}
	return found
}

func scrubEnv(t *testing.T) (*Manager, store.Account, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scrub.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	a, err := m.CreateAccount(context.Background(), "alina", "Alina Rao", AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	return m, a, path
}

func TestALeaveLeavesNoLeafKeyOnDisk(t *testing.T) {
	m, a, path := scrubEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	for _, purpose := range []string{PurposeSignup, PurposeRenew} {
		csr, err := m.IssueCSR(ctx, a.ID, purpose, endpointA, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
	}
	keys := sealedKeys(t, m, a.ID)
	if len(keys) != 3 { // the current leaf's, the superseded leaf's, the account's copy
		t.Fatalf("want three sealed keys before the leave, have %d", len(keys))
	}
	if got := residue(t, path, keys); len(got) == 0 {
		t.Fatal("the scan finds no key while the keys are live: it is looking at nothing")
	}
	if _, err := m.Leave(ctx, a.ID, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if got := residue(t, path, keys); len(got) > 0 {
		t.Fatalf("after the leave, sealed leaf keys are still on disk: %v", got)
	}
}

func TestARetiredLeafKeyIsNotLeftOnDisk(t *testing.T) {
	m, a, path := scrubEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	csr, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 1), now); err != nil {
		t.Fatal(err)
	}
	keys := sealedKeys(t, m, a.ID)
	if len(keys) != 2 {
		t.Fatalf("want two sealed keys, have %d", len(keys))
	}
	retired, err := m.RetireExpiredLeafKeys(ctx, a.ID, now.Add(49*time.Hour))
	if err != nil || len(retired) != 1 {
		t.Fatalf("retire: %v %v", retired, err)
	}
	if got := residue(t, path, keys); len(got) > 0 {
		t.Fatalf("after its leaf expired, the key is still on disk: %v", got)
	}
}
