package cli

// backup create|restore (PLAN P5-04): a consistent offline snapshot of the
// data dir — SQLite via `VACUUM INTO` (a transactionally consistent copy),
// the content-addressed blob tree, and by default the keyring master key —
// packed into one tar.gz with a manifest. Both directions hold the data-dir
// lock, so they refuse while the node serves. Postgres stores are external:
// the archive carries blobs + key and the operator runs pg_dump/psql.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/tech-sumit/pact-gateway/internal/core"
)

const (
	backupDB       = "pact.db"
	backupKey      = "keyring.key"
	backupBlobs    = "blobs"
	backupManifest = "MANIFEST.json"
)

type backupManifestDoc struct {
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	StoreEngine string    `json:"store_engine"`
	HasKey      bool      `json:"has_master_key"`
	Tool        string    `json:"tool"`
	// KeyringID names the master key the archive's key columns are sealed
	// under (a hash, never the key). A node whose keyring is another one is
	// importing another host's archive, and PACT §9 says such an import
	// carries data and no key material: restore refuses the keys unless told
	// -data-only, which strips them.
	KeyringID string `json:"keyring_id,omitempty"`
}

// keyringID hashes the master key the way both create and restore read it —
// the environment first, then the file — so the two sides agree; "" when the
// node has none yet.
func keyringID(cfg *core.Config) string {
	if v, ok := os.LookupEnv("PACT_MASTER_KEY"); ok && v != "" {
		return hashKeyring([]byte(v))
	}
	b, err := os.ReadFile(masterKeyPath(cfg))
	if err != nil || len(b) == 0 {
		return ""
	}
	return hashKeyring(b)
}

func hashKeyring(b []byte) string {
	sum := sha256.Sum256(append([]byte("pact-keyring-id/"), strings.TrimSpace(string(b))...))
	return hex.EncodeToString(sum[:8])
}

func backupCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway backup <create|restore|identity|restore-identity> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath, out, from, slug, passFile string
	var withoutKey, yes, dataOnly, sameNode bool
	fs := commonFlags("backup "+sub, &cfgPath, stderr)
	fs.BoolVar(&dataOnly, "data-only", false, "restore: import another host's archive — the data comes in, every key in it is refused (PACT §9)")
	fs.BoolVar(&sameNode, "same-node", false, "restore: this is your own node's archive restored onto a fresh machine — its master key and sealed keys are taken as yours")
	fs.StringVar(&out, "out", "", "create|identity: path to write")
	fs.StringVar(&from, "from", "", "restore|restore-identity: path to read")
	fs.StringVar(&slug, "slug", "", "identity: which account to back up")
	fs.StringVar(&passFile, "passphrase-file", "",
		"identity|restore-identity: 0600 file holding the passphrase (or set "+passphraseEnv+")")
	fs.BoolVar(&withoutKey, "without-master-key", false, "create: leave keyring.key out of the archive")
	fs.BoolVar(&yes, "yes", false, "restore: overwrite an existing store")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "backup:", err)
		return 1
	}
	// a restore onto a fresh machine has no data dir yet; the lock lives there
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "backup:", err)
		return 1
	}
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, "backup:", err)
		return 1
	}
	defer lock.Release()
	switch sub {
	case "identity":
		// One account's keypair, sealed under a passphrase and portable to
		// another node (SPEC §3.10). Not `create`, which is the whole node under
		// the node's OWN master key and therefore only restorable beside it.
		return exportIdentity(cfg, slug, out, passFile, stdout, stderr)
	case "restore-identity":
		return restoreIdentity(cfg, from, passFile, stdout, stderr)
	case "create":
		if out == "" {
			fmt.Fprintln(stderr, "backup create: -out is required")
			return 2
		}
		n, err := backupCreate(cfg, out, !withoutKey)
		if err != nil {
			fmt.Fprintln(stderr, "backup:", err)
			return 1
		}
		fmt.Fprintf(stdout, "backup written: %s (%d entries)\n", out, n)
		if cfg.StoreEngine == "postgres" {
			fmt.Fprintln(stdout, "note: store_engine is postgres — dump the database separately with pg_dump; this archive holds blobs + master key only")
		}
		if !withoutKey {
			fmt.Fprintln(stdout, "warning: the archive contains keyring.key — it IS every account's identity; store it as securely as the node")
		}
		return 0
	case "restore":
		if from == "" {
			fmt.Fprintln(stderr, "backup restore: -from is required")
			return 2
		}
		if _, err := os.Stat(filepath.Join(cfg.DataDir, backupDB)); err == nil && !yes {
			fmt.Fprintln(stderr, "backup restore: data dir already holds a store; pass -yes to overwrite it")
			return 1
		}
		n, err := backupRestore(cfg, from, dataOnly, sameNode)
		if err != nil {
			fmt.Fprintln(stderr, "backup:", err)
			return 1
		}
		fmt.Fprintf(stdout, "restored %d entries into %s\nnext: pact-gateway migrate, then serve\n", n, cfg.DataDir)
		if dataOnly {
			fmt.Fprintln(stdout, "keys were not imported: each account needs a leaf from its wallet before it serves (account csr -purpose renew, then install-leaf)")
		}
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway backup <create|restore|identity|restore-identity> [flags]")
		return 2
	}
}

// snapshotSQLite copies the live database consistently with VACUUM INTO.
func snapshotSQLite(dbPath, dst string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(context.Background(), "VACUUM INTO ?", dst)
	return err
}

func masterKeyPath(cfg *core.Config) string {
	if cfg.MasterKeyFile != "" {
		return cfg.MasterKeyFile
	}
	return filepath.Join(cfg.DataDir, backupKey)
}

func backupCreate(cfg *core.Config, out string, withKey bool) (int, error) {
	tmp, err := os.MkdirTemp("", "pact-backup-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)

	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	entries := 0
	add := func(name string, mode int64, r io.Reader, size int64) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: size, ModTime: time.Now()}); err != nil {
			return err
		}
		if _, err := io.Copy(tw, r); err != nil {
			return err
		}
		entries++
		return nil
	}
	addFile := func(name, path string, mode int64) error {
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		fh, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fh.Close()
		return add(name, mode, fh, st.Size())
	}

	man := backupManifestDoc{Version: 1, CreatedAt: time.Now().UTC(), StoreEngine: cfg.StoreEngine, HasKey: withKey, Tool: "pact-gateway", KeyringID: keyringID(cfg)}
	mb, _ := json.MarshalIndent(man, "", "  ")
	if err := add(backupManifest, 0o600, strings.NewReader(string(mb)), int64(len(mb))); err != nil {
		return 0, err
	}
	if cfg.StoreEngine != "postgres" {
		dbPath := filepath.Join(cfg.DataDir, backupDB)
		if _, err := os.Stat(dbPath); err != nil {
			return 0, fmt.Errorf("no store at %s (run migrate first?)", dbPath)
		}
		snap := filepath.Join(tmp, backupDB)
		if err := snapshotSQLite(dbPath, snap); err != nil {
			return 0, fmt.Errorf("sqlite snapshot: %w", err)
		}
		if err := addFile(backupDB, snap, 0o600); err != nil {
			return 0, err
		}
	}
	if withKey {
		if err := addFile(backupKey, masterKeyPath(cfg), 0o600); err != nil {
			return 0, fmt.Errorf("master key: %w", err)
		}
	}
	blobRoot := filepath.Join(cfg.DataDir, backupBlobs)
	if st, err := os.Stat(blobRoot); err == nil && st.IsDir() {
		err := filepath.Walk(blobRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(cfg.DataDir, path)
			return addFile(filepath.ToSlash(rel), path, 0o600)
		})
		if err != nil {
			return 0, err
		}
	}
	return entries, nil
}

func backupRestore(cfg *core.Config, from string, dataOnly, sameNode bool) (int, error) {
	// Stripping keys means rewriting the restored SQLite file. On a Postgres node
	// there is no such file — `backup create` skips the database there — so the
	// strip would open an empty one and fail "no such table: accounts" AFTER the
	// blobs were restored, and the keys it meant to strip were never in the
	// archive to begin with. Refused with the two ways forward.
	if dataOnly && cfg.StoreEngine == "postgres" {
		return 0, errors.New(
			"backup restore -data-only is for a SQLite node: this node stores in Postgres, where the archive carries no database " +
				"(and so no keys). Import the data with pg_restore, or run the restore on the SQLite node that made the archive")
	}
	// The manifest first, before anything is wiped: an archive from another
	// host is refused whole unless the caller asked for its data alone.
	man, err := readBackupManifest(from)
	if err != nil {
		return 0, err
	}
	// Foreign unless proven otherwise: the manifest's keyring id is the former
	// host's to omit, and a fresh node has no keyring to compare with — both
	// used to read as "safe" and let the archive's master key and every sealed
	// key land here, which is exactly what PACT §9 forbids a host to take.
	if !dataOnly && !sameNode {
		local := keyringID(cfg)
		if man.KeyringID == "" || local == "" || man.KeyringID != local {
			return 0, fmt.Errorf("this archive is treated as another node's: it was not proven to be this node's own (the archive's keyring id %q, this node's %q); "+
				"a host importing another host's archive takes the data and none of the keys (PACT §9) — restore with -data-only, "+
				"or with -same-node when this is your own node's archive restored onto a fresh machine",
				short(man.KeyringID), short(local))
		}
	}
	f, err := os.Open(from)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("not a pact backup (gzip): %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return 0, err
	}
	// wipe the store + blobs first so a partial old state cannot leak through
	_ = os.Remove(filepath.Join(cfg.DataDir, backupDB))
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		_ = os.Remove(filepath.Join(cfg.DataDir, backupDB+suffix))
	}
	_ = os.RemoveAll(filepath.Join(cfg.DataDir, backupBlobs))
	entries := 0
	sawManifest := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		name := filepath.Clean(h.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return 0, fmt.Errorf("refusing archive entry %q", h.Name)
		}
		switch {
		case name == backupManifest:
			var man backupManifestDoc
			if err := json.NewDecoder(tr).Decode(&man); err != nil || man.Tool != "pact-gateway" {
				return 0, fmt.Errorf("not a pact backup: bad manifest")
			}
			sawManifest = true
			continue
		case name == backupKey:
			if dataOnly {
				continue // the other host's master key never lands here
			}
			if err := writeEntry(masterKeyPath(cfg), tr, 0o600); err != nil {
				return 0, err
			}
		case name == backupDB || strings.HasPrefix(name, backupBlobs+string(filepath.Separator)) || strings.HasPrefix(name, backupBlobs+"/"):
			if err := writeEntry(filepath.Join(cfg.DataDir, name), tr, 0o600); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("refusing unexpected archive entry %q", h.Name)
		}
		entries++
	}
	if !sawManifest {
		return 0, fmt.Errorf("not a pact backup: manifest missing")
	}
	if dataOnly {
		if err := stripKeys(filepath.Join(cfg.DataDir, backupDB)); err != nil {
			return 0, fmt.Errorf("stripping key material: %w", err)
		}
	}
	return entries, nil
}

// readBackupManifest reads MANIFEST.json out of an archive without touching
// the data directory.
func readBackupManifest(from string) (backupManifestDoc, error) {
	f, err := os.Open(from)
	if err != nil {
		return backupManifestDoc{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return backupManifestDoc{}, fmt.Errorf("not a pact backup (gzip): %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return backupManifestDoc{}, fmt.Errorf("not a pact backup: manifest missing")
		}
		if err != nil {
			return backupManifestDoc{}, err
		}
		if filepath.Clean(h.Name) == backupManifest {
			var man backupManifestDoc
			if err := json.NewDecoder(tr).Decode(&man); err != nil || man.Tool != "pact-gateway" {
				return backupManifestDoc{}, fmt.Errorf("not a pact backup: bad manifest")
			}
			return man, nil
		}
	}
}

// stripKeys removes every sealed key from a restored store: the accounts'
// keys, a rotation's retiring key, and the leaf ledger's keys — the ledger
// rows stay, as former leaves, so an envelope sealed to one is answered
// certificate_renewed once the wallet has issued a leaf here (PACT §14.4).
func stripKeys(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()
	for _, stmt := range []string{
		"UPDATE accounts SET key_sealed = NULL, prev_key_sealed = NULL, prev_fingerprint = NULL, grace_until = 0",
		"UPDATE leaves SET key_sealed = NULL, state = 'former' WHERE state IN ('current', 'superseded', 'pending')",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func writeEntry(path string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, r)
	return err
}

// short abbreviates a keyring id for a message; "" stays "".
func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}
