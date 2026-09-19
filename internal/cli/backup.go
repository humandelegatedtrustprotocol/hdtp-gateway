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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
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
		fmt.Fprintln(stderr, "usage: pact-gateway backup <create|restore> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	// Before the flags, the data directory and the lock: a verb this command does not have
	// should cost nothing, and until now it made the directory and took the lock first.
	if sub != "create" && sub != "restore" {
		fmt.Fprintln(stderr, "usage: pact-gateway backup <create|restore> [flags]")
		return 2
	}
	var cfgPath, out, from string
	var withoutKey, yes, dataOnly, sameNode bool
	fs := commonFlags("backup "+sub, &cfgPath, stderr)
	fs.BoolVar(&dataOnly, "data-only", false, "restore: import another host's archive — the data comes in, every key in it is refused (PACT §9)")
	fs.BoolVar(&sameNode, "same-node", false, "restore: this is your own node's archive restored onto a fresh machine — its master key is taken as yours (it unseals saved settings and integration credentials; no leaf key is in an archive)")
	fs.StringVar(&out, "out", "", "create: path to write")
	fs.StringVar(&from, "from", "", "restore: path to read")
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
	// There is no `backup identity`. It exported one account's keypair under a passphrase,
	// "portable to another node" — which is the one thing a leaf's key must never be. A leaf is
	// the person's root entrusting THIS host for one address until one date; whoever else holds
	// its key can speak as this host from that address. Moving to another node is the wallet
	// issuing that node a leaf of its own (`account csr -purpose move`), and the key never travels.
	if sub == "create" {
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
			fmt.Fprintln(stdout, "warning: the archive contains keyring.key — it unseals this node's saved settings and integration credentials; store it as securely as the node. It holds no identity: that is the root in your wallet, and no leaf key is in this archive")
		}
		return 0
	}
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
	// Said on every restore now, because it is true of every restore: a leaf's key never
	// travels, so a restored identity is one the wallet has to certify again.
	fmt.Fprintln(stdout, "keys were not imported: no archive carries a leaf key, so each account needs a leaf from its wallet before it is served — `serve` names each one and the command that asks for it")
	return 0
}

// snapshotWithoutLeafKeys writes the copy of the database that goes into a bundle: everything
// the node holds EXCEPT the private keys of its leaves.
//
// A leaf is the person's root entrusting THIS host, for ONE address, until ONE date (PACT §2).
// Its private key is therefore not the person's data — it is the host's credential. A bundle
// that carries it lets whoever holds the bundle speak as this host from this address until the
// leaf runs out, and a message sent that way says "this came from the host the person chose"
// when it did not. Nothing about restoring or moving needs it: a wallet issues a fresh leaf to
// whoever serves next, which is what makes renewal cheap. So the keys never enter the archive,
// and a restored node awaits a leaf and says so.
//
// This used to copy the whole database — `accounts.key_sealed` and `leaves.key_sealed` included
// — beside the master key that unseals them, which made every backup a complete credential. The
// only protection was on the importer's side (`restore -data-only`), which is no protection
// against somebody who simply has the file.
//
// Three steps, and the third is not optional. The first copy is consistent; the second removes
// the keys; but an UPDATE to NULL leaves the old bytes in the file's free pages, and in a bundle
// the master key that unseals them sits beside it. `Snapshot` REBUILDS — live rows only, no free
// pages — so the final copy is made from the stripped one, and the intermediate is removed.
func snapshotWithoutLeafKeys(ctx context.Context, dbPath, dst string) error {
	live, err := store.OpenSQLite(dbPath)
	if err != nil {
		return err
	}
	defer live.Close()
	withKeys := dst + ".withkeys"
	if err := live.Snapshot(ctx, withKeys); err != nil {
		return err
	}
	defer os.Remove(withKeys)
	stripped, err := store.OpenSQLite(withKeys)
	if err != nil {
		return err
	}
	if err := stripped.StripKeys(ctx); err != nil {
		stripped.Close()
		return fmt.Errorf("removing leaf keys from the copy: %w", err)
	}
	err = stripped.Snapshot(ctx, dst)
	stripped.Close()
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
		if err := snapshotWithoutLeafKeys(context.Background(), dbPath, snap); err != nil {
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
	// used to read as "safe" and let another host's master key land here, which
	// PACT §9 forbids a host to take. (A leaf key is no longer in question: no
	// archive carries one, and the restore strips the columns regardless.)
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
	// Every restore ends with a keyless store, whoever made the archive and whenever. A bundle
	// made by this build carries no leaf key to begin with; one made before 2026-09-19 carries
	// both `key_sealed` columns, and the rule that a leaf's key never leaves the host it was
	// issued to must not depend on the age of the file. What `-data-only` and `-same-node` still
	// decide is whether the archive's MASTER key is taken — it also seals settings and integration
	// credentials, which a node restoring itself wants back and a node importing a stranger does
	// not. Postgres nodes archive no database, so there is nothing here to strip.
	if cfg.StoreEngine != "postgres" {
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

// stripKeys removes every sealed key from a restored store, leaving the leaf ledger's rows in
// place as former leaves so an envelope sealed to one is answered certificate_renewed once the
// wallet has issued a leaf here (PACT §14.4).
//
// The archive's database is whatever age its source node was, and an old one can still carry
// `accounts.prev_key_sealed` — a sealed private key from a 1.x rotation that was in flight. So the
// restored store is MIGRATED FIRST and stripped second. Migration 0031 destroys that column, after
// which the only key material left is in the two columns the current schema names, and
// `Store.StripKeys` removes it through two static sqlc queries.
//
// That ordering is what keeps this free of hand-written SQL. It used to name columns in a fixed
// UPDATE, which fails on any archive newer than the column it names; a rewrite then read the
// archive's own schema and built statements from its column names — dynamic SQL over a file
// somebody else supplied. Neither is needed once the schema is known, and migrating makes it known.
func stripKeys(dbPath string) error {
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("bringing the restored store to the current schema: %w", err)
	}
	return st.StripKeys(ctx)
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
