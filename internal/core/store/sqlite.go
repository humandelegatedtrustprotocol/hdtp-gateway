package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/pact-cloud/pact-gateway/internal/core/store/sqlitedb"
	"github.com/pact-cloud/pact-gateway/migrations"
)

// SQLite is the default engine (SPEC §11.1): pure Go driver, one file, WAL mode,
// foreign keys ON (SQLite leaves them off unless asked — the schema relies on them).
//
// The rest of how it is opened was measured against a store of a million messages
// (scale_test.go; the numbers are in docs/release/round2-2026-09-19-plan.md, R7), one setting at a time:
//
//   - `_txlock=immediate`. Every transaction this store opens writes. SQLite's default starts one as
//     a reader and upgrades it at the first write, and an upgrade that meets another writer fails at
//     once — `busy_timeout` does not apply to it. With four writers, 87 of every 100 read-then-write
//     transactions failed; taking the write lock at BEGIN, none did.
//   - Four connections, kept. Parallel reads were 2.2 times faster through four than through an
//     unbounded pool, and slower again at eight and sixteen: past four the connections contend
//     with each other, and an unbounded pool also closes and reopens the file under every burst.
//   - `synchronous` stays FULL, SQLite's default. NORMAL made a write 1.3 to 3 times faster and was
//     declined: under WAL it cannot corrupt the file, but a power cut can take the last commits
//     with it, and a commit here is a message a peer was told was DELIVERED — they will not send
//     it again — or a row of an audit chain whose head may already be anchored elsewhere.
//   - Left at their defaults because they bought nothing measurable: `cache_size` (16 and 64 MiB
//     were within noise of 2 MiB), and `ANALYZE`/`PRAGMA optimize` (no plan or number changed).
//     `mmap_size` made parallel reads a third faster and was declined as well: an I/O error on a
//     mapped file is a signal that kills the process, not an error a statement returns.
//   - `secure_delete` ON. A leaf's private key MUST be destroyed at expiry and when the person
//     leaves (PACT §9, SPEC §3.9), and a DELETE does not destroy bytes: SQLite leaves a deleted
//     row's content in freed cell space and on free pages until something reuses them. With
//     secure_delete it overwrites them with zeros as it frees them. What the write-ahead log still
//     holds is Scrub's to clear.
type SQLite struct {
	db   *sql.DB
	path string
	q    *sqlitedb.Queries
	// inTx marks the copy Atomically hands to its callback: its `q` is a transaction already.
	inTx bool
}

var _ Store = (*SQLite)(nil)

// sqliteConns is the size of the connection pool, and the number kept open. See the type's comment.
const sqliteConns = 4

func OpenSQLite(path string) (*SQLite, error) {
	dsn := fmt.Sprintf("file:%s?_txlock=immediate&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)&_pragma=secure_delete(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	db.SetMaxOpenConns(sqliteConns)
	db.SetMaxIdleConns(sqliteConns)
	return &SQLite{db: db, path: path, q: sqlitedb.New(db)}, nil
}

// Scrub makes what this store has deleted unreadable from its own files. secure_delete zeroes a
// deleted row in the database file as the row is freed; the write-ahead log still holds every
// page image written since the last checkpoint, the deleted row's among them. Scrub checkpoints
// the log into the database and truncates it to nothing (`wal_checkpoint(TRUNCATE)`), and proves it by the log's
// size: a checkpoint another connection's reader kept from finishing leaves the log whole, and
// that is an error, never a success.
//
// sqlc cannot express a PRAGMA (its SQLite grammar drops the statement), and the store runs no
// statement by hand (TestNoHandWrittenSQLOutsideTheStore). So the checkpoint is a connection
// setting, exactly as journal_mode and secure_delete are above: a connection of its own is opened
// with the pragma in its DSN, which the driver runs as the connection opens, and closed.
func (s *SQLite) Scrub(ctx context.Context) error {
	if s.inTx {
		return fmt.Errorf("store: scrub inside a transaction: the checkpoint would wait on this transaction's own lock")
	}
	if s.path == "" || s.path == ":memory:" {
		return nil
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=secure_delete(1)&_pragma=wal_checkpoint(TRUNCATE)", s.path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("store: scrub: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("store: scrub: %w", err)
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("store: scrub: %w", err)
	}
	fi, err := os.Stat(s.path + "-wal")
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return fmt.Errorf("store: scrub: %w", err)
	case fi.Size() != 0:
		return fmt.Errorf("store: scrub: the write-ahead log still holds %d bytes: a reader kept the checkpoint from finishing, and deleted rows may be in it until the next scrub", fi.Size())
	}
	return nil
}

// Atomically runs fn on a copy of this store whose queries all go through one transaction. Every
// method of the store reaches the database through `s.q`, so re-pointing `q` at the transaction is
// the whole of it — no method has a second, transactional spelling to keep in step.
func (s *SQLite) Atomically(ctx context.Context, fn func(tx Store) error) error {
	if s.inTx {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(&SQLite{db: s.db, path: s.path, q: s.q.WithTx(tx), inTx: true}); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// ErrNotFound is what a store method returns when the row asked for is not there, on either
// engine. It IS `sql.ErrNoRows` — the same value, so every `errors.Is(err, sql.ErrNoRows)` written
// before this name existed still holds — and it exists so that a caller outside this package can
// ask the question without importing `database/sql`, which `TestNoHandWrittenSQLOutsideTheStore`
// forbids everywhere else: a package that can name the driver's types can write a statement.
var ErrNotFound = sql.ErrNoRows

func (s *SQLite) Migrate(ctx context.Context) error {
	p, err := s.provider()
	if err != nil {
		return err
	}
	if _, err = p.Up(ctx); err != nil {
		return err
	}
	return fillLeafFingerprints(ctx, s.q.ListContactLeafKeysUnfilled, func(ctx context.Context, fpr sql.NullString, id string) error {
		return s.q.SetContactLeafFingerprint(ctx, sqlitedb.SetContactLeafFingerprintParams{LeafFingerprint: fpr, ID: id})
	})
}

func (s *SQLite) SchemaCurrent(ctx context.Context) error {
	p, err := s.provider()
	if err != nil {
		return err
	}
	return schemaCurrent(ctx, p)
}

// schemaCurrent is SchemaCurrent over either engine's migrations.
func schemaCurrent(ctx context.Context, p *goose.Provider) error {
	current, target, err := p.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("store: schema version: %w", err)
	}
	switch {
	case current < target:
		return fmt.Errorf("store: the schema is at version %d and this binary needs %d: it has not been migrated", current, target)
	case current > target:
		return fmt.Errorf("store: the schema is at version %d, newer than this binary's %d: a newer pact-gateway migrated it", current, target)
	}
	return nil
}

// MigrateDown rolls back everything; exists for the up/down/up cleanliness check.
func (s *SQLite) MigrateDown(ctx context.Context) error {
	p, err := s.provider()
	if err != nil {
		return err
	}
	_, err = p.DownTo(ctx, 0)
	return err
}

func (s *SQLite) provider() (*goose.Provider, error) {
	sub, err := fs.Sub(migrations.SQLite, "sqlite")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.db, sub)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return p, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand failure is unrecoverable
	}
	return hex.EncodeToString(b)
}

func now() int64 { return time.Now().Unix() }

func (s *SQLite) CreateOwnerWithID(ctx context.Context, id, displayName string) (Owner, error) {
	if id == "" {
		id = newID()
	}
	o := Owner{ID: id, DisplayName: displayName, CreatedAt: now()}
	err := s.q.InsertOwner(ctx, sqlitedb.InsertOwnerParams{ID: o.ID, DisplayName: o.DisplayName, CreatedAt: o.CreatedAt})
	return o, err
}

func (s *SQLite) InsertCredential(ctx context.Context, c Credential) error {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = now()
	}
	return s.q.InsertCredential(ctx, sqlitedb.InsertCredentialParams{
		ID: c.ID, OwnerID: c.OwnerID, Kind: c.Kind, Tag: c.Tag, Data: c.Data, CreatedAt: c.CreatedAt,
	})
}

func (s *SQLite) CountCredentialsByKind(ctx context.Context, kind string) (int64, error) {
	return s.q.CountCredentialsByKind(ctx, kind)
}

func (s *SQLite) GetOwner(ctx context.Context, id string) (Owner, error) {
	r, err := s.q.GetOwner(ctx, id)
	if err != nil {
		return Owner{}, err
	}
	return Owner{ID: r.ID, DisplayName: r.DisplayName, CreatedAt: r.CreatedAt}, nil
}

func (s *SQLite) ListOwners(ctx context.Context) ([]Owner, error) {
	rs, err := s.q.ListOwners(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Owner, 0, len(rs))
	for _, r := range rs {
		out = append(out, Owner{ID: r.ID, DisplayName: r.DisplayName, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (s *SQLite) DeleteOwner(ctx context.Context, id string) error {
	n, err := s.q.DeleteOwner(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CreateAccount refuses a slug an identity has vacated while the last leaf issued for it is live
// (ErrAddressVacated, PACT §9). It is here, and not in identity.Manager, because every door that
// creates an account reaches this method and not all of them go through the manager: an import
// (internal/portable) creates its identities in the store's own transaction.
func (s *SQLite) CreateAccount(ctx context.Context, p CreateAccountParams) (Account, error) {
	var out Account
	err := s.Atomically(ctx, func(tx Store) error {
		t := tx.(*SQLite)
		at := now()
		vacated, err := t.LiveVacatedSlug(ctx, p.Slug, at)
		if err != nil {
			return err
		}
		if vacated {
			return ErrAddressVacated
		}
		id := newID()
		if err := t.q.InsertAccount(ctx, sqlitedb.InsertAccountParams{
			ID: id, Slug: p.Slug, DisplayName: p.DisplayName, Algo: p.Algo, CreatedAt: at,
		}); err != nil {
			return err
		}
		r, err := t.q.GetAccount(ctx, id)
		if err != nil {
			return err
		}
		out = accountFromRow(r)
		return nil
	})
	if err != nil {
		return Account{}, err
	}
	return out, nil
}

func (s *SQLite) SetAccountKey(ctx context.Context, accountID, fingerprint string, sealedKey []byte) error {
	n, err := s.q.SetAccountKey(ctx, sqlitedb.SetAccountKeyParams{
		Fingerprint: sql.NullString{String: fingerprint, Valid: true}, KeySealed: sealedKey, ID: accountID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: account %s missing or already keyed", accountID)
	}
	return nil
}

func (s *SQLite) GetAccountByID(ctx context.Context, id string) (Account, error) {
	r, err := s.q.GetAccount(ctx, id)
	if err != nil {
		return Account{}, err
	}
	return accountFromRow(r), nil
}

func (s *SQLite) GetAccountSealedKey(ctx context.Context, id string) ([]byte, error) {
	r, err := s.q.GetAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	// No key is a STATE, not a failure: an account that arrived in a data-only
	// archive holds its root and no key, because a leaf key belongs to the host
	// that issued it (PACT §9). Reporting that as an error made three callers'
	// `len(sealed) == 0` branches unreachable — the node read it as "unavailable"
	// and refused to start when it was the only account, `csr -purpose signup`
	// could not mint a key, and `install-leaf` could not install the first leaf
	// after a move. Each caller decides what an absent key means to it.
	return r.KeySealed, nil
}

func (s *SQLite) GetAccountBySlug(ctx context.Context, slug string) (Account, error) {
	r, err := s.q.GetAccountBySlug(ctx, slug)
	if err != nil {
		return Account{}, err
	}
	return accountFromRow(r), nil
}

func (s *SQLite) ListAccounts(ctx context.Context) ([]Account, error) {
	rs, err := s.q.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(rs))
	for _, r := range rs {
		out = append(out, accountFromRow(r))
	}
	return out, nil
}

func (s *SQLite) AddMembership(ctx context.Context, ownerID, accountID, role string) error {
	return s.q.InsertMembership(ctx, sqlitedb.InsertMembershipParams{OwnerID: ownerID, AccountID: accountID, Role: role})
}

func (s *SQLite) ListMembershipsByOwner(ctx context.Context, ownerID string) ([]Membership, error) {
	rs, err := s.q.ListMembershipsByOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	out := make([]Membership, 0, len(rs))
	for _, r := range rs {
		out = append(out, Membership{OwnerID: r.OwnerID, AccountID: r.AccountID, Role: r.Role})
	}
	return out, nil
}

func (s *SQLite) RemoveMembership(ctx context.Context, ownerID, accountID string) error {
	n, err := s.q.DeleteMembership(ctx, sqlitedb.DeleteMembershipParams{OwnerID: ownerID, AccountID: accountID})
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLite) ListCredentialsByKind(ctx context.Context, kind string) ([]Credential, error) {
	rs, err := s.q.ListCredentialsByKind(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(rs))
	for _, r := range rs {
		out = append(out, Credential{ID: r.ID, OwnerID: r.OwnerID, Kind: r.Kind, Tag: r.Tag, Data: r.Data, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (s *SQLite) RemoveCredentialIfNotLast(ctx context.Context, id, kind string) (bool, error) {
	// The kind is named twice because the statement compares it twice: once to pick
	// the row, once to count the survivors of the same kind.
	n, err := s.q.DeleteCredentialIfNotLast(ctx, sqlitedb.DeleteCredentialIfNotLastParams{ID: id, Kind: kind, Kind_2: kind})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *SQLite) InsertSession(ctx context.Context, id, ownerID string, createdAt, expiresAt int64) error {
	return s.q.InsertSession(ctx, sqlitedb.InsertSessionParams{ID: id, OwnerID: ownerID, CreatedAt: createdAt, ExpiresAt: expiresAt})
}

func (s *SQLite) GetSession(ctx context.Context, id string) (string, int64, error) {
	r, err := s.q.GetSession(ctx, id)
	if err != nil {
		return "", 0, err
	}
	return r.OwnerID, r.ExpiresAt, nil
}

func (s *SQLite) RemoveSession(ctx context.Context, id string) error {
	_, err := s.q.DeleteSession(ctx, id)
	return err
}

func (s *SQLite) InsertToken(ctx context.Context, id, ownerID, label string, hash []byte, accountID string, createdAt int64) error {
	return s.q.InsertToken(ctx, tokenInsert(id, ownerID, label, hash, accountID, createdAt))
}

func (s *SQLite) GetTokenByHash(ctx context.Context, hash []byte) (Token, error) {
	r, err := s.q.GetTokenByHash(ctx, hash)
	if err != nil {
		return Token{}, err
	}
	return tokenFromRow(r), nil
}

func (s *SQLite) ListTokens(ctx context.Context) ([]Token, error) {
	rs, err := s.q.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rs))
	for _, r := range rs {
		out = append(out, tokenFromRow(r))
	}
	return out, nil
}

func (s *SQLite) RevokeToken(ctx context.Context, id string, now int64) error {
	n, err := s.q.RevokeToken(ctx, sqlitedb.RevokeTokenParams{RevokedAt: sql.NullInt64{Int64: now, Valid: true}, ID: id})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: token missing or already revoked")
	}
	return nil
}

func (s *SQLite) InsertAuditEvent(ctx context.Context, seq int64, ts int64, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash string) error {
	return s.q.InsertAuditEvent(ctx, auditInsert(seq, ts, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash))
}

func (s *SQLite) AppendAuditEvent(ctx context.Context, seal func(prevSeq int64, prevHash string) (AuditRow, error)) error {
	// Atomically's transaction begins IMMEDIATE (_txlock): it holds the write lock from the read
	// of the head to the commit, against every connection and every process.
	return s.Atomically(ctx, func(tx Store) error { return appendAudit(ctx, tx, seal) })
}

func (s *SQLite) LastAuditEvent(ctx context.Context) (int64, string, error) {
	r, err := s.q.LastAuditEvent(ctx)
	if err != nil {
		return 0, "", err
	}
	return r.Seq, r.Hash, nil
}

func (s *SQLite) ListAuditEvents(ctx context.Context, actorFilter string) ([]AuditRow, error) {
	var rs []sqlitedb.AuditEvent
	var err error
	if actorFilter != "" {
		rs, err = s.q.ListAuditEventsByActor(ctx, actorFilter)
	} else {
		rs, err = s.q.ListAuditEvents(ctx)
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditRow, 0, len(rs))
	for _, r := range rs {
		out = append(out, auditFromRow(r))
	}
	return out, nil
}

func (s *SQLite) UpsertMoveFanout(ctx context.Context, f MoveFanout) error {
	if f.UpdatedAt == 0 {
		f.UpdatedAt = now()
	}
	return s.q.UpsertMoveFanout(ctx, sqlitedb.UpsertMoveFanoutParams{
		AccountID: f.AccountID, ContactFpr: f.ContactFpr, LeafKid: f.LeafKid, Status: f.Status,
		Attempts: f.Attempts, LastError: f.LastError, UpdatedAt: f.UpdatedAt,
	})
}

func (s *SQLite) ListMoveFanout(ctx context.Context, accountID string) ([]MoveFanout, error) {
	rows, err := s.q.ListMoveFanout(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]MoveFanout, 0, len(rows))
	for _, r := range rows {
		out = append(out, MoveFanout{AccountID: r.AccountID, ContactFpr: r.ContactFpr, LeafKid: r.LeafKid,
			Status: r.Status, Attempts: r.Attempts, LastError: r.LastError, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}

func (s *SQLite) UpdateAccountSeal(ctx context.Context, accountID, seal string) error {
	n, err := s.q.UpdateAccountSeal(ctx, sqlitedb.UpdateAccountSealParams{Seal: seal, ID: accountID})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: account %s: %w", accountID, sql.ErrNoRows)
	}
	return nil
}

// ListAuditEventsPage returns the newest entries first, bounded. A limit of 0
// or less is refused rather than silently meaning "everything": that default is
// how the unbounded read got there in the first place.
func (s *SQLite) ListAuditEventsPage(ctx context.Context, p AuditPage) ([]AuditRow, error) {
	if p.Limit <= 0 {
		p.Limit = 200
	}
	// Two statements, not one with two optional filters: an actor's page is answered from
	// `audit_events_actor`, and `(? = '' OR actor_id = ?)` cannot be.
	//
	// Column1 and Column2 are sqlc's names for the account placeholder. Named parameters would
	// read better and cannot be used: sqlc rewrites `sqlc.arg(x)` back to a placeholder in the
	// SQL it emits, and TestQueriesMatchTheHandWrittenCode compares that text with the source.
	var rs []sqlitedb.AuditEvent
	var err error
	if p.Actor != "" {
		rs, err = s.q.ListAuditEventsPageByActor(ctx, sqlitedb.ListAuditEventsPageByActorParams{
			ActorID: p.Actor, Column2: p.Account, Limit: int64(p.Limit),
		})
	} else {
		rs, err = s.q.ListAuditEventsPage(ctx, sqlitedb.ListAuditEventsPageParams{Column1: p.Account, Limit: int64(p.Limit)})
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditRow, 0, len(rs))
	for _, r := range rs {
		out = append(out, auditFromRow(r))
	}
	return out, nil
}
