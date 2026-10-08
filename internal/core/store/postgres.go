package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/migrations"
)

// Postgres is the disconnect-the-storage engine (SPEC §11.1): same Store contract,
// same conformance suite, pgx underneath. Migrations run through goose over a
// database/sql handle derived from the pool; queries run on the pool directly.
type Postgres struct {
	pool *pgxpool.Pool
	q    *pgdb.Queries
	// inTx marks the copy Atomically hands to its callback: its `q` is a transaction already.
	inTx bool
}

var _ Store = (*Postgres)(nil)

// Atomically runs fn on a copy of this store whose queries all go through one transaction (see
// SQLite.Atomically: every method reaches the database through `s.q`).
func (s *Postgres) Atomically(ctx context.Context, fn func(tx Store) error) error {
	if s.inTx {
		return fn(s)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(&Postgres{pool: s.pool, q: s.q.WithTx(tx), inTx: true}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// OpenPostgres opens a connection pool on dsn through pgxpool. It does not create the schema;
// Migrate does.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Postgres{pool: pool, q: pgdb.New(pool)}, nil
}

func (s *Postgres) provider() (*goose.Provider, *sql.DB, error) {
	sub, err := fs.Sub(migrations.Postgres, "postgres")
	if err != nil {
		return nil, nil, fmt.Errorf("store: %w", err)
	}
	db := stdlib.OpenDBFromPool(s.pool)
	// Many node processes, on many hosts, share one Postgres (SPEC §11.1), and each migrates as it
	// starts: a session-level advisory lock makes them take turns, so one applies the migrations
	// and the rest find nothing pending.
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("store: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, sub, goose.WithSessionLocker(locker))
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("store: %w", err)
	}
	return p, db, nil
}

// Migrate applies every pending migration. Processes sharing the database take turns under goose's
// session-level advisory lock, so one applies and the others find nothing pending.
func (s *Postgres) Migrate(ctx context.Context) error {
	p, db, err := s.provider()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = p.Up(ctx)
	return err
}

// SchemaCurrent reports an error unless the schema is exactly the version this binary migrates to;
// the error says whether it is behind or ahead.
func (s *Postgres) SchemaCurrent(ctx context.Context) error {
	p, db, err := s.provider()
	if err != nil {
		return err
	}
	defer db.Close()
	return schemaCurrent(ctx, p)
}

// MigrateDown rolls the schema back to version 0. It exists for the conformance suite's up, down and
// up check and is not on the Store interface.
func (s *Postgres) MigrateDown(ctx context.Context) error {
	p, db, err := s.provider()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = p.DownTo(ctx, 0)
	return err
}

// Close closes the connection pool and returns nil.
func (s *Postgres) Close() error {
	s.pool.Close()
	return nil
}

// Scrub does nothing on Postgres, because nothing the node can do from a connection destroys a
// deleted row's bytes there: the old row version stays in its page as a dead tuple until VACUUM
// reclaims the space (and reclaiming does not overwrite it), the write-ahead log keeps it until
// the segment is recycled, and any base backup or WAL archive keeps it for as long as that is
// kept. SPEC §3.9 names this as a divergence from HDTP §9's "destroy"; what remains is ciphertext
// sealed under the node's keyring.
func (s *Postgres) Scrub(context.Context) error { return nil }

// CreateOwnerWithID inserts an owner under id, or under a fresh random id when id is empty, with the
// current time as CreatedAt. An id already used is refused by the primary key.
func (s *Postgres) CreateOwnerWithID(ctx context.Context, id, displayName string) (Owner, error) {
	if id == "" {
		id = newID()
	}
	o := Owner{ID: id, DisplayName: displayName, CreatedAt: now()}
	err := s.q.InsertOwner(ctx, pgdb.InsertOwnerParams{ID: o.ID, DisplayName: o.DisplayName, CreatedAt: o.CreatedAt})
	return o, err
}

// InsertCredential inserts a credential, giving it a random id and the current time when it has
// none. Kind must be one the table's CHECK admits (passkey, oauth, password), and an owner that does
// not exist is refused by the foreign key.
func (s *Postgres) InsertCredential(ctx context.Context, c Credential) error {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = now()
	}
	return s.q.InsertCredential(ctx, pgdb.InsertCredentialParams{
		ID: c.ID, OwnerID: c.OwnerID, Kind: c.Kind, Tag: c.Tag, Data: c.Data, CreatedAt: c.CreatedAt,
	})
}

// CountCredentialsByKind counts the credentials of one kind across every owner.
func (s *Postgres) CountCredentialsByKind(ctx context.Context, kind string) (int64, error) {
	return s.q.CountCredentialsByKind(ctx, kind)
}

// GetOwner returns the owner, or ErrNotFound.
func (s *Postgres) GetOwner(ctx context.Context, id string) (Owner, error) {
	r, err := s.q.GetOwner(ctx, id)
	if err != nil {
		return Owner{}, err
	}
	return Owner{ID: r.ID, DisplayName: r.DisplayName, CreatedAt: r.CreatedAt}, nil
}

// ListOwners returns every owner ordered by creation time and then id.
func (s *Postgres) ListOwners(ctx context.Context) ([]Owner, error) {
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

// DeleteOwner deletes the owner; one that is not there is ErrNotFound.
func (s *Postgres) DeleteOwner(ctx context.Context, id string) error {
	n, err := s.q.DeleteOwner(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CreateAccount inserts an account under a fresh random id with the current time as CreatedAt and
// returns the stored row. It runs in a transaction; a slug already taken is refused by the table's
// constraint.
func (s *Postgres) CreateAccount(ctx context.Context, p CreateAccountParams) (Account, error) {
	var out Account
	err := s.Atomically(ctx, func(tx Store) error {
		t := tx.(*Postgres)
		at := now()
		id := newID()
		if err := t.q.InsertAccount(ctx, pgdb.InsertAccountParams{
			ID: id, Slug: p.Slug, DisplayName: p.DisplayName, Algo: p.Algo, CreatedAt: at,
		}); err != nil {
			return err
		}
		r, err := t.q.GetAccount(ctx, id)
		if err != nil {
			return err
		}
		out = accountFromRow(sqlitedb.Account(r))
		return nil
	})
	if err != nil {
		return Account{}, err
	}
	return out, nil
}

// SetAccountKey binds the account's first key, once. An account that is missing or already keyed is
// an error.
func (s *Postgres) SetAccountKey(ctx context.Context, accountID, fingerprint string, sealedKey []byte) error {
	n, err := s.q.SetAccountKey(ctx, pgdb.SetAccountKeyParams{
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

// GetAccountByID returns the account, or ErrNotFound.
func (s *Postgres) GetAccountByID(ctx context.Context, id string) (Account, error) {
	r, err := s.q.GetAccount(ctx, id)
	if err != nil {
		return Account{}, err
	}
	return accountFromRow(sqlitedb.Account(r)), nil
}

// GetAccountSealedKey returns the account's sealed leaf key. An account with no key returns nil and
// a nil error: no key is a state, and each caller decides what it means.
func (s *Postgres) GetAccountSealedKey(ctx context.Context, id string) ([]byte, error) {
	r, err := s.q.GetAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	// No key is a STATE, not a failure: an account that arrived in a data-only
	// archive holds its root and no key, because a leaf key belongs to the host
	// that issued it (HDTP §9). Reporting that as an error made three callers'
	// `len(sealed) == 0` branches unreachable — the node read it as "unavailable"
	// and refused to start when it was the only account, `csr -purpose signup`
	// could not mint a key, and `install-leaf` could not install the first leaf
	// after a move. Each caller decides what an absent key means to it.
	return r.KeySealed, nil
}

// GetAccountBySlug returns the account with this slug, or ErrNotFound.
func (s *Postgres) GetAccountBySlug(ctx context.Context, slug string) (Account, error) {
	r, err := s.q.GetAccountBySlug(ctx, slug)
	if err != nil {
		return Account{}, err
	}
	return accountFromRow(sqlitedb.Account(r)), nil
}

// ListAccounts returns every account ordered by creation time and then id.
func (s *Postgres) ListAccounts(ctx context.Context) ([]Account, error) {
	rs, err := s.q.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(rs))
	for _, r := range rs {
		out = append(out, accountFromRow(sqlitedb.Account(r)))
	}
	return out, nil
}

// AddMembership records that ownerID administers accountID with the given role. An owner or account
// that does not exist is refused by the foreign keys.
func (s *Postgres) AddMembership(ctx context.Context, ownerID, accountID, role string) error {
	return s.q.InsertMembership(ctx, pgdb.InsertMembershipParams{OwnerID: ownerID, AccountID: accountID, Role: role})
}

// ListMembershipsByOwner returns the owner's memberships, ordered by account id.
func (s *Postgres) ListMembershipsByOwner(ctx context.Context, ownerID string) ([]Membership, error) {
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

// RemoveMembership removes the owner's membership of the account; one that is not there is
// ErrNotFound.
func (s *Postgres) RemoveMembership(ctx context.Context, ownerID, accountID string) error {
	n, err := s.q.DeleteMembership(ctx, pgdb.DeleteMembershipParams{OwnerID: ownerID, AccountID: accountID})
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListCredentialsByKind returns the credentials of one kind, across owners, ordered by creation time
// and then id.
func (s *Postgres) ListCredentialsByKind(ctx context.Context, kind string) ([]Credential, error) {
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

// RemoveCredentialIfNotLast deletes the credential only while another of the same kind survives, in
// one statement, and reports whether it deleted one.
func (s *Postgres) RemoveCredentialIfNotLast(ctx context.Context, id, kind string) (bool, error) {
	// The kind is named twice because the statement compares it twice: once to pick
	// the row, once to count the survivors of the same kind.
	n, err := s.q.DeleteCredentialIfNotLast(ctx, pgdb.DeleteCredentialIfNotLastParams{ID: id, Kind: kind})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// InsertSession inserts an owner session as given. The id is the primary key, and an owner that does
// not exist is refused by the foreign key. The expiry is not checked here: GetSession returns it,
// and DeleteExpiredSessions removes sessions past it.
func (s *Postgres) InsertSession(ctx context.Context, id, ownerID string, createdAt, expiresAt int64) error {
	return s.q.InsertSession(ctx, pgdb.InsertSessionParams{ID: id, OwnerID: ownerID, CreatedAt: createdAt, ExpiresAt: expiresAt})
}

// GetSession returns the session's owner and expiry, or ErrNotFound. It does not compare the expiry
// with the clock; the caller does.
func (s *Postgres) GetSession(ctx context.Context, id string) (string, int64, error) {
	r, err := s.q.GetSession(ctx, id)
	if err != nil {
		return "", 0, err
	}
	return r.OwnerID, r.ExpiresAt, nil
}

// RemoveSession deletes the session; one that is not there is not an error.
func (s *Postgres) RemoveSession(ctx context.Context, id string) error {
	_, err := s.q.DeleteSession(ctx, id)
	return err
}

// InsertToken inserts an owner-MCP token by the hash of its secret; an empty accountID stores NULL,
// an owner-wide token.
func (s *Postgres) InsertToken(ctx context.Context, id, ownerID, label string, hash []byte, accountID string, createdAt int64) error {
	return s.q.InsertToken(ctx, pgdb.InsertTokenParams(tokenInsert(id, ownerID, label, hash, accountID, createdAt)))
}

// GetTokenByHash returns the owner-MCP token with this hash, revoked or not, or ErrNotFound.
func (s *Postgres) GetTokenByHash(ctx context.Context, hash []byte) (Token, error) {
	r, err := s.q.GetTokenByHash(ctx, hash)
	if err != nil {
		return Token{}, err
	}
	return tokenFromRow(sqlitedb.Token(r)), nil
}

// ListTokens returns every owner-MCP token, revoked ones included (RevokedAt is set), ordered by
// creation time and then id.
func (s *Postgres) ListTokens(ctx context.Context) ([]Token, error) {
	rs, err := s.q.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rs))
	for _, r := range rs {
		out = append(out, tokenFromRow(sqlitedb.Token(r)))
	}
	return out, nil
}

// RevokeToken stamps the token revoked at now; a token that is missing or already revoked is an
// error.
func (s *Postgres) RevokeToken(ctx context.Context, id string, now int64) error {
	n, err := s.q.RevokeToken(ctx, pgdb.RevokeTokenParams{RevokedAt: sql.NullInt64{Int64: now, Valid: true}, ID: id})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: token missing or already revoked")
	}
	return nil
}

// InsertAuditEvent inserts one audit row exactly as given, with an empty accountID stored as NULL.
// It does not read the head or check the hashes: AppendAuditEvent is the path that extends the
// chain.
func (s *Postgres) InsertAuditEvent(ctx context.Context, seq int64, ts int64, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash string) error {
	return s.q.InsertAuditEvent(ctx, pgdb.InsertAuditEventParams(auditInsert(seq, ts, accountID, actorKind, actorID, action, resource, outcome, requestID, details, prevHash, hash)))
}

// AppendAuditEvent extends the audit chain by one row in a single transaction. The transaction takes
// the chain's advisory lock (LockAuditChain) before it reads the head, so a second process waits for
// the first's commit and reads the row it wrote; the row seal builds is inserted by InsertAuditEvent
// on that head. An error from seal rolls the transaction back and nothing is written.
func (s *Postgres) AppendAuditEvent(ctx context.Context, seal func(prevSeq int64, prevHash string) (AuditRow, error)) error {
	return s.Atomically(ctx, func(tx Store) error {
		// Read committed would let two processes read one head; the lock makes the second wait
		// for the first's commit and read the row it wrote.
		if err := tx.(*Postgres).q.LockAuditChain(ctx); err != nil {
			return fmt.Errorf("store: audit head: %w", err)
		}
		return appendAudit(ctx, tx, seal)
	})
}

// LastAuditEvent returns the seq and hash of the newest audit row, or ErrNotFound for an empty
// chain.
func (s *Postgres) LastAuditEvent(ctx context.Context) (int64, string, error) {
	r, err := s.q.LastAuditEvent(ctx)
	if err != nil {
		return 0, "", err
	}
	return r.Seq, r.Hash, nil
}

// ListAuditEvents returns the whole trail ascending by seq, or only one actor's rows when
// actorFilter is not empty. It is the trail as it is verified; ListAuditEventsPage is the trail as
// it is read.
func (s *Postgres) ListAuditEvents(ctx context.Context, actorFilter string) ([]AuditRow, error) {
	var rs []pgdb.AuditEvent
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
		out = append(out, auditFromRow(sqlitedb.AuditEvent(r)))
	}
	return out, nil
}

// UpsertMoveFanout writes the progress of a move campaign for one contact, one row per account and
// contact, stamped now when UpdatedAt is zero.
func (s *Postgres) UpsertMoveFanout(ctx context.Context, f MoveFanout) error {
	if f.UpdatedAt == 0 {
		f.UpdatedAt = now()
	}
	return s.q.UpsertMoveFanout(ctx, pgdb.UpsertMoveFanoutParams{
		AccountID: f.AccountID, ContactFpr: f.ContactFpr, LeafKid: f.LeafKid, Status: f.Status,
		Attempts: f.Attempts, LastError: f.LastError, UpdatedAt: f.UpdatedAt,
	})
}

// ListMoveFanout returns the account's move-campaign progress rows, ordered by contact fingerprint.
func (s *Postgres) ListMoveFanout(ctx context.Context, accountID string) ([]MoveFanout, error) {
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

// UpdateAccountSeal sets the account's seal policy; an account that is not there is an error
// wrapping ErrNotFound.
func (s *Postgres) UpdateAccountSeal(ctx context.Context, accountID, seal string) error {
	n, err := s.q.UpdateAccountSeal(ctx, pgdb.UpdateAccountSealParams{Seal: seal, ID: accountID})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: account %s: %w", accountID, sql.ErrNoRows)
	}
	return nil
}

// ListAuditEventsPage returns the newest entries first, bounded by p.Limit. A limit of 0 or less
// is read as 200, never as "everything": an unbounded default is how the unbounded read got there
// in the first place. Actor and Account narrow the page when they are not empty.
func (p *Postgres) ListAuditEventsPage(ctx context.Context, f AuditPage) ([]AuditRow, error) {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	lim := pgLimit(f.Limit)
	// Two statements, not one with two optional filters; see the sqlite side for why, and for
	// why the account placeholder keeps sqlc's name.
	var rs []pgdb.AuditEvent
	var err error
	if f.Actor != "" {
		rs, err = p.q.ListAuditEventsPageByActor(ctx, pgdb.ListAuditEventsPageByActorParams{ActorID: f.Actor, Column2: f.Account, Limit: lim})
	} else {
		rs, err = p.q.ListAuditEventsPage(ctx, pgdb.ListAuditEventsPageParams{Column1: f.Account, Limit: lim})
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditRow, 0, len(rs))
	for _, r := range rs {
		out = append(out, auditFromRow(sqlitedb.AuditEvent(r)))
	}
	return out, nil
}
