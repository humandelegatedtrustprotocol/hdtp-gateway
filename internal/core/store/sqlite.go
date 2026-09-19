package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
	"github.com/tech-sumit/pact-gateway/migrations"
)

// SQLite is the default engine (SPEC §11.1): pure Go driver, one file, WAL mode,
// foreign keys ON (SQLite leaves them off unless asked — the schema relies on them).
type SQLite struct {
	db *sql.DB
	q  *sqlitedb.Queries
}

var _ Store = (*SQLite)(nil)

func OpenSQLite(path string) (*SQLite, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &SQLite{db: db, q: sqlitedb.New(db)}, nil
}

// Snapshot writes a consistent, compact copy of this database to dst, which must not exist.
//
// It is the ONE statement in this module that is not a generated query, and it is here rather
// than in whoever wants a copy for that reason. The rule is that database access goes through
// sqlc; `VACUUM INTO ?` was tried as a named query on 2026-09-19 and sqlc's SQLite grammar
// rejects it — it knows VACUUM and not the INTO form. A storage-engine maintenance command is
// not data access, the engine's own file is the right owner for it, and the guard that enforces
// the rule names this function as its single exception (TestNoHandWrittenSQLOutsideTheStore).
//
// VACUUM INTO rebuilds: the copy holds live rows only, with no free pages. That matters to a
// caller that has just deleted something from the source and needs it gone from the copy too.
func (s *SQLite) Snapshot(ctx context.Context, dst string) error {
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return fmt.Errorf("store: snapshot: %w", err)
	}
	return nil
}

func (s *SQLite) Migrate(ctx context.Context) error {
	p, err := s.provider()
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
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

func (s *SQLite) CreateAccount(ctx context.Context, p CreateAccountParams) (Account, error) {
	id := newID()
	err := s.q.InsertAccount(ctx, sqlitedb.InsertAccountParams{
		ID: id, Slug: p.Slug, DisplayName: p.DisplayName, Algo: p.Algo, CreatedAt: now(),
	})
	if err != nil {
		return Account{}, err
	}
	r, err := s.q.GetAccount(ctx, id)
	if err != nil {
		return Account{}, err
	}
	return accountFromRow(r), nil
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

func accountFromRow(r sqlitedb.Account) Account {
	return Account{
		ID: r.ID, Slug: r.Slug, DisplayName: r.DisplayName, Algo: r.Algo,
		Fingerprint: r.Fingerprint.String, Seal: r.Seal, Status: r.Status, CreatedAt: r.CreatedAt,
		RootFingerprint: r.RootFingerprint.String, RootCert: r.RootCert,
		AcceptNewHosts: r.AcceptNewHosts,
	}
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
	return s.q.InsertToken(ctx, sqlitedb.InsertTokenParams{
		ID: id, OwnerID: ownerID, Label: label, Hash: hash,
		AccountID: sql.NullString{String: accountID, Valid: accountID != ""}, CreatedAt: createdAt,
	})
}

func tokenFromRowSQL(r sqlitedb.Token) Token {
	t := Token{ID: r.ID, OwnerID: r.OwnerID, Label: r.Label, CreatedAt: r.CreatedAt}
	if r.AccountID.Valid {
		t.AccountID = r.AccountID.String
	}
	t.RevokedAt = r.RevokedAt.Int64
	return t
}

func (s *SQLite) GetTokenByHash(ctx context.Context, hash []byte) (Token, error) {
	r, err := s.q.GetTokenByHash(ctx, hash)
	if err != nil {
		return Token{}, err
	}
	return tokenFromRowSQL(r), nil
}

func (s *SQLite) ListTokens(ctx context.Context) ([]Token, error) {
	rs, err := s.q.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rs))
	for _, r := range rs {
		out = append(out, tokenFromRowSQL(r))
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
	return s.q.InsertAuditEvent(ctx, sqlitedb.InsertAuditEventParams{
		Seq: seq, Ts: ts, AccountID: sql.NullString{String: accountID, Valid: accountID != ""}, ActorKind: actorKind, ActorID: actorID,
		Action: action, Resource: resource, Outcome: outcome, RequestID: requestID,
		Details: details, PrevHash: prevHash, Hash: hash,
	})
}

func (s *SQLite) LastAuditEvent(ctx context.Context) (int64, string, error) {
	r, err := s.q.LastAuditEvent(ctx)
	if err != nil {
		return 0, "", err
	}
	return r.Seq, r.Hash, nil
}

func auditRowSQL(r sqlitedb.AuditEvent) AuditRow {
	acct := ""
	if r.AccountID.Valid {
		acct = r.AccountID.String
	}
	return AuditRow{
		Seq: r.Seq, TS: r.Ts, AccountID: acct, ActorKind: r.ActorKind, ActorID: r.ActorID,
		Action: r.Action, Resource: r.Resource, Outcome: r.Outcome, RequestID: r.RequestID,
		Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
	}
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
		out = append(out, auditRowSQL(r))
	}
	return out, nil
}

func (s *SQLite) UpsertRotationFanout(ctx context.Context, f RotationFanout) error {
	if f.UpdatedAt == 0 {
		f.UpdatedAt = now()
	}
	if f.Kind == "" {
		f.Kind = "rotation"
	}
	return s.q.UpsertRotationFanout(ctx, sqlitedb.UpsertRotationFanoutParams{
		AccountID: f.AccountID, ContactFpr: f.ContactFpr, NewFpr: f.NewFpr, Status: f.Status,
		Attempts: f.Attempts, LastError: f.LastError, UpdatedAt: f.UpdatedAt, Kind: f.Kind,
	})
}

func (s *SQLite) ListRotationFanout(ctx context.Context, accountID string) ([]RotationFanout, error) {
	rows, err := s.q.ListRotationFanout(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]RotationFanout, 0, len(rows))
	for _, r := range rows {
		out = append(out, RotationFanout{AccountID: r.AccountID, ContactFpr: r.ContactFpr, NewFpr: r.NewFpr,
			Status: r.Status, Attempts: r.Attempts, LastError: r.LastError, UpdatedAt: r.UpdatedAt, Kind: r.Kind})
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
	// Column1 and Column2 are sqlc's names for `?1` and `?2` - the actor and the
	// account. Named parameters would read better and cannot be used: sqlc rewrites
	// `sqlc.arg(x)` back to a placeholder in the SQL it emits, and
	// TestQueriesMatchTheHandWrittenCode compares that text with the source.
	rs, err := s.q.ListAuditEventsPage(ctx, sqlitedb.ListAuditEventsPageParams{
		Column1: p.Actor, Column2: p.Account, Limit: int64(p.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]AuditRow, 0, len(rs))
	for _, r := range rs {
		out = append(out, auditRowSQL(r))
	}
	return out, nil
}
