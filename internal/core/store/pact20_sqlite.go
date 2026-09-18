package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store/sqlitedb"
)

// PACT 2.0 state (migration 0027): the account's root and leaf ledger, the
// 2.0 pins, the removal tombstone, former endpoints and pending addresses.

func (s *SQLite) SetAccountProtocol(ctx context.Context, accountID string, protocol int64, rootFingerprint string, rootCert []byte) error {
	n, err := s.q.SetAccountProtocol(ctx, sqlitedb.SetAccountProtocolParams{
		Protocol: protocol, RootFingerprint: sql.NullString{String: rootFingerprint, Valid: rootFingerprint != ""},
		RootCert: rootCert, ID: accountID,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: account %s not found", accountID)
	}
	return nil
}

func (s *SQLite) SetAccountLeafKey(ctx context.Context, accountID, fingerprint string, sealedKey []byte, algo string) error {
	n, err := s.q.SetAccountLeafKey(ctx, sqlitedb.SetAccountLeafKeyParams{
		Fingerprint: sql.NullString{String: fingerprint, Valid: true}, KeySealed: sealedKey, Algo: algo, ID: accountID,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: account %s not found", accountID)
	}
	return nil
}

func (s *SQLite) SetAccountHostPolicy(ctx context.Context, accountID, acceptNewHosts string, accept1x bool) error {
	n, err := s.q.SetAccountHostPolicy(ctx, sqlitedb.SetAccountHostPolicyParams{
		AcceptNewHosts: acceptNewHosts, Accept1x: boolInt(accept1x), ID: accountID,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: account %s not found", accountID)
	}
	return nil
}

func (s *SQLite) InsertLeaf(ctx context.Context, l Leaf) error {
	if l.CreatedAt == 0 {
		l.CreatedAt = now()
	}
	return s.q.InsertLeaf(ctx, sqlitedb.InsertLeafParams{
		AccountID: l.AccountID, Kid: l.Kid, Leaf: l.Leaf, KeySealed: l.KeySealed,
		NotBefore: l.NotBefore, NotAfter: l.NotAfter, State: l.State, Endpoint: l.Endpoint, CreatedAt: l.CreatedAt,
	})
}

func (s *SQLite) UpdateLeaf(ctx context.Context, l Leaf) error {
	n, err := s.q.UpdateLeaf(ctx, sqlitedb.UpdateLeafParams{
		Leaf: l.Leaf, NotBefore: l.NotBefore, NotAfter: l.NotAfter, State: l.State, Endpoint: l.Endpoint,
		AccountID: l.AccountID, Kid: l.Kid,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: leaf %s not found", l.Kid)
	}
	return nil
}

func (s *SQLite) ListLeaves(ctx context.Context, accountID string) ([]Leaf, error) {
	rows, err := s.q.ListLeaves(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]Leaf, 0, len(rows))
	for _, r := range rows {
		out = append(out, Leaf{AccountID: r.AccountID, Kid: r.Kid, Leaf: r.Leaf, KeySealed: r.KeySealed,
			NotBefore: r.NotBefore, NotAfter: r.NotAfter, State: r.State, Endpoint: r.Endpoint, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (s *SQLite) RetireLeafKey(ctx context.Context, accountID, kid string) error {
	if _, err := s.q.RetireLeafKey(ctx, sqlitedb.RetireLeafKeyParams{AccountID: accountID, Kid: kid}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func (s *SQLite) DeleteLeavesByState(ctx context.Context, accountID, state string) (int64, error) {
	n, err := s.q.DeleteLeavesByState(ctx, sqlitedb.DeleteLeavesByStateParams{AccountID: accountID, State: state})
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return n, nil
}

func (s *SQLite) UpsertTombstone(ctx context.Context, t Tombstone) error {
	if t.At == 0 {
		t.At = now()
	}
	return s.q.UpsertTombstone(ctx, sqlitedb.UpsertTombstoneParams{AccountID: t.AccountID, Root: t.Root, Leaf: t.Leaf, At: t.At})
}

func (s *SQLite) ListTombstones(ctx context.Context, accountID string) ([]Tombstone, error) {
	rows, err := s.q.ListTombstones(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]Tombstone, 0, len(rows))
	for _, r := range rows {
		out = append(out, Tombstone{AccountID: r.AccountID, Root: r.Root, Leaf: r.Leaf, At: r.At})
	}
	return out, nil
}

func (s *SQLite) DeleteTombstone(ctx context.Context, accountID, root string) error {
	if _, err := s.q.DeleteTombstone(ctx, sqlitedb.DeleteTombstoneParams{AccountID: accountID, Root: root}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func (s *SQLite) InsertFormerEndpoint(ctx context.Context, f FormerEndpoint) error {
	if f.At == 0 {
		f.At = now()
	}
	return s.q.InsertFormerEndpoint(ctx, sqlitedb.InsertFormerEndpointParams{AccountID: f.AccountID, Root: f.Root, Endpoint: f.Endpoint, At: f.At})
}

func (s *SQLite) ListFormerEndpoints(ctx context.Context, accountID string) ([]FormerEndpoint, error) {
	rows, err := s.q.ListFormerEndpoints(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]FormerEndpoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, FormerEndpoint{AccountID: r.AccountID, Root: r.Root, Endpoint: r.Endpoint, At: r.At})
	}
	return out, nil
}

func (s *SQLite) UpsertPendingAddress(ctx context.Context, p PendingAddress) error {
	if p.At == 0 {
		p.At = now()
	}
	return s.q.UpsertPendingAddress(ctx, sqlitedb.UpsertPendingAddressParams{
		AccountID: p.AccountID, Root: p.Root, Endpoint: p.Endpoint, Leaf: p.Leaf, Why: p.Why, At: p.At,
		RootCert: p.RootCert,
	})
}

func (s *SQLite) ListPendingAddresses(ctx context.Context, accountID string) ([]PendingAddress, error) {
	rows, err := s.q.ListPendingAddresses(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := make([]PendingAddress, 0, len(rows))
	for _, r := range rows {
		out = append(out, PendingAddress{AccountID: r.AccountID, Root: r.Root, Endpoint: r.Endpoint, Leaf: r.Leaf, Why: r.Why, At: r.At, RootCert: r.RootCert})
	}
	return out, nil
}

func (s *SQLite) GetPendingAddress(ctx context.Context, accountID, root string) (PendingAddress, error) {
	r, err := s.q.GetPendingAddress(ctx, sqlitedb.GetPendingAddressParams{AccountID: accountID, Root: root})
	if err != nil {
		return PendingAddress{}, err
	}
	return PendingAddress{AccountID: r.AccountID, Root: r.Root, Endpoint: r.Endpoint, Leaf: r.Leaf, Why: r.Why, At: r.At, RootCert: r.RootCert}, nil
}

func (s *SQLite) DeletePendingAddress(ctx context.Context, accountID, root string) error {
	if _, err := s.q.DeletePendingAddress(ctx, sqlitedb.DeletePendingAddressParams{AccountID: accountID, Root: root}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func (s *SQLite) RepinContactAddress(ctx context.Context, accountID, root, endpoint string, leaf, spki []byte, nowTS int64) error {
	n, err := s.q.RepinContactAddress(ctx, sqlitedb.RepinContactAddressParams{
		Endpoint: endpoint, Leaf: leaf, Spki: spki, PinnedAt: sql.NullInt64{Int64: nowTS, Valid: nowTS != 0},
		AccountID: accountID, Fingerprint: root,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

func (s *SQLite) SetContactChainSentKid(ctx context.Context, accountID, fingerprint, kid string) error {
	n, err := s.q.SetContactChainSentKid(ctx, sqlitedb.SetContactChainSentKidParams{ChainSentKid: kid, AccountID: accountID, Fingerprint: fingerprint})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

func (s *SQLite) ClearChainSentKids(ctx context.Context, accountID string) error {
	if _, err := s.q.ClearChainSentKids(ctx, accountID); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func (s *SQLite) UpgradeContactPin(ctx context.Context, accountID, oldFpr, root, endpoint string, leaf, spki []byte, nowTS int64) error {
	n, err := s.q.UpgradeContactPin(ctx, sqlitedb.UpgradeContactPinParams{
		Fingerprint: root, Endpoint: endpoint, Leaf: leaf, Spki: spki,
		PinnedAt: sql.NullInt64{Int64: nowTS, Valid: nowTS != 0}, AccountID: accountID, Fingerprint_2: oldFpr,
	})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: contact not found")
	}
	return nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// SetContactRootCert fills in the root certificate of a pin that has none. A pin
// whose cert is already stored is left alone: the root cannot change (PACT sec. 14.3),
// so the stored one is the cert that was checked when the pin was made.
func (s *SQLite) SetContactRootCert(ctx context.Context, accountID, root string, cert []byte) error {
	if len(cert) == 0 {
		return nil
	}
	if _, err := s.q.SetContactRootCert(ctx, sqlitedb.SetContactRootCertParams{
		RootCert: cert, AccountID: accountID, Fingerprint: root,
	}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}
