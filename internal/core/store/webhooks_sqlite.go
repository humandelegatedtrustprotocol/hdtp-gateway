package store

import (
	"context"
	"database/sql"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertWebhookEndpoint inserts an endpoint, active with no failures, as given.
func (s *SQLite) InsertWebhookEndpoint(ctx context.Context, e WebhookEndpoint) error {
	return s.q.InsertWebhookEndpoint(ctx, webhookEndpointInsert(e))
}

// ListWebhookEndpoints returns up to limit of the account's endpoints, newest first.
func (s *SQLite) ListWebhookEndpoints(ctx context.Context, accountID string, limit int) ([]WebhookEndpoint, error) {
	rs, err := s.q.ListWebhookEndpoints(ctx, sqlitedb.ListWebhookEndpointsParams{AccountID: accountID, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]WebhookEndpoint, 0, len(rs))
	for _, r := range rs {
		out = append(out, webhookEndpointFromRow(r))
	}
	return out, nil
}

// CountWebhookEndpoints returns how many endpoints the account has, active or paused.
func (s *SQLite) CountWebhookEndpoints(ctx context.Context, accountID string) (int64, error) {
	return s.q.CountWebhookEndpoints(ctx, accountID)
}

// GetWebhookEndpoint returns one of the account's endpoints, or ErrNotFound.
func (s *SQLite) GetWebhookEndpoint(ctx context.Context, accountID, id string) (WebhookEndpoint, error) {
	r, err := s.q.GetWebhookEndpoint(ctx, sqlitedb.GetWebhookEndpointParams{AccountID: accountID, ID: id})
	if err != nil {
		return WebhookEndpoint{}, err
	}
	return webhookEndpointFromRow(r), nil
}

// RotateWebhookSecret stores sealed as the endpoint's secret and keeps the one it replaces as the
// previous secret, accepted until until; false when the account has no such endpoint.
func (s *SQLite) RotateWebhookSecret(ctx context.Context, accountID, id string, sealed []byte, until, now int64) (bool, error) {
	n, err := s.q.RotateWebhookSecret(ctx, webhookRotate(accountID, id, sealed, until, now))
	return n == 1, err
}

// PauseWebhookEndpoint parks the endpoint; false when the account has no such endpoint.
func (s *SQLite) PauseWebhookEndpoint(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.PauseWebhookEndpoint(ctx, sqlitedb.PauseWebhookEndpointParams{UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// ResumeWebhookEndpoint makes the endpoint active and clears its failure run; false when the
// account has no such endpoint.
func (s *SQLite) ResumeWebhookEndpoint(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.ResumeWebhookEndpoint(ctx, sqlitedb.ResumeWebhookEndpointParams{UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// DeleteWebhookEndpoint removes the endpoint, its delivery rows staying; false when the account
// has no such endpoint.
func (s *SQLite) DeleteWebhookEndpoint(ctx context.Context, accountID, id string) (bool, error) {
	n, err := s.q.DeleteWebhookEndpoint(ctx, sqlitedb.DeleteWebhookEndpointParams{AccountID: accountID, ID: id})
	return n == 1, err
}

// InsertWebhookDelivery records one attempt.
func (s *SQLite) InsertWebhookDelivery(ctx context.Context, d WebhookDelivery) error {
	return s.q.InsertWebhookDelivery(ctx, webhookDeliveryInsert(d))
}

// ClearWebhookFailures ends the endpoint's failure run; false when the account has no such
// endpoint.
func (s *SQLite) ClearWebhookFailures(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.ClearWebhookFailures(ctx, sqlitedb.ClearWebhookFailuresParams{UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// CountWebhookFailure adds one failure to the endpoint's run and parks it when the run reaches
// limit; false when the account has no such endpoint.
func (s *SQLite) CountWebhookFailure(ctx context.Context, accountID, id string, limit, now int64) (bool, error) {
	n, err := s.q.CountWebhookFailure(ctx, sqlitedb.CountWebhookFailureParams{Failures: limit - 1, UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// ListWebhookDeliveries returns up to limit of one endpoint's attempts, newest first.
func (s *SQLite) ListWebhookDeliveries(ctx context.Context, accountID, endpointID string, limit int) ([]WebhookDelivery, error) {
	rs, err := s.q.ListWebhookDeliveries(ctx, sqlitedb.ListWebhookDeliveriesParams{AccountID: accountID, EndpointID: endpointID, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]WebhookDelivery, 0, len(rs))
	for _, r := range rs {
		out = append(out, webhookDeliveryFromRow(r))
	}
	return out, nil
}

// WebhookAccounts returns every account with an endpoint, active or paused.
func (s *SQLite) WebhookAccounts(ctx context.Context) ([]string, error) {
	return s.q.ListWebhookAccounts(ctx)
}

// WebhookCursor returns the id of the account's last change the dispatcher claimed, 0 before its
// first claim.
func (s *SQLite) WebhookCursor(ctx context.Context, accountID string) (int64, error) {
	return cursorOf(s.q.GetWebhookCursor(ctx, accountID))
}

// ClaimWebhookCursor moves the account's cursor from `from`, the id the caller read, to `to`;
// false, changing nothing, when another process moved it first.
func (s *SQLite) ClaimWebhookCursor(ctx context.Context, accountID string, from, to int64) (bool, error) {
	var n int64
	var err error
	if from == 0 {
		n, err = s.q.StartWebhookCursor(ctx, sqlitedb.StartWebhookCursorParams{AccountID: accountID, LastChangeID: to})
	} else {
		n, err = s.q.MoveWebhookCursor(ctx, sqlitedb.MoveWebhookCursorParams{LastChangeID: to, AccountID: accountID, LastChangeID_2: from})
	}
	return n == 1, err
}

// StartWebhookCursorAt puts the account's cursor at id, as though every change up to it had been
// claimed, and never moves it back. Id 0 writes nothing: no row is the cursor at 0, and a row at 0
// would refuse the first claim (ClaimWebhookCursor).
func (s *SQLite) StartWebhookCursorAt(ctx context.Context, accountID string, id int64) error {
	if id == 0 {
		return nil
	}
	n, err := s.q.StartWebhookCursor(ctx, sqlitedb.StartWebhookCursorParams{AccountID: accountID, LastChangeID: id})
	if err != nil || n == 1 {
		return err
	}
	_, err = s.q.AdvanceWebhookCursor(ctx, sqlitedb.AdvanceWebhookCursorParams{LastChangeID: id, AccountID: accountID, LastChangeID_2: id})
	return err
}

// DeleteWebhookDeliveriesBefore deletes the delivery rows written before at (unix milliseconds)
// and returns how many went.
func (s *SQLite) DeleteWebhookDeliveriesBefore(ctx context.Context, at int64) (int64, error) {
	return s.q.DeleteWebhookDeliveriesBefore(ctx, at)
}

// ForgetExpiredWebhookSecrets clears the secret a rotation replaced where it stopped being
// accepted by now (unix milliseconds), and returns how many were cleared.
func (s *SQLite) ForgetExpiredWebhookSecrets(ctx context.Context, now int64) (int64, error) {
	return s.q.ForgetExpiredWebhookSecrets(ctx, sql.NullInt64{Int64: now, Valid: true})
}
