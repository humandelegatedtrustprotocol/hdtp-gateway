package store

import (
	"context"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/pgdb"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/sqlitedb"
)

// InsertWebhookEndpoint inserts an endpoint, active with no failures, as given.
func (s *Postgres) InsertWebhookEndpoint(ctx context.Context, e WebhookEndpoint) error {
	return s.q.InsertWebhookEndpoint(ctx, pgdb.InsertWebhookEndpointParams(webhookEndpointInsert(e)))
}

// ListWebhookEndpoints returns up to limit of the account's endpoints, newest first.
func (s *Postgres) ListWebhookEndpoints(ctx context.Context, accountID string, limit int) ([]WebhookEndpoint, error) {
	rs, err := s.q.ListWebhookEndpoints(ctx, pgdb.ListWebhookEndpointsParams{AccountID: accountID, Limit: pgLimit(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]WebhookEndpoint, 0, len(rs))
	for _, r := range rs {
		out = append(out, webhookEndpointFromRow(sqlitedb.WebhookEndpoint(r)))
	}
	return out, nil
}

// GetWebhookEndpoint returns one of the account's endpoints, or ErrNotFound.
func (s *Postgres) GetWebhookEndpoint(ctx context.Context, accountID, id string) (WebhookEndpoint, error) {
	r, err := s.q.GetWebhookEndpoint(ctx, pgdb.GetWebhookEndpointParams{AccountID: accountID, ID: id})
	if err != nil {
		return WebhookEndpoint{}, err
	}
	return webhookEndpointFromRow(sqlitedb.WebhookEndpoint(r)), nil
}

// RotateWebhookSecret stores sealed as the endpoint's secret and keeps the one it replaces as the
// previous secret, accepted until until; false when the account has no such endpoint.
func (s *Postgres) RotateWebhookSecret(ctx context.Context, accountID, id string, sealed []byte, until, now int64) (bool, error) {
	n, err := s.q.RotateWebhookSecret(ctx, pgdb.RotateWebhookSecretParams(webhookRotate(accountID, id, sealed, until, now)))
	return n == 1, err
}

// PauseWebhookEndpoint parks the endpoint; false when the account has no such endpoint.
func (s *Postgres) PauseWebhookEndpoint(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.PauseWebhookEndpoint(ctx, pgdb.PauseWebhookEndpointParams{UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// ResumeWebhookEndpoint makes the endpoint active and clears its failure run; false when the
// account has no such endpoint.
func (s *Postgres) ResumeWebhookEndpoint(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.ResumeWebhookEndpoint(ctx, pgdb.ResumeWebhookEndpointParams{UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// DeleteWebhookEndpoint removes the endpoint, its delivery rows staying; false when the account
// has no such endpoint.
func (s *Postgres) DeleteWebhookEndpoint(ctx context.Context, accountID, id string) (bool, error) {
	n, err := s.q.DeleteWebhookEndpoint(ctx, pgdb.DeleteWebhookEndpointParams{AccountID: accountID, ID: id})
	return n == 1, err
}

// InsertWebhookDelivery records one attempt.
func (s *Postgres) InsertWebhookDelivery(ctx context.Context, d WebhookDelivery) error {
	return s.q.InsertWebhookDelivery(ctx, pgdb.InsertWebhookDeliveryParams(webhookDeliveryInsert(d)))
}

// ClearWebhookFailures ends the endpoint's failure run; false when the account has no such
// endpoint.
func (s *Postgres) ClearWebhookFailures(ctx context.Context, accountID, id string, now int64) (bool, error) {
	n, err := s.q.ClearWebhookFailures(ctx, pgdb.ClearWebhookFailuresParams{UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// CountWebhookFailure adds one failure to the endpoint's run and parks it when the run reaches
// limit; false when the account has no such endpoint.
func (s *Postgres) CountWebhookFailure(ctx context.Context, accountID, id string, limit, now int64) (bool, error) {
	n, err := s.q.CountWebhookFailure(ctx, pgdb.CountWebhookFailureParams{Failures: limit - 1, UpdatedAt: now, AccountID: accountID, ID: id})
	return n == 1, err
}

// ListWebhookDeliveries returns up to limit of one endpoint's attempts, newest first.
func (s *Postgres) ListWebhookDeliveries(ctx context.Context, accountID, endpointID string, limit int) ([]WebhookDelivery, error) {
	rs, err := s.q.ListWebhookDeliveries(ctx, pgdb.ListWebhookDeliveriesParams{AccountID: accountID, EndpointID: endpointID, Limit: pgLimit(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]WebhookDelivery, 0, len(rs))
	for _, r := range rs {
		out = append(out, webhookDeliveryFromRow(sqlitedb.WebhookDelivery(r)))
	}
	return out, nil
}

// WebhookAccounts returns every account with an endpoint, active or paused.
func (s *Postgres) WebhookAccounts(ctx context.Context) ([]string, error) {
	return s.q.ListWebhookAccounts(ctx)
}

// WebhookCursor returns the id of the account's last change the dispatcher claimed, 0 before its
// first claim.
func (s *Postgres) WebhookCursor(ctx context.Context, accountID string) (int64, error) {
	return cursorOf(s.q.GetWebhookCursor(ctx, accountID))
}

// ClaimWebhookCursor moves the account's cursor from `from`, the id the caller read, to `to`;
// false, changing nothing, when another process moved it first.
func (s *Postgres) ClaimWebhookCursor(ctx context.Context, accountID string, from, to int64) (bool, error) {
	var n int64
	var err error
	if from == 0 {
		n, err = s.q.StartWebhookCursor(ctx, pgdb.StartWebhookCursorParams{AccountID: accountID, LastChangeID: to})
	} else {
		n, err = s.q.MoveWebhookCursor(ctx, pgdb.MoveWebhookCursorParams{LastChangeID: to, AccountID: accountID, LastChangeID_2: from})
	}
	return n == 1, err
}
