// Package webhooks is the node's outbound webhooks: where an account wants its events posted, the
// dispatcher that posts them, the signing secret each endpoint is shown once, and the log of what
// was posted. It is BatonDeck's gateway/src/webhooks/ ported to the node
// (docs/release/webhooks-2026-10-18.md), with the cloud's names, constants, refusal codes, envelope
// and signature grammar, over the node's store, keyring and change log.
package webhooks

// Webhook endpoints: where an account wants its events sent, and what may be one.
//
// The cloud dials a customer-chosen URL from inside its own network, so it refuses plain http, IP
// literals and inward names. The node does not (ruling A of the plan, 2026-10-18): only the node's
// owner registers an endpoint, through the portal, and an agent on the same host or in the same
// compose project is the receiver the feature is for. So http, loopback, LAN names and IP literals
// are taken, a named divergence from the cloud's not_https, literal_address and private_name.
// What stays is what is a mistake on either host: not_a_url, has_credentials (a URL that reads as
// one host and dials another) and unknown_event.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// RotationWindow is how long both secrets are accepted after a rotation. A day is a working day.
const RotationWindow = 24 * time.Hour

// FailureLimit is how many failures in a row park an endpoint.
const FailureLimit = 20

// EndpointLimit is the most endpoints Create lets an account have (the next one is a conflict),
// and the most List returns, as the cloud's listEndpoints. The cloud refuses no endpoint for
// their number.
const EndpointLimit = 100

// MaxURLBytes is the longest URL an endpoint takes, in bytes.
const MaxURLBytes = 2048

// The deliveries a log read returns: deliveriesDefault when the caller names no number, at most
// deliveriesMax, as the cloud's limitQuery(200, 50).
const (
	deliveriesDefault = 50
	deliveriesMax     = 200
)

// The reasons CheckEndpointURL refuses a URL, in the cloud's codes.
const (
	NotAURL        = "not_a_url"
	HasCredentials = "has_credentials"
	UnknownEvent   = "unknown_event"
	// URLTooLong is the node's own: the cloud bounds no URL.
	URLTooLong = "url_too_long"
)

// refusalWords is what each refusal says, in the cloud's words (BatonDeck's WEBHOOK_REFUSALS,
// gateway/src/api/v1/routes/shared.ts); unknown_event names the event first.
var refusalWords = map[string]string{
	NotAURL:        "That is not a URL.",
	HasCredentials: "Take the username and password out of the URL — a URL that carries them reads as one host and dials another.",
	UnknownEvent:   " is not an event we send, so a filter on it would never fire. The ones we send are listed on this page.",
	URLTooLong:     "That URL is longer than " + strconv.Itoa(MaxURLBytes) + " bytes, the most an endpoint takes.",
}

// Refused is beside the refusal of a registration a check refused: the cloud's code, and for
// unknown_event the name refused. What a door shows is the refusal.BadRequest joined to it.
type Refused struct{ Code, Detail string }

func (r Refused) Error() string { return "webhooks: " + r.Code + " " + r.Detail }

func refused(code, detail string) error {
	sentence := refusalWords[code]
	if code == UnknownEvent {
		sentence = detail + sentence
	}
	return errors.Join(refusal.BadRequest(sentence, nil), Refused{Code: code, Detail: detail})
}

// CheckEndpointURL is the reason a URL is not one the node will post to, or "" when it is. Go's
// url.Parse takes nearly anything, so a URL here is an absolute http or https URL with a host, of at
// most MaxURLBytes once trimmed.
func CheckEndpointURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > MaxURLBytes {
		return URLTooLong
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return NotAURL
	}
	// `https://receiver.example@evil.test/hook` reads as receiver.example and dials evil.test.
	if u.User != nil {
		return HasCredentials
	}
	return ""
}

// CheckEvents is the first name that is not an event the node emits, or "": a typo, or a name the
// cloud sends and the node does not, is a subscription that never fires.
func CheckEvents(events []string) string {
	names := Subscribable()
	for _, e := range events {
		if !slices.Contains(names, e) {
			return e
		}
	}
	return ""
}

// EndpointView is an endpoint as a door shows it: no secret, sealed or otherwise. Times are unix
// milliseconds.
type EndpointView struct {
	ID  string `json:"id"`
	URL string `json:"url"`
	// Events empty means every event.
	Events              []string `json:"events"`
	Status              string   `json:"status"`
	ConsecutiveFailures int64    `json:"consecutive_failures"`
	// RotatingUntil is when the previous secret stops being accepted; nil when no rotation is in
	// flight.
	RotatingUntil *int64 `json:"rotating_until"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

func parseList(raw string) []string {
	var v []string
	if json.Unmarshal([]byte(raw), &v) != nil || v == nil {
		return []string{}
	}
	return v
}

// viewOf projects a stored endpoint; RotatingUntil is set only while the previous secret is still
// accepted at now (unix milliseconds).
func viewOf(e store.WebhookEndpoint, now int64) EndpointView {
	v := EndpointView{ID: e.ID, URL: e.URL, Events: parseList(e.Events), Status: e.Status,
		ConsecutiveFailures: e.Failures, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt}
	if e.PreviousSealed != nil && e.PreviousUntil > now {
		until := e.PreviousUntil
		v.RotatingUntil = &until
	}
	return v
}

// Service is the one implementation of webhook endpoints and their log, under every door.
type Service struct {
	store store.Store
	kr    Sealer
	audit func(action, resource, outcome string)
	now   func() time.Time
}

// New is the webhooks service over st, sealing secrets with kr and auditing each change through
// audit.
func New(st store.Store, kr Sealer, audit func(action, resource, outcome string)) *Service {
	return &Service{store: st, kr: kr, audit: audit, now: time.Now}
}

func newID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand failure is unrecoverable
	}
	return prefix + hex.EncodeToString(b)
}

// account refuses an account the store does not hold, so a list of an unknown account is not
// found rather than empty.
func (s *Service) account(ctx context.Context, accountID string) error {
	if _, err := s.store.GetAccountByID(ctx, accountID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return refusal.NotFound("unknown account", err)
		}
		return err
	}
	return nil
}

// noEndpoint is a write or read that found no endpoint by the id of this account's.
func noEndpoint() error { return refusal.NotFound(refusal.NotFoundDetail, store.ErrNotFound) }

// Create registers an endpoint for the account and returns it with its signing secret, shown this
// once. The URL is stored trimmed, the filter without repeats. An account that has EndpointLimit
// endpoints is refused another (conflict), however many creates race for the last slot. The
// account's first endpoint starts the dispatcher's cursor at the newest change, so it is not walked
// through the log written before it, change by change, to reach the first one it may be sent.
func (s *Service) Create(ctx context.Context, accountID, rawURL string, events []string) (EndpointView, string, error) {
	if err := s.account(ctx, accountID); err != nil {
		return EndpointView{}, "", err
	}
	if code := CheckEndpointURL(rawURL); code != "" {
		s.audit("webhook_create", "account:"+accountID, "bad_request")
		return EndpointView{}, "", refused(code, "")
	}
	if name := CheckEvents(events); name != "" {
		s.audit("webhook_create", "account:"+accountID, "bad_request")
		return EndpointView{}, "", refused(UnknownEvent, name)
	}
	var filter []string
	for _, e := range events {
		if !slices.Contains(filter, e) {
			filter = append(filter, e)
		}
	}
	list, err := json.Marshal(append([]string{}, filter...))
	if err != nil {
		return EndpointView{}, "", err
	}
	secret, err := NewSigningSecret()
	if err != nil {
		return EndpointView{}, "", err
	}
	id := newID("whe_")
	sealed, err := s.seal(accountID, id, secret)
	if err != nil {
		return EndpointView{}, "", err
	}
	now := s.now().UnixMilli()
	e := store.WebhookEndpoint{ID: id, AccountID: accountID, URL: strings.TrimSpace(rawURL), Events: string(list),
		Status: "active", SecretSealed: sealed, CreatedAt: now, UpdatedAt: now}
	full := false
	err = s.store.Atomically(ctx, func(tx store.Store) error {
		// The account is locked first, so two creates on one store count one after the other and
		// the cap holds (on SQLite the transaction already runs alone).
		if err := tx.LockAccount(ctx, accountID); err != nil {
			return err
		}
		n, err := tx.CountWebhookEndpoints(ctx, accountID)
		if err != nil {
			return err
		}
		if n >= EndpointLimit {
			full = true
			return nil
		}
		if err := tx.InsertWebhookEndpoint(ctx, e); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		_, newest, err := tx.ChangeBounds(ctx)
		if err != nil {
			return err
		}
		return tx.StartWebhookCursorAt(ctx, accountID, newest)
	})
	if err != nil {
		return EndpointView{}, "", err
	}
	if full {
		s.audit("webhook_create", "account:"+accountID, "endpoint_cap")
		return EndpointView{}, "", refusal.Conflict("This identity has "+strconv.Itoa(EndpointLimit)+
			" endpoints, the most it can have. Remove one to add another.", nil)
	}
	// The host and never the address: a receiver may put a token in the path or the query, and an
	// audit row is never edited afterwards.
	u, _ := url.Parse(e.URL) // CheckEndpointURL parsed it
	s.audit("webhook_create", "account:"+accountID+" webhook:"+id+" host:"+u.Host, "ok")
	return viewOf(e, now), secret, nil
}

// List is the account's endpoints, newest first, at most EndpointLimit.
func (s *Service) List(ctx context.Context, accountID string) ([]EndpointView, error) {
	if err := s.account(ctx, accountID); err != nil {
		return nil, err
	}
	rows, err := s.store.ListWebhookEndpoints(ctx, accountID, EndpointLimit)
	if err != nil {
		return nil, err
	}
	now := s.now().UnixMilli()
	out := make([]EndpointView, len(rows))
	for i, r := range rows {
		out[i] = viewOf(r, now)
	}
	return out, nil
}

// Rotate gives the endpoint a new secret, shown this once, and keeps the one it replaces accepted
// until the returned time (unix milliseconds), RotationWindow on. A rotation during a rotation
// drops the oldest of three: two is what a receiver can be asked to accept at once. A paused
// endpoint rotates as an active one does.
func (s *Service) Rotate(ctx context.Context, accountID, id string) (secret string, until int64, err error) {
	secret, err = NewSigningSecret()
	if err != nil {
		return "", 0, err
	}
	sealed, err := s.seal(accountID, id, secret)
	if err != nil {
		return "", 0, err
	}
	now := s.now()
	until = now.Add(RotationWindow).UnixMilli()
	ok, err := s.store.RotateWebhookSecret(ctx, accountID, id, sealed, until, now.UnixMilli())
	if err != nil {
		return "", 0, err
	}
	if !ok {
		s.audit("webhook_rotate", "account:"+accountID+" webhook:"+id, "not_found")
		return "", 0, noEndpoint()
	}
	s.audit("webhook_rotate", "account:"+accountID+" webhook:"+id, "ok")
	return secret, until, nil
}

// SetStatus pauses an endpoint ("paused") or resumes one ("active"). Resuming clears the failure
// run: an endpoint parked for being down and since fixed must not be one failure from parked
// again. A parked endpoint is resumed by the owner, never by the node.
func (s *Service) SetStatus(ctx context.Context, accountID, id, status string) error {
	var (
		ok     bool
		err    error
		action string
	)
	now := s.now().UnixMilli()
	switch status {
	case "paused":
		action = "webhook_pause"
		ok, err = s.store.PauseWebhookEndpoint(ctx, accountID, id, now)
	case "active":
		action = "webhook_resume"
		ok, err = s.store.ResumeWebhookEndpoint(ctx, accountID, id, now)
	default:
		s.audit("webhook_status", "account:"+accountID+" webhook:"+id, "bad_request")
		return refusal.BadRequest(`status is "active" or "paused"`, nil)
	}
	if err != nil {
		return err
	}
	if !ok {
		s.audit(action, "account:"+accountID+" webhook:"+id, "not_found")
		return noEndpoint()
	}
	s.audit(action, "account:"+accountID+" webhook:"+id, "ok")
	return nil
}

// Remove deletes an endpoint. Its delivery rows stay, still naming it, until the retention pass
// takes them at their 30-day window (retention.WebhookDeliveriesKept); its log is not found once it
// is gone, as the cloud's.
func (s *Service) Remove(ctx context.Context, accountID, id string) error {
	ok, err := s.store.DeleteWebhookEndpoint(ctx, accountID, id)
	if err != nil {
		return err
	}
	if !ok {
		s.audit("webhook_delete", "account:"+accountID+" webhook:"+id, "not_found")
		return noEndpoint()
	}
	s.audit("webhook_delete", "account:"+accountID+" webhook:"+id, "ok")
	return nil
}

// DeliveryView is one attempt as a door shows it. HTTPStatus and ResponseExcerpt are nil when no
// answer came and when the answer was empty; times are unix milliseconds. The cloud's `attempt`
// (always 1) and `next_attempt_at` (always null) are not kept: there is no second attempt.
type DeliveryView struct {
	ID              string  `json:"id"`
	EndpointID      string  `json:"endpoint_id"`
	EventID         string  `json:"event_id"`
	EventType       string  `json:"event_type"`
	Status          string  `json:"status"`
	HTTPStatus      *int64  `json:"http_status"`
	LatencyMs       int64   `json:"latency_ms"`
	ResponseExcerpt *string `json:"response_excerpt"`
	CreatedAt       int64   `json:"created_at"`
}

// ListDeliveries is what was posted to one of the account's endpoints, newest first: limit rows,
// deliveriesDefault when limit is 0, refused outside 1 to deliveriesMax. The endpoint is looked up
// first, so the log of one that does not exist, or is another account's, is not found rather than
// empty.
func (s *Service) ListDeliveries(ctx context.Context, accountID, endpointID string, limit int) ([]DeliveryView, error) {
	if limit == 0 {
		limit = deliveriesDefault
	}
	if limit < 1 || limit > deliveriesMax {
		return nil, refusal.BadRequest("limit is a whole number from 1 to 200", nil)
	}
	if _, err := s.store.GetWebhookEndpoint(ctx, accountID, endpointID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, noEndpoint()
		}
		return nil, err
	}
	rows, err := s.store.ListWebhookDeliveries(ctx, accountID, endpointID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]DeliveryView, len(rows))
	for i, r := range rows {
		v := DeliveryView{ID: r.ID, EndpointID: r.EndpointID, EventID: r.EventID, EventType: r.EventType,
			Status: r.Status, LatencyMs: r.LatencyMs, CreatedAt: r.CreatedAt}
		if r.HTTPStatus != 0 {
			code := r.HTTPStatus
			v.HTTPStatus = &code
		}
		if r.Excerpt != "" {
			excerpt := r.Excerpt
			v.ResponseExcerpt = &excerpt
		}
		out[i] = v
	}
	return out, nil
}
