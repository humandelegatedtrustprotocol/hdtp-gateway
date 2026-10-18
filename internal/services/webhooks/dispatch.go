package webhooks

// The dispatcher: a reader of the change log (SPEC §7.8) that posts each change a webhook carries
// to the account's endpoints that want it. It is BatonDeck's publish.ts and the attempt of
// deliver.ts, with the cloud's queue replaced by the node's change log, read from a cursor per
// account (item W2 of docs/release/webhooks-2026-10-18.md).
//
// One attempt, never retried (ruling C). The cursor is claimed for a change BEFORE the change is
// posted. A process that stops mid-post does not post the change again when it starts. Of two
// processes on one store, only the one whose claim moves the cursor posts the change. The
// "webhooks" lease (SPEC §11.1) keeps a second process from reading the log at all while the
// first holds it. The claim is what holds when a holder stalls past its lease.
//
// Nothing here can fail the change it posts: the change was recorded before the dispatcher read
// it. A failure is swallowed, and what stays of it is one line naming the stage, the account and
// the event's type, never the error's text (Building rule 10), as the cloud's PublishFailure.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// Timeout is how long an attempt may take, answer included; one that takes longer has failed.
const Timeout = 10 * time.Second

// LeaseName is the lease a process holds to dispatch (SPEC §11.1).
const LeaseName = "webhooks"

// cursorPage is how many of an account's changes one read takes; a full page is read again at once.
const cursorPage = 500

// The stages a swallowed failure is logged as, the cloud's codes where the cloud has the stage:
//   - webhook_accounts_unreadable, webhook_cursor_unreadable, webhook_changes_unreadable: the
//     accounts with an endpoint, an account's cursor, or the account and its change log could not
//     be read, so nothing was sent from it this pass;
//   - webhook_cursor_unwritable: a change could not be claimed, so it was not sent; the next pass
//     reads it again;
//   - webhook_endpoints_unreadable: the account's endpoints could not be listed; nothing was sent;
//   - webhook_secret_unreadable: an endpoint's row or sealed secret could not be read or opened;
//     that endpoint and the ones after it were not sent the event;
//   - webhook_previous_secret_unreadable (a warning): the secret a rotation replaced would not
//     open; the delivery went ahead, signed with the current one only;
//   - webhook_delivery_record_failed: the attempt was made and its row, or the endpoint's failure
//     count, was not written; the endpoints after it were not sent the event;
//   - webhook_publish_failed: the body could not be written; nothing was sent.
const (
	failAccounts     = "webhook_accounts_unreadable"
	failCursor       = "webhook_cursor_unreadable"
	failChanges      = "webhook_changes_unreadable"
	failClaim        = "webhook_cursor_unwritable"
	failEndpoints    = "webhook_endpoints_unreadable"
	failSecret       = "webhook_secret_unreadable"
	warnPreviousLost = "webhook_previous_secret_unreadable"
	failRecord       = "webhook_delivery_record_failed"
	failPublish      = "webhook_publish_failed"
)

// Dispatcher posts what the change log records to the endpoints that want it. Build one with
// NewDispatcher and start it with Run.
type Dispatcher struct {
	svc     *Service
	bus     *messaging.Bus
	leading func(context.Context) bool
	client  *http.Client
	agent   string
	log     io.Writer
}

// NewDispatcher is a dispatcher over svc's store and keyring. It is woken by bus. It reads only
// while leading reports that this process holds LeaseName (nil: always). It sends version in its
// user agent and writes its failure lines to log.
//
// A redirect is not followed: the 3xx is the answer, and a failure. The owner named one address
// (ruling A), and a redirect would post the signed event to an address the owner did not name.
func NewDispatcher(svc *Service, bus *messaging.Bus, leading func(context.Context) bool, version string, log io.Writer) *Dispatcher {
	return &Dispatcher{svc: svc, bus: bus, leading: leading, agent: "hdtp-gateway-webhooks/" + version, log: log,
		client: &http.Client{
			Timeout:       Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
}

// Run dispatches until ctx ends. It is woken by every event the bus delivers, with
// messaging.PollInterval as the floor, so a wake the bus dropped costs at most that long.
func (d *Dispatcher) Run(ctx context.Context) {
	events, cancel := d.bus.Subscribe("")
	defer cancel()
	tick := time.NewTicker(messaging.PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-events:
		}
		// One pass reads everything there is, so the wakes queued meanwhile are spent.
		for drained := false; !drained; {
			select {
			case <-events:
			default:
				drained = true
			}
		}
		if d.leading == nil || d.leading(ctx) {
			d.Pass(ctx)
		}
	}
}

// Pass reads every account's change log from its cursor and posts each change a webhook carries.
func (d *Dispatcher) Pass(ctx context.Context) {
	accounts, err := d.svc.store.WebhookAccounts(ctx)
	if err != nil {
		d.fail(ctx, failAccounts, "", "")
		return
	}
	for _, accountID := range accounts {
		d.account(ctx, accountID)
	}
}

// account posts what one account's change log holds after its cursor.
func (d *Dispatcher) account(ctx context.Context, accountID string) {
	st := d.svc.store
	from, err := st.WebhookCursor(ctx, accountID)
	if err != nil {
		d.fail(ctx, failCursor, accountID, "")
		return
	}
	a, err := st.GetAccountByID(ctx, accountID)
	if err != nil {
		d.fail(ctx, failChanges, accountID, "")
		return
	}
	for {
		rows, err := st.AccountChangesAfter(ctx, accountID, from, cursorPage)
		if err != nil {
			d.fail(ctx, failChanges, accountID, "")
			return
		}
		for _, c := range rows {
			claimed, err := st.ClaimWebhookCursor(ctx, accountID, from, c.ID)
			if err != nil {
				d.fail(ctx, failClaim, accountID, "")
				return
			}
			if !claimed {
				return // another process moved the cursor: what follows is its
			}
			from = c.ID
			if event, ok := EnvelopeOf(c, a.Slug); ok {
				d.publish(ctx, accountID, event)
			}
		}
		if len(rows) < cursorPage {
			return
		}
	}
}

// publish posts one event to every endpoint of the account that wants it, one after another: an
// account has a handful, and a fan-out is how one slow receiver becomes everybody's problem.
func (d *Dispatcher) publish(ctx context.Context, accountID string, event EventEnvelope) {
	body, err := EnvelopeBody(event)
	if err != nil {
		d.fail(ctx, failPublish, accountID, event.Type)
		return
	}
	endpoints, err := d.svc.List(ctx, accountID)
	if err != nil {
		d.fail(ctx, failEndpoints, accountID, event.Type)
		return
	}
	for _, e := range TargetsFor(endpoints, event) {
		if !d.deliverOnce(ctx, accountID, e.ID, event, body) {
			return
		}
	}
}

// deliverOnce makes the one attempt to post event to the endpoint and records it; false when a
// failure means the endpoints after it are not sent the event.
func (d *Dispatcher) deliverOnce(ctx context.Context, accountID, endpointID string, event EventEnvelope, body string) bool {
	row, err := d.svc.store.GetWebhookEndpoint(ctx, accountID, endpointID)
	if errors.Is(err, store.ErrNotFound) {
		return true // removed since it was listed: nobody to send to, and nothing failed
	}
	if err != nil {
		d.fail(ctx, failSecret, accountID, event.Type)
		return false
	}
	if row.Status != "active" {
		return true // paused since it was listed
	}
	at := d.svc.now()
	secrets, previousLost, err := d.svc.SecretsFor(row, at.UnixMilli())
	if err != nil {
		d.fail(ctx, failSecret, accountID, event.Type)
		return false
	}
	if previousLost {
		d.fail(ctx, warnPreviousLost, accountID, event.Type)
	}
	deliveryID := NewDeliveryID()
	out := d.attempt(ctx, row.URL, secrets, event, body, deliveryID, at)
	// The attempt was made, so it is logged even when the process is stopping: the change was
	// claimed and is never posted again, and a log missing it would say it was never sent.
	if _, err := d.svc.RecordAttempt(context.WithoutCancel(ctx), accountID, deliveryID, row.ID, event, out); err != nil {
		d.fail(ctx, failRecord, accountID, event.Type)
		return false
	}
	return true
}

// attempt posts body once, signed with secrets at the time at, and says what happened; it writes
// nothing. A non-2xx is a failure and so is a timeout, a refused connection, a DNS failure and a
// TLS failure: they are the same fact, "this did not arrive", and the excerpt tells them apart.
func (d *Dispatcher) attempt(ctx context.Context, address string, secrets []string, event EventEnvelope, body, deliveryID string, at time.Time) AttemptOutcome {
	started := time.Now()
	failed := func(reason string) AttemptOutcome {
		return AttemptOutcome{LatencyMs: time.Since(started).Milliseconds(), Excerpt: reason}
	}
	signature, err := Signature(secrets, body, at.Unix())
	if err != nil {
		return failed(err.Error())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, strings.NewReader(body))
	if err != nil {
		return failed(err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, signature)
	req.Header.Set(EventIDHeader, event.ID)
	req.Header.Set(EventTypeHeader, event.Type)
	// The delivery id, not the event id: it names one row of the delivery log, which is what a
	// receiver quotes about a delivery.
	req.Header.Set(DeliveryHeader, deliveryID)
	req.Header.Set("User-Agent", d.agent)
	resp, err := d.client.Do(req)
	if err != nil {
		// The reason without the address: http's error names the URL, and a receiver may keep a
		// token in it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return failed(err.Error())
	}
	defer resp.Body.Close()
	// At most ExcerptBytes of the answer is read; closing the body unread ends an endless one.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, ExcerptBytes))
	if len(b) == ExcerptBytes {
		// The read stopped at the limit, perhaps inside a character: the part of it read is not kept.
		i := len(b) - 1
		for i > 0 && len(b)-i < utf8.UTFMax && !utf8.RuneStart(b[i]) {
			i--
		}
		if !utf8.FullRune(b[i:]) {
			b = b[:i]
		}
	}
	return AttemptOutcome{OK: resp.StatusCode >= 200 && resp.StatusCode < 300, HTTPStatus: int64(resp.StatusCode),
		LatencyMs: time.Since(started).Milliseconds(), Excerpt: string(b)}
}

// fail writes one line naming the stage that failed, the account and the event's type. Nothing is
// written once ctx has ended: a shutdown is not a failure.
func (d *Dispatcher) fail(ctx context.Context, code, accountID, eventType string) {
	if ctx.Err() != nil || d.log == nil {
		return
	}
	line := "webhooks: " + code
	if accountID != "" {
		line += " account:" + accountID
	}
	if eventType != "" {
		line += " event_type:" + eventType
	}
	fmt.Fprintln(d.log, line)
}
