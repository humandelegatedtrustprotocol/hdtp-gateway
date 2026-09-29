// Package limits is the node's side of PACT SPEC §12's call budgets: a client of the limits
// sidecar (cmd/pact-limitd), asked over a kept-open unix socket for every decision (layer 2 of
// docs/release/two-layer-limits-2026-09-28.md; the owner's choice of 2026-09-29, §6).
//
// The node decides nothing about a budget itself. It opens the envelope, works out what the call
// is charged to (the caller's tier, its root, its source, the identity's contact cap) and asks;
// the sidecar holds the numbers (its configuration file) and the counters, one set for every
// account and every node process on the host. A sidecar that does not answer is an error here,
// and the node answers every sealed call `unavailable` until it does: a budget nobody can enforce
// is not a budget the node may guess at.
//
// The wire is one JSON object a line, both ways (cmd/pact-limitd/src/lib.rs): a charge is the
// contract's LimitsCharge (pact-identity CONTRACT §6.3), an answer the contract's `limits_decide`
// result without its `writes`. Every request names the identity, and every counter is that
// identity's.
package limits

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ErrUnavailable is the sidecar not answering: not dialled, not answering in time, or answering
// something that does not read. Every such failure wraps it.
var ErrUnavailable = errors.New("the limits sidecar is not answering")

// Charge is what one call is charged to (CONTRACT §6.3 LimitsCharge). Build one with the
// constructors below; the zero value is not a charge.
type Charge struct {
	kind string
	// members holds exactly the kind's members, so a charge is sent with nothing the sidecar
	// would refuse as a stranger and nothing it needs left out (guest_in's `addressed` false,
	// its `source` empty).
	members map[string]any
}

// ContactIn is an active contact calling in: its own bucket, then the identity's aggregate sized
// by contactCap.
func ContactIn(root string, contactCap int) Charge {
	return Charge{"contact_in", map[string]any{"kind": "contact_in", "root": root, "contact_cap": contactCap}}
}

// GuestIn is anybody else calling in — a guest, a pending root, a blocked or superseded root —
// by the root the envelope proved (empty when none was: a small form answered chain_required) and
// the source it came from; addressed is whether the transport gave a source at all.
func GuestIn(root, source string, addressed bool) Charge {
	var r any
	if root != "" {
		r = root
	}
	return Charge{"guest_in", map[string]any{"kind": "guest_in", "root": r, "source": source, "addressed": addressed}}
}

// ContactOut is a call out to an active contact: its bucket, then the identity's outbound aggregate.
func ContactOut(root string, contactCap int) Charge {
	return Charge{"contact_out", map[string]any{"kind": "contact_out", "root": root, "contact_cap": contactCap}}
}

// StrangerOut is a call out to anybody who is not an active contact, or one that starts or
// answers a relationship.
func StrangerOut() Charge { return Charge{"stranger_out", map[string]any{"kind": "stranger_out"}} }

// Integration is a call to one integration by one contact: the owner's upstream quota, which one
// contact may not spend all of.
func Integration(integrationID, contact string) Charge {
	return Charge{"integration", map[string]any{"kind": "integration", "integration": integrationID, "contact": contact}}
}

// PendingIn is a request from a stranger while the identity holds `held` requests already: a
// count against the cap, no bucket.
func PendingIn(held int64) Charge {
	return Charge{"pending_in", map[string]any{"kind": "pending_in", "held": held}}
}

// Kind names the charge, for an audit row.
func (c Charge) Kind() string { return c.kind }

// Decision is the sidecar's answer.
type Decision struct {
	Allowed bool
	// RetryAfter is the whole seconds until every refusing bucket holds a call again; zero when
	// allowed, and zero for the pending cap, which no wait refills (Countable says which).
	RetryAfter time.Duration
	// RefusedBy names the bucket that refused (contract §6.3), or `pending_in`; empty when allowed.
	RefusedBy string
	// Countable is false for a refusal no wait ends (the pending cap): the answer to a peer is
	// `unavailable`, not `rate_limited`, since no number of seconds is true of a full list.
	Countable bool
}

// Rules is the rules document the sidecar enforces, as its configuration holds it (CONTRACT §6.3
// LimitsRules): what get_card advertises is read from here and nowhere else.
type Rules struct {
	ContactCallsPerSecond     float64 `json:"contact_calls_per_second"`
	ContactBurst              float64 `json:"contact_burst"`
	IdentityCapacityPerSecond float64 `json:"identity_capacity_per_second"`
	GuestCallsPerHour         float64 `json:"guest_calls_per_hour"`
	GuestSourceCallsPerHour   float64 `json:"guest_source_calls_per_hour"`
	StrangerCallsOutPerHour   float64 `json:"stranger_calls_out_per_hour"`
	IntegrationCallsPerHour   float64 `json:"integration_calls_per_hour"`
	GuestTotalCallsPerHour    float64 `json:"guest_total_calls_per_hour"`
	PendingInCap              float64 `json:"pending_in_cap"`
}

// Advertised is what get_card says of the call budgets (PACT §12's `limits` members about calls)
// for an identity allowed a number of contacts: the sidecar's rules, and the identity's aggregate as
// the crate computes it, so this host holds no copy of that formula.
type Advertised struct {
	ContactCallsPerSecond   float64 `json:"contact_calls_per_second"`
	ContactBurst            float64 `json:"contact_burst"`
	IdentityCallsPerSecond  float64 `json:"identity_calls_per_second"`
	GuestCallsPerHour       float64 `json:"guest_calls_per_hour"`
	GuestSourceCallsPerHour float64 `json:"guest_source_calls_per_hour"`
}

// Status is what the health check, doctor and the serve banner say about the sidecar.
type Status struct {
	Path string
	// Answering is whether the last exchange with the sidecar succeeded.
	Answering bool
	// Why is the last failure, when not answering.
	Why string
}

// Client asks one sidecar over one kept-open connection. Safe for concurrent use: requests are
// serialised on the connection, which is what the sidecar's line protocol expects.
type Client struct {
	// Path is the sidecar's unix socket.
	Path string
	// Timeout bounds one exchange, dial included; zero is DefaultTimeout.
	Timeout time.Duration

	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
	rules   *Rules
	lastErr error
	ever    bool // whether any exchange has been attempted
}

// DefaultTimeout is how long one exchange may take: a local socket answers in microseconds, and
// a sidecar that takes longer than this is one that is not answering.
const DefaultTimeout = 2 * time.Second

// New is a client of the sidecar at path. Nothing is dialled until the first exchange.
func New(path string) *Client { return &Client{Path: path} }

// Decide charges one call of identity's budget to charge, or reports how long until it may be.
func (c *Client) Decide(ctx context.Context, identity string, charge Charge, now time.Time) (Decision, error) {
	return c.ask(ctx, "decide", identity, charge, now)
}

type answer struct {
	Allowed    bool        `json:"allowed"`
	RetryAfter *uint64     `json:"retry_after"`
	RefusedBy  *string     `json:"refused_by"`
	Rules      *Rules      `json:"rules"`
	Limits     *Advertised `json:"limits"`
	Error      *string     `json:"error"`
}

func (c *Client) ask(ctx context.Context, op, identity string, charge Charge, now time.Time) (Decision, error) {
	if charge.kind == "" {
		return Decision{}, errors.New("limits: a zero Charge is not a charge")
	}
	req := map[string]any{"op": op, "identity": identity, "charge": charge.members, "now": now.UnixMilli()}
	a, err := c.exchange(ctx, req)
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Allowed: a.Allowed}
	if a.RefusedBy != nil {
		d.RefusedBy = *a.RefusedBy
	}
	if a.RetryAfter != nil {
		d.Countable = true
		d.RetryAfter = time.Duration(*a.RetryAfter) * time.Second
	}
	return d, nil
}

// Advertise is what get_card says of the call budgets for an identity allowed contactCap contacts.
// It spends nothing.
func (c *Client) Advertise(ctx context.Context, contactCap int) (Advertised, error) {
	a, err := c.exchange(ctx, map[string]any{"op": "card", "contact_cap": contactCap})
	if err != nil {
		return Advertised{}, err
	}
	if a.Limits == nil {
		return Advertised{}, c.failed(fmt.Errorf("%w: it answered no limits", ErrUnavailable))
	}
	return *a.Limits, nil
}

// Rules is the sidecar's rules document, read once and kept: the numbers get_card advertises.
// A sidecar restarted with other numbers is read again by Probe.
func (c *Client) Rules(ctx context.Context) (Rules, error) {
	c.mu.Lock()
	cached := c.rules
	c.mu.Unlock()
	if cached != nil {
		return *cached, nil
	}
	return c.Probe(ctx)
}

// Probe asks the sidecar for its rules, which is the one exchange that spends nothing and proves
// the sidecar answers: the health check, doctor and serve's banner make it.
func (c *Client) Probe(ctx context.Context) (Rules, error) {
	a, err := c.exchange(ctx, map[string]any{"op": "rules"})
	if err != nil {
		return Rules{}, err
	}
	if a.Rules == nil {
		return Rules{}, c.failed(fmt.Errorf("%w: it answered no rules", ErrUnavailable))
	}
	c.mu.Lock()
	c.rules = a.Rules
	c.mu.Unlock()
	return *a.Rules, nil
}

// Status reports the last exchange's outcome. Before any exchange it is not answering, with why:
// nothing has been asked of it.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{Path: c.Path, Answering: c.ever && c.lastErr == nil}
	switch {
	case !c.ever:
		s.Why = "not asked yet"
	case c.lastErr != nil:
		s.Why = c.lastErr.Error()
	}
	return s
}

// Close drops the connection; the next exchange dials again.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropLocked()
}

func (c *Client) failed(err error) error {
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
	return err
}

// exchange sends one request and reads one answer, on the kept connection when it has one and on
// a fresh one otherwise. A connection that fails mid-exchange is dropped and the request tried
// once more on a fresh one: a sidecar restarted between two calls costs one reconnect, not a
// refusal. An answer carrying `error` is the sidecar refusing the request, which is a defect of
// this client, not of the sidecar, and is reported as such.
func (c *Client) exchange(ctx context.Context, req map[string]any) (answer, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return answer{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ever = true
	var a answer
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.connectLocked(ctx); err != nil {
			last = err
			break
		}
		a, err = c.roundTripLocked(ctx, body)
		if err == nil {
			break
		}
		last = err
		_ = c.dropLocked()
	}
	if last != nil {
		c.lastErr = fmt.Errorf("%w: %v", ErrUnavailable, last)
		return answer{}, c.lastErr
	}
	if a.Error != nil {
		c.lastErr = fmt.Errorf("%w: the sidecar refused the request: %s", ErrUnavailable, *a.Error)
		return answer{}, c.lastErr
	}
	c.lastErr = nil
	return a, nil
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Client) connectLocked(ctx context.Context) error {
	if c.conn != nil {
		return nil
	}
	dialer := net.Dialer{Timeout: c.timeout()}
	conn, err := dialer.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return err
	}
	c.conn, c.reader = conn, bufio.NewReader(conn)
	return nil
}

func (c *Client) dropLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.reader = nil, nil
	return err
}

func (c *Client) roundTripLocked(ctx context.Context, body []byte) (answer, error) {
	deadline := time.Now().Add(c.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return answer{}, err
	}
	if _, err := c.conn.Write(append(body, '\n')); err != nil {
		return answer{}, err
	}
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return answer{}, err
	}
	var a answer
	if err := json.Unmarshal(line, &a); err != nil {
		return answer{}, fmt.Errorf("the answer does not read: %w", err)
	}
	return a, nil
}
