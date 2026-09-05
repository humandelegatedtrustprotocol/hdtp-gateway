package relay

// The CLIENT side of relay mode (SPEC §10.5, PACT §9): a node that publishes a
// relay as `X-PACT-GATEWAY` fetches its mail from it, and any node falls back
// to a peer's relay when direct delivery fails.
//
// Two rules keep this honest:
//   - A fetched envelope is NOT trusted because the relay handed it over. It
//     goes through the standard open order (§4.4) exactly like a direct call,
//     with one documented relaxation: relay-delivered envelopes are exempt from
//     the 300 s timestamp window and bounded by `exp` alone.
//   - Fallback is automatic but never silent: it is audited, and it happens
//     only after direct delivery has actually failed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/envelope"
)

// Fetch backoff bounds (PACT §9: the relay may also push a content-free ping,
// which simply wakes the loop early).
const (
	MinPoll = 15 * time.Second
	MaxPoll = 10 * time.Minute
)

// QueuedItem is one envelope as the relay hands it back.
type QueuedItem struct {
	ID       string             `json:"id"`
	Envelope *envelope.Envelope `json:"envelope"`
	QueuedAt int64              `json:"queued_at"`
}

// Transport is the calling surface the client needs — one method, so a real
// outbound.Client, a test double, or an in-process relay all satisfy it.
type Transport interface {
	Call(ctx context.Context, tool string, args map[string]any) (*mcp.CallToolResult, error)
}

// Client fetches from, and delivers to, a relay.
type Client struct {
	Transport Transport
	Audit     func(action, resource, outcome string)
	// Process handles one fetched envelope through the node's §4.4 pipeline.
	// Returning nil means "handled": the item is acked and deleted.
	Process func(ctx context.Context, item QueuedItem) error
	// Jitter is a seam for tests; nil uses rand.
	Jitter func(d time.Duration) time.Duration
	// Allowlist, when set, reports who may currently queue for this node (its
	// active contacts). Run re-syncs whenever the answer changes: a contact
	// added after startup must reach the relay, and a relay that lost its state
	// must be repopulated. Nil disables re-syncing.
	Allowlist func(ctx context.Context) ([]string, error)
	// PostAllowlist delivers that list to the relay. It is deliberately NOT the
	// MCP Transport: the allow-list is the relay's own control plane, not one of
	// PACT §9's three verbs (see Server.AllowlistHandler). Nil means this client
	// cannot sync, and syncIfChanged simply does nothing.
	PostAllowlist func(ctx context.Context, senders []string) error

	lastSent string
}

func (c *Client) audit(action, resource, outcome string) {
	if c.Audit != nil {
		c.Audit(action, resource, outcome)
	}
}

func result(res *mcp.CallToolResult) (string, bool) {
	if res == nil || len(res.Content) == 0 {
		return "", false
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return "", false
	}
	return tc.Text, !res.IsError
}

// SyncAllowlist tells the relay which senders may queue for this node — the
// node's own active contacts, nobody else (§10.5).
func (c *Client) SyncAllowlist(ctx context.Context, senders []string) error {
	if c.PostAllowlist == nil {
		return fmt.Errorf("relay: no allow-list endpoint configured")
	}
	if err := c.PostAllowlist(ctx, senders); err != nil {
		return err
	}
	c.audit("relay_allowlist_sync", "relay", fmt.Sprintf("%d", len(senders)))
	return nil
}

// FetchOnce fetches, processes and acks one batch. It returns how many items
// were handled — the caller's cue for whether to poll again immediately.
func (c *Client) FetchOnce(ctx context.Context) (int, error) {
	res, err := c.Transport.Call(ctx, "fetch_queued", map[string]any{
		// Ask the relay to hold an empty fetch (§9's content-free wake). An old
		// relay ignores this and answers at once — Run reads the elapsed time
		// to tell the two apart.
		"wait_seconds": int(MaxWait / time.Second),
	})
	if err != nil {
		return 0, err
	}
	body, ok := result(res)
	if !ok {
		return 0, fmt.Errorf("relay: fetch refused")
	}
	var payload struct {
		Items []QueuedItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return 0, fmt.Errorf("relay: fetch payload: %w", err)
	}
	handled := 0
	for _, item := range payload.Items {
		if item.Envelope == nil {
			continue
		}
		// The relay is not trusted: the envelope passes the full open order.
		if err := c.Process(ctx, item); err != nil {
			// A bad item must not wedge the queue: it stays until it expires,
			// and the failure is audited (§10.5, §11).
			c.audit("relay_process", "item:"+item.ID, "rejected")
			continue
		}
		if _, err := c.Transport.Call(ctx, "ack", map[string]any{"id": item.ID}); err != nil {
			return handled, err
		}
		handled++
	}
	if handled > 0 {
		c.audit("relay_fetch", "relay", fmt.Sprintf("%d", handled))
	}
	return handled, nil
}

// Run polls until ctx ends. wake is the optional "you have mail" channel: a
// signal on it fetches immediately instead of waiting out the backoff.
func (c *Client) Run(ctx context.Context, wake <-chan struct{}) {
	delay := MinPoll
	for {
		c.syncIfChanged(ctx)
		started := time.Now()
		n, err := c.FetchOnce(ctx)
		held := err == nil && n == 0 && time.Since(started) >= MaxWait/2
		switch {
		case err != nil:
			delay = c.next(delay) // unreachable relay: back off
		case n > 0:
			delay = MinPoll // more may be waiting
		case held:
			// The relay held the empty fetch for us — it is doing the waiting,
			// so the next poll goes out immediately and idle latency is the
			// hold length, not the backoff. An old relay answers at once and
			// lands in the branch below, exactly today's cadence.
			delay = MinPoll
			continue
		default:
			delay = c.next(delay)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-wake:
			t.Stop()
			delay = MinPoll
		case <-t.C:
		}
	}
}

// syncIfChanged re-sends the allow-list when it differs from the last one this
// client sent. Cheap when nothing changed (a string compare), and it is the
// only thing that keeps a long-running node's relay permissions current.
func (c *Client) syncIfChanged(ctx context.Context) {
	if c.Allowlist == nil || c.PostAllowlist == nil {
		return
	}
	senders, err := c.Allowlist(ctx)
	if err != nil {
		return
	}
	sorted := append([]string(nil), senders...)
	sort.Strings(sorted)
	key := strings.Join(sorted, "\x00")
	if key == c.lastSent {
		return
	}
	if err := c.SyncAllowlist(ctx, sorted); err != nil {
		return // the relay is down; the next tick tries again
	}
	c.lastSent = key
}

func (c *Client) next(d time.Duration) time.Duration {
	d *= 2
	if d > MaxPoll {
		d = MaxPoll
	}
	if c.Jitter != nil {
		return c.Jitter(d)
	}
	// full jitter: spread reconnects so a restarted relay is not stampeded
	// #nosec G404 -- backoff jitter, not a secret; predictability costs nothing here
	return time.Duration(float64(d) * (0.5 + rand.Float64()/2))
}

/* --------------------------- outbound fallback --------------------------- */

// ErrNoRelay says the peer published no gateway, so there is nothing to fall
// back to and the direct failure stands.
var ErrNoRelay = errors.New("relay: peer has no X-PACT-GATEWAY")

// Deliverer delivers one sealed envelope directly to a peer.
type Deliverer func(ctx context.Context) error

// Fallback is the sender-side rule of PACT §7: try direct; on failure, if the
// peer's card names a relay, queue the SAME sealed envelope there instead.
// Sealing is unchanged — the relay carries ciphertext either way.
type Fallback struct {
	// Direct attempts delivery to the peer's endpoint.
	Direct Deliverer
	// RelayTransport talks to the peer's gateway; nil = no relay published.
	RelayTransport Transport
	Audit          func(action, resource, outcome string)
}

// Deliver runs the chain and reports which path succeeded.
func (f Fallback) Deliver(ctx context.Context, peerFpr string, env *envelope.Envelope) (path string, err error) {
	if f.Direct != nil {
		if err = f.Direct(ctx); err == nil {
			return "direct", nil
		}
	}
	if f.RelayTransport == nil {
		if f.Audit != nil {
			f.Audit("delivery", "contact:"+peerFpr, "failed")
		}
		if err == nil {
			err = ErrNoRelay
		}
		return "", fmt.Errorf("%w (and %v)", ErrNoRelay, err)
	}
	res, rerr := f.RelayTransport.Call(ctx, "relay_call", map[string]any{"to": peerFpr, "envelope": env})
	if rerr != nil {
		if f.Audit != nil {
			f.Audit("delivery", "contact:"+peerFpr, "relay_unreachable")
		}
		return "", fmt.Errorf("relay: %w (direct also failed: %v)", rerr, err)
	}
	body, ok := result(res)
	if !ok {
		if f.Audit != nil {
			f.Audit("delivery", "contact:"+peerFpr, "relay_refused")
		}
		return "", fmt.Errorf("relay refused: %s (direct also failed: %v)", body, err)
	}
	if f.Audit != nil {
		f.Audit("delivery", "contact:"+peerFpr, "queued_at_relay")
	}
	return "relay", nil
}
