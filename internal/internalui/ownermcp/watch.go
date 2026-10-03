// The owner's agent is not always connected, and the owner MCP pushes nothing
// (SPEC §8.5): it is stateless, so there is no stream to push on, and the bus
// is explicitly "a hint, not the ledger" (§7.8).
//
// These two tools are how the agent finds out instead. `wait_for_updates` blocks until
// something happens (or the timeout elapses) and answers with what changed since
// the caller's cursor, so a loop is one call and a restart loses nothing.
// `digest` answers the end-of-day question — what arrived, from whom, and what
// is still unanswered — in a single call rather than a walk over every thread.
//
// Neither decides anything. What to do about a message — reply, escalate to the
// human, or leave it for the digest — is the agent's judgment, and putting that
// policy in the node would be a second, worse agent (SPEC §7.7: the node labels
// and hands over; it does not act on a contact's words).
package ownermcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// WaitArgs is a resumable cursor and a bound on how long to hold the call.
type WaitArgs struct {
	AccountID string `json:"account_id"`
	// Since is the cursor from a previous answer: an id of the store's change log (SPEC §7.8),
	// the same in every node process sharing the store. Omit it to start watching from now: the
	// first call returns immediately with a cursor and no backlog, so an agent can begin a loop
	// without replaying its history. A pointer, because 0 is a cursor like any other (the answer
	// on a store whose change log is empty) and must not read as "omitted".
	Since *int64 `json:"since,omitempty" jsonschema:"cursor from a previous wait_for_updates; omit to start from now"`
	// TimeoutSec bounds the wait: whole seconds from 1 to WaitMaxSec, WaitMaxSec
	// when omitted. A pointer, so an omitted bound (the default) and an explicit 0
	// (refused: it would answer at once, and a loop on it spins) are told apart.
	TimeoutSec *int64 `json:"timeout_sec,omitempty" jsonschema:"seconds to wait for something to happen, from 1 to 25; 25 when omitted"`
}

// WaitMaxSec is the longest wait_for_updates holds a call, and its default: the
// hosted edition's bound too (batondeck WATCH_WAIT_MAX_SEC, its /v1 watchChanges
// and its owner MCP's wait), so an agent written for one host waits the same on
// the other. Under half a minute, so a proxy's or a platform's idle timeout does
// not cut a call mid-wait.
const WaitMaxSec = 25

type DigestArgs struct {
	AccountID string `json:"account_id"`
	// SinceTS bounds the window; omit for the last 24 hours.
	SinceTS int64 `json:"since_ts,omitempty" jsonschema:"unix seconds; omit for the last 24 hours"`
}

// changed is one thread that moved, with enough to decide whether to look
// closer. The bodies are deliberately not here: they are untrusted text and the
// agent should read them through read_thread, which labels every one with the
// contact's trust flag (§7.7).
type changed struct {
	ThreadID   string `json:"thread_id"`
	ContactFpr string `json:"contact_fpr"`
	Contact    string `json:"contact,omitempty"`
	Unread     int64  `json:"unread"`
	LastAt     int64  `json:"last_at"`
	// Trust is the OWNER's stance on this contact (§7.6), carried here so the
	// agent can triage without a read: may_instruct threads may be acted on,
	// messages_only threads are raised to the human. The label is resolved
	// from the owner's row — nothing the contact sent can influence it.
	Trust string `json:"trust,omitempty"`
}

// callEvent is one substantive tool call a contact made against this account
// since the cursor — a booking, a media send, an availability check. Sourced
// from the audit trail, so it is exactly what the node recorded, and it names
// only the caller and the tool: arguments are the peer's untrusted input and
// stay behind read_thread / the audit page.
type callEvent struct {
	ContactFpr string `json:"contact_fpr"`
	Tool       string `json:"tool"`
	Trust      string `json:"trust,omitempty"`
	At         int64  `json:"at"`
}

// attention is a condition only the owner can clear.
type attention struct {
	Kind        string `json:"kind"` // integration_auth
	Integration string `json:"integration"`
	Status      string `json:"status"`
}

type waitResult struct {
	// Cursor to pass as since next time: the newest change this answer read, from the store's
	// change log, never a clock. It advances even when nothing changed for this account, so a
	// quiet loop does not re-read the same tail forever.
	Cursor int64 `json:"cursor"`
	// CursorExpired says the cursor is not one this change log can answer from: older than its
	// oldest change (it keeps a week), or past its newest (one it never issued). What moved before
	// is not listed here. Re-read the inbox (get_inbox) once, and wait from the cursor answered.
	CursorExpired bool `json:"cursor_expired,omitempty"`
	// Threads that moved since the cursor.
	Threads []changed `json:"threads"`
	// Waiting is the count of contact requests awaiting the owner's approval,
	// and Pending the agent-answered calls waiting for an answer (§6.8). Both
	// are things only a person or their agent can clear, so a watcher that
	// only looked at messages would sit next to a blocked contact forever.
	Waiting int64 `json:"contact_requests"`
	Pending int64 `json:"pending_requests"`
	// Addresses is the count of contacts waiting at a new address for the owner's answer (HDTP
	// §5.3, list_pending_addresses): a third queue only the owner clears, and parking one wakes
	// this wait the way a contact request does.
	Addresses int64 `json:"pending_addresses"`
	// Calls: substantive tool calls contacts made since the cursor (bookings,
	// media, availability), so an agent learns a peer ACTED, not only that a
	// message arrived.
	Calls []callEvent `json:"calls,omitempty"`
	// NeedsAttention: conditions only the owner can clear — today, an
	// integration whose token died (auth_error) and needs re-authorizing.
	NeedsAttention []attention `json:"needs_attention,omitempty"`
	// CallsTruncated says more changed since the cursor than one read returns: Threads and Calls
	// hold the oldest of it, and the cursor stops where the read did, so the next wait continues
	// from there. The full trail is audit_query's job.
	CallsTruncated bool `json:"calls_truncated,omitempty"`
	// TimedOut says the wait ended on the clock rather than on an event: the
	// difference between "nothing happened" and "here is what happened".
	TimedOut bool `json:"timed_out"`
}

// AddWatchTools registers the agent's change feed and its digest.
func AddWatchTools(s *mcp.Server, d Deps, allow func(ctx context.Context, accountID string) bool) {
	ot := ownerTools{d: d, allow: allow}
	mcp.AddTool(s, &mcp.Tool{
		Name: "wait_for_updates",
		Description: "Block until something changes for this account — a message arrives, a contact asks to connect, " +
			"a request needs answering — then return what moved since your cursor. Call it in a loop with the cursor " +
			"it returns as since. Omitting since starts from now with no backlog.",
	}, ot.waitForUpdatesTool)

	mcp.AddTool(s, &mcp.Tool{
		Name: "digest",
		Description: "What happened in a window and what is still open: messages in and out per contact, who is " +
			"waiting on a reply, contacts asking to connect, requests awaiting an answer. For an end-of-day summary.",
	}, ot.digestTool)
}

// waitForUpdatesTool is the `wait_for_updates` tool.
func (ot ownerTools) waitForUpdatesTool(ctx context.Context, req *mcp.CallToolRequest, a WaitArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	timeout := WaitMaxSec * time.Second
	if a.TimeoutSec != nil {
		if *a.TimeoutSec < 1 || *a.TimeoutSec > WaitMaxSec {
			b, err := json.Marshal(map[string]string{"code": "bad_request", "detail": fmt.Sprintf("timeout_sec is whole seconds from 1 to %d", WaitMaxSec)})
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
		}
		timeout = time.Duration(*a.TimeoutSec) * time.Second
	}
	// A first call has nothing to say: hand back a cursor and let the next
	// call do the waiting. Replaying every thread on connect would make the
	// agent's first act a re-read of its whole history.
	if a.Since == nil {
		_, newest, err := ot.d.Store.ChangeBounds(ctx)
		if err != nil {
			return nil, nil, err
		}
		r, err := jsonResult(waitResult{Cursor: newest})
		return r, nil, err
	}
	// Listening before the first read: a change written between the read and the wait still
	// wakes it. The event only says "look"; the store says what (§7.8).
	var evs <-chan messaging.Event
	if ot.d.Bus != nil {
		ch, stop := ot.d.Bus.Subscribe(a.AccountID)
		defer stop()
		evs = ch
	}
	res, err := ot.d.changesSince(ctx, a.AccountID, *a.Since)
	if err != nil {
		return nil, nil, err
	}
	if res.news() {
		r, err := jsonResult(res)
		return r, nil, err
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case <-evs:
		case <-wctx.Done():
			// The clock ran out. The cursor stays where the last read left it — the newest change
			// it saw — and never jumps to a clock, which would pass over a change whose wake was lost.
			res.TimedOut = true
			r, err := jsonResult(res)
			return r, nil, err
		}
		// Every event is a reason to look, and not every one is news for this wait (an answer
		// relayed, say): what the store holds decides whether to answer or wait on.
		if res, err = ot.d.changesSince(ctx, a.AccountID, *a.Since); err != nil {
			return nil, nil, err
		}
		if res.news() {
			r, err := jsonResult(res)
			return r, nil, err
		}
	}
}

// news is whether a wait has something to answer with rather than park on: a thread moved, a
// contact acted, or one of the queues only the owner clears holds something.
func (r waitResult) news() bool {
	return len(r.Threads) > 0 || len(r.Calls) > 0 || r.Waiting > 0 || r.Pending > 0 || r.CursorExpired
}

// digestTool is the `digest` tool.
func (ot ownerTools) digestTool(ctx context.Context, req *mcp.CallToolRequest, a DigestArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	since := a.SinceTS
	if since == 0 {
		since = time.Now().Add(-24 * time.Hour).Unix()
	}
	threads, err := ot.d.Store.ListThreadsByAccount(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	type perContact struct {
		ContactFpr    string `json:"contact_fpr"`
		Contact       string `json:"contact,omitempty"`
		In            int    `json:"in"`
		Out           int    `json:"out"`
		Unread        int64  `json:"unread"`
		LastAt        int64  `json:"last_at"`
		LastDirection string `json:"last_direction,omitempty"`
		// AwaitingReply: their last word came after ours. The agent decides
		// what that is worth; the digest only says it is true.
		AwaitingReply bool   `json:"awaiting_reply"`
		Trust         string `json:"trust,omitempty"`
	}
	by := map[string]*perContact{}
	for _, th := range threads {
		msgs, err := ot.d.Store.ListMessagesByThread(ctx, a.AccountID, th.ID)
		if err != nil {
			continue
		}
		p := by[th.ContactFpr]
		if p == nil {
			p = &perContact{ContactFpr: th.ContactFpr}
			if c, err := ot.d.Store.GetContact(ctx, a.AccountID, th.ContactFpr); err == nil {
				p.Contact = displayName(c)
				p.Trust = c.TrustFlag
			}
			by[th.ContactFpr] = p
		}
		if n, err := ot.d.Store.UnreadCount(ctx, a.AccountID, th.ID); err == nil {
			p.Unread += n
		}
		for _, m := range msgs {
			if m.CreatedAt < since {
				continue
			}
			if m.Direction == "in" {
				p.In++
			} else {
				p.Out++
			}
			if m.CreatedAt >= p.LastAt {
				p.LastAt, p.LastDirection = m.CreatedAt, m.Direction
			}
		}
	}
	out := make([]perContact, 0, len(by))
	for _, p := range by {
		p.AwaitingReply = p.LastDirection == "in"
		if p.In > 0 || p.Out > 0 || p.Unread > 0 {
			out = append(out, *p)
		}
	}
	waiting, addresses, pending := ot.d.openCounts(ctx, a.AccountID)
	r, err := jsonResult(map[string]any{
		"since": since, "until": time.Now().Unix(), "contacts": out,
		"contact_requests": waiting, "pending_addresses": addresses, "pending_requests": pending,
	})
	return r, nil, err
}

// waitPage is how many of one account's changes a wait reads at once.
const waitPage = 500

// changesSince is the shared read behind the wait: the account's changes after the cursor in the
// store's change log — the threads that moved, the calls contacts made — and the queues only a
// person can clear.
func (d Deps) changesSince(ctx context.Context, accountID string, since int64) (waitResult, error) {
	// The newest id first: every change at or below it is committed (ids commit in order), so a
	// cursor of it passes over nothing.
	oldest, newest, err := d.Store.ChangeBounds(ctx)
	if err != nil {
		return waitResult{}, err
	}
	// A cursor this log never issued — older than its oldest change, or past its newest (a store
	// restored into a fresh log, another engine's, a time where an id belongs) — is said to be, at
	// once, with the log's newest: waiting from past the newest would wait on nothing, forever.
	res := waitResult{Cursor: newest, CursorExpired: (oldest > 0 && since < oldest-1) || since > newest}
	rows, err := d.Store.AccountChangesAfter(ctx, accountID, since, waitPage)
	if err != nil {
		return waitResult{}, err
	}
	var kept []store.Change
	for _, c := range rows {
		if c.ID <= newest {
			kept = append(kept, c)
		}
	}
	if len(rows) == waitPage && len(kept) > 0 {
		// More than a page moved: answer with this much, and let the next wait read on from it.
		res.Cursor, res.CallsTruncated = kept[len(kept)-1].ID, true
	}
	seen := map[string]bool{}
	trustOf := map[string]string{}
	for _, c := range kept {
		switch messaging.EventKind(c.Kind) {
		case messaging.EventMessage:
			if c.ThreadID == "" || seen[c.ThreadID] {
				continue
			}
			seen[c.ThreadID] = true
			th, err := d.Store.GetThread(ctx, accountID, c.ThreadID)
			if err != nil {
				continue // gone since: nothing to read
			}
			ch := changed{ThreadID: th.ID, ContactFpr: th.ContactFpr, LastAt: th.LastAt}
			if n, err := d.Store.UnreadCount(ctx, accountID, th.ID); err == nil {
				ch.Unread = n
			}
			// Fail SAFE on the label: a thread whose contact row cannot be read
			// (removed since, store hiccup) is reported at the lowest grant, the
			// same default read_thread resolves to — never unlabeled, never up.
			ch.Trust = "messages_only"
			if ct, err := d.Store.GetContact(ctx, accountID, th.ContactFpr); err == nil {
				ch.Contact = displayName(ct)
				ch.Trust = ct.TrustFlag
			}
			res.Threads = append(res.Threads, ch)
		case messaging.EventCall:
			if !messaging.FeedCalls[c.Ref] || c.ContactFpr == "" {
				continue
			}
			trust, cached := trustOf[c.ContactFpr]
			if !cached {
				if ct, err := d.Store.GetContact(ctx, accountID, c.ContactFpr); err == nil {
					trust = ct.TrustFlag
				}
				trustOf[c.ContactFpr] = trust
			}
			if trust == "" {
				// Not a contact this account knows (removed since): there is no owner grant to
				// report under, so the call is not this feed's news. It stays in audit_query.
				continue
			}
			res.Calls = append(res.Calls, callEvent{ContactFpr: c.ContactFpr, Tool: c.Ref, Trust: trust, At: c.At})
		}
	}
	res.Waiting, res.Addresses, res.Pending = d.openCounts(ctx, accountID)
	res.NeedsAttention = d.needsAttention(ctx, accountID)
	return res, nil
}

func (d Deps) needsAttention(ctx context.Context, accountID string) []attention {
	ints, err := d.Store.ListIntegrations(ctx, accountID)
	if err != nil {
		return nil
	}
	var out []attention
	for _, in := range ints {
		if in.Status == "auth_error" {
			out = append(out, attention{Kind: "integration_auth", Integration: in.Slug, Status: in.Status})
		}
	}
	return out
}

func (d Deps) openCounts(ctx context.Context, accountID string) (waiting, addresses, pending int64) {
	// Counted in the store, reading the rows in that state alone: every wake asks, and reading
	// every contact to count them made each wake grow with the list.
	if n, err := d.Store.CountContactsByStatus(ctx, accountID, "pending_in"); err == nil {
		waiting = n
	}
	if ps, err := d.Store.ListPendingAddresses(ctx, accountID); err == nil {
		addresses = int64(len(ps))
	}
	if d.Pending != nil {
		if rows, err := d.Store.ListOpenPendingRequests(ctx, accountID, time.Now().Unix()); err == nil {
			pending = int64(len(rows))
		}
	}
	return waiting, addresses, pending
}

func displayName(c store.Contact) string {
	if c.Petname != "" {
		return c.Petname
	}
	return c.DisplayName
}
