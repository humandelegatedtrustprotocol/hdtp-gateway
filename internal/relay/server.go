// Package relay implements relay mode in both directions (SPEC §10.5, PACT §9):
// this file is the SERVER side — the store-and-forward surface a node offers to
// other people's contacts.
//
// The defining property is what the relay CANNOT do: it never holds a key that
// opens a relayed envelope, and this package never imports the opening path.
// It verifies a sender's detached signature with the key from that sender's
// mTLS client certificate (§4.8) and enforces the recipient's synced allow-list
// on `from` — allow-list enforcement without plaintext. It sees metadata:
// sender, recipient, msg_id, timestamps, sizes. That trade-off is stated, not
// hidden (§13).
package relay

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
)

// Retention caps how long a queued item lives: min(envelope exp, 30 days).
const Retention = 30 * 24 * time.Hour

// MaxFetch bounds one fetch_queued response.
const MaxFetch = 32

// CallerKey is how the surface learns the calling node's certificate key. The
// relay REQUIRES it: without a client certificate there is no key to verify a
// signature with, which is why a relay must not run on an edge-mode listener
// (§10.5).
type CallerKey func(ctx context.Context) (spki []byte, fingerprint string, ok bool)

// Server is the relay surface for one node.
type Server struct {
	Store  store.Store
	Caller CallerKey
	Now    func() time.Time
	Audit  func(action, resource, outcome string)
	// Notify, when set, is the content-free "you have mail" ping to a recipient
	// that is currently connected (PACT §9); it never carries the envelope.
	Notify func(recipientFpr string)
	// Serves reports whether this relay serves a given recipient — the
	// registration gate on the allow-list endpoint. nil means an OPEN relay,
	// which is the documented default so that turning the knob on is what
	// changes behaviour.
	//
	// relay_call already refuses a sender absent from the recipient's
	// allow-list, so mail could never be queued for a stranger. Nothing gated
	// BECOMING a recipient, though: any caller with any client certificate
	// could POST a list and be stored as one, and certificates are free to
	// mint. An operator who set `relay: true` for their own household was
	// running a public store-and-forward service.
	Serves func(recipientFpr string) bool
	// MaxQueue and MaxQueueBytes bound one recipient's queue (PACT §9: a relay
	// SHOULD bound per-recipient depth). Zero means the documented defaults.
	MaxQueue      int
	MaxQueueBytes int64

	// waiters holds the recipients currently long-polling fetch_queued; a
	// relay_call for one of them releases the hold — the §9 content-free
	// "you have mail", carried on the connection the recipient already has
	// open, because a relay-assisted recipient has no inbound path a real
	// push could use.
	waitMu  sync.Mutex
	waiters map[string]map[chan struct{}]struct{}
}

// MaxWait caps fetch_queued's wait_seconds. The outbound client gives one call
// 30 seconds; the hold must end comfortably inside it.
const MaxWait = 20 * time.Second

// subscribe registers a hold for a recipient; cancel is idempotent and MUST be
// called, or the registry grows with abandoned channels.
func (s *Server) subscribe(recipientFpr string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.waitMu.Lock()
	if s.waiters == nil {
		s.waiters = map[string]map[chan struct{}]struct{}{}
	}
	if s.waiters[recipientFpr] == nil {
		s.waiters[recipientFpr] = map[chan struct{}]struct{}{}
	}
	s.waiters[recipientFpr][ch] = struct{}{}
	s.waitMu.Unlock()
	return ch, func() {
		s.waitMu.Lock()
		if set := s.waiters[recipientFpr]; set != nil {
			delete(set, ch)
			if len(set) == 0 {
				delete(s.waiters, recipientFpr)
			}
		}
		s.waitMu.Unlock()
	}
}

// wakeWaiters releases every hold for a recipient. Non-blocking: a waiter that
// already has a pending signal needs no second one.
func (s *Server) wakeWaiters(recipientFpr string) {
	s.waitMu.Lock()
	for ch := range s.waiters[recipientFpr] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	s.waitMu.Unlock()
}

// Queue quotas (PACT §9, §12). Envelopes can be large (the node-wide body cap
// is what bounds one), so a count alone would still let one recipient's queue
// hold hundreds of megabytes; both dimensions are checked.
const (
	MaxQueuePerRecipient      = 100
	MaxQueueBytesPerRecipient = 64 << 20
)

func (s *Server) maxQueue() int {
	if s.MaxQueue > 0 {
		return s.MaxQueue
	}
	return MaxQueuePerRecipient
}

func (s *Server) maxQueueBytes() int64 {
	if s.MaxQueueBytes > 0 {
		return s.MaxQueueBytes
	}
	return MaxQueueBytesPerRecipient
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) audit(action, resource, outcome string) {
	if s.Audit != nil {
		s.Audit(action, resource, outcome)
	}
}

func errResult(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"` + code + `"}`}}}
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
}

func fingerprintOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// MCPServer builds the relay's MCP server. It is EXACTLY PACT §9's three verbs
// and nothing else — see AllowlistHandler for why the allow-list is not here.
func (s *Server) MCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "pact-relay", Version: "1"}, nil)
	obj := json.RawMessage(`{"type":"object"}`)
	srv.AddTool(&mcp.Tool{Name: "relay_call", Description: "Queue a sealed envelope for an allow-listed recipient", InputSchema: obj}, s.relayCall)
	srv.AddTool(&mcp.Tool{Name: "fetch_queued", Description: "Fetch envelopes queued for the calling node", InputSchema: obj}, s.fetchQueued)
	srv.AddTool(&mcp.Tool{Name: "ack", Description: "Delete a fetched envelope", InputSchema: obj}, s.ack)
	return srv
}

// relayCall queues one sealed envelope. Verification here is deliberately
// shallow-but-sufficient: the signature must verify under the CALLER'S OWN
// certificate key, `from` must equal that caller, and `from` must be on the
// recipient's allow-list. No decryption, ever.
func (s *Server) relayCall(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	spki, callerFpr, ok := s.Caller(ctx)
	if !ok || len(spki) == 0 {
		s.audit("relay_call", "relay", "identity_required")
		return errResult("identity_required"), nil
	}
	var args struct {
		To       string             `json:"to"`
		Envelope *envelope.Envelope `json:"envelope"`
	}
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil || args.Envelope == nil {
		return errResult("bad_request"), nil
	}
	h, err := envelope.ParseHeader(args.Envelope)
	if err != nil {
		s.audit("relay_call", "sender:"+callerFpr, "envelope_invalid")
		return errResult("envelope_invalid"), nil
	}
	// the envelope's own routing wins over any argument
	recipient := h.To
	if args.To != "" && args.To != recipient {
		return errResult("envelope_invalid"), nil
	}
	if h.From != callerFpr || fingerprintOf(spki) != callerFpr {
		s.audit("relay_call", "sender:"+callerFpr, "envelope_invalid")
		return errResult("envelope_invalid"), nil
	}
	// signature verified with the presented certificate key (§4.8) — no opening
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return errResult("envelope_invalid"), nil
	}
	if err := envelope.VerifySig(args.Envelope, pub); err != nil {
		s.audit("relay_call", "sender:"+callerFpr, "envelope_invalid")
		return errResult("envelope_invalid"), nil
	}
	// Enforce the operator's recipient list HERE too, not only at registration.
	// Gating registration alone left every allow-list row created while the
	// relay was open still being served: an operator who narrowed the list saw
	// new registrations refused and kept carrying mail for whoever got in
	// first. Checking at use is also what makes the knob safe to narrow later,
	// without a purge that could not be undone.
	//
	// The refusal is deliberately the same permission_denied an unlisted sender
	// gets, for the reason given below: an unknown recipient must look the same.
	if s.Serves != nil && !s.Serves(recipient) {
		s.audit("relay_call", "sender:"+callerFpr+"->"+recipient, "permission_denied")
		return errResult("permission_denied"), nil
	}
	allowed, err := s.Store.RelayAllowed(ctx, recipient, callerFpr)
	if err != nil {
		return errResult("unavailable"), nil
	}
	if !allowed {
		// Refusal is audited (§10.5) and says nothing about whether the
		// recipient exists here: an unknown recipient looks the same.
		s.audit("relay_call", "sender:"+callerFpr+"->"+recipient, "permission_denied")
		return errResult("permission_denied"), nil
	}
	now := s.now()
	exp := h.Exp
	if cap := now.Add(Retention).Unix(); exp > cap {
		exp = cap
	}
	if exp <= now.Unix() {
		return errResult("envelope_invalid"), nil
	}
	body, err := json.Marshal(args.Envelope)
	if err != nil {
		return errResult("unavailable"), nil
	}
	// The quota is a soft cap: two concurrent relay_calls can each pass the
	// read and overshoot by one item, which is fine — the bound this enforces
	// is "roughly this much", not an invariant anything downstream relies on.
	items, bytes, err := s.Store.RelayQueueUsage(ctx, recipient, now.Unix())
	if err != nil {
		return errResult("unavailable"), nil
	}
	if items >= int64(s.maxQueue()) || bytes+int64(len(body)) > s.maxQueueBytes() {
		s.audit("relay_call", "sender:"+callerFpr+"->"+recipient, "rate_limited")
		return errResult("rate_limited"), nil
	}
	item, err := s.Store.EnqueueRelay(ctx, store.RelayItem{
		RecipientFpr: recipient, SenderFpr: callerFpr, MsgID: h.MsgID,
		Envelope: string(body), SizeBytes: int64(len(body)),
		QueuedAt: now.Unix(), ExpiresAt: exp,
	})
	if err != nil {
		return errResult("unavailable"), nil
	}
	s.audit("relay_call", "sender:"+callerFpr+"->"+recipient, "queued")
	s.wakeWaiters(recipient) // release any long-polling fetch (content-free)
	if s.Notify != nil {
		s.Notify(recipient) // content-free: "you have mail"
	}
	return jsonResult(map[string]any{"status": "queued", "id": item.ID, "expires_at": exp})
}

// fetchQueued returns the calling node's own queue — identity is the client
// certificate, so a node can only ever fetch its own mail.
func (s *Server) fetchQueued(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, callerFpr, ok := s.Caller(ctx)
	if !ok {
		return errResult("identity_required"), nil
	}
	// wait_seconds turns an empty fetch into a bounded hold: the §9 push,
	// without inventing a channel — a relay-assisted recipient has no inbound
	// path, so the connection it already opened is the only wire a wake can
	// ride. Old relays ignore the argument and answer immediately; old
	// clients send none and get today's behaviour. Backward compatible both
	// ways by construction.
	var args struct {
		WaitSeconds int `json:"wait_seconds"`
	}
	if len(req.Params.Arguments) > 0 {
		_ = json.Unmarshal(req.Params.Arguments, &args)
	}
	now := s.now().Unix()
	if _, err := s.Store.PurgeExpiredRelay(ctx, now); err != nil {
		return errResult("unavailable"), nil
	}
	items, err := s.Store.FetchRelayQueue(ctx, callerFpr, now, MaxFetch)
	if err != nil {
		return errResult("unavailable"), nil
	}
	if len(items) == 0 && args.WaitSeconds > 0 {
		wait := time.Duration(args.WaitSeconds) * time.Second
		if wait > MaxWait {
			wait = MaxWait
		}
		ch, cancel := s.subscribe(callerFpr)
		defer cancel()
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
		case <-ch:
		}
		now = s.now().Unix()
		items, err = s.Store.FetchRelayQueue(ctx, callerFpr, now, MaxFetch)
		if err != nil {
			return errResult("unavailable"), nil
		}
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		var env envelope.Envelope
		if err := json.Unmarshal([]byte(it.Envelope), &env); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": it.ID, "envelope": env, "queued_at": it.QueuedAt})
	}
	s.audit("fetch_queued", "recipient:"+callerFpr, fmt.Sprintf("%d", len(out)))
	return jsonResult(map[string]any{"items": out})
}

// ack deletes one fetched item; a node may only ack its own.
func (s *Server) ack(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, callerFpr, ok := s.Caller(ctx)
	if !ok {
		return errResult("identity_required"), nil
	}
	var args struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil || args.ID == "" {
		return errResult("bad_request"), nil
	}
	deleted, err := s.Store.AckRelay(ctx, args.ID, callerFpr)
	if err != nil {
		return errResult("unavailable"), nil
	}
	s.audit("relay_ack", "recipient:"+callerFpr, fmt.Sprintf("%v", deleted))
	return jsonResult(map[string]any{"deleted": deleted})
}

// syncAllowlist replaces the calling node's allow-list: the recipient decides
// who may queue for it, and only for itself.
/* ------------------------ the allow-list control ------------------------ */

// MaxAllowlist bounds one submission. The list is a node's active contacts, and
// a cap keeps a broken or hostile client from writing an unbounded table through
// a surface whose only ticket is a client certificate.
const MaxAllowlist = 4096

// maxAllowlistBody caps the request body ahead of any parsing.
const maxAllowlistBody = 1 << 20

// AllowlistHandler is the relay's OWN control endpoint, and deliberately NOT an
// MCP tool. PACT §9 defines exactly three relay verbs — `relay_call`,
// `fetch_queued`, `ack` — so registering a fourth would make every peer's
// `tools/list` advertise something the protocol does not define, and a peer
// cannot tell a local extension from a verb it should have implemented. The
// mechanism is still needed: a recipient has no other way to tell its relay who
// may queue for it. So it moves rather than disappears, onto the same mTLS
// connection with the same certificate deciding who is calling (SPEC §10.5).
//
// A caller can only ever set its OWN list. The recipient is the fingerprint of
// the presented certificate; nothing in the body names a recipient, so there is
// no field to forge.
func (s *Server) AllowlistHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeCode(w, http.StatusMethodNotAllowed, "bad_request")
			return
		}
		_, callerFpr, ok := s.Caller(r.Context())
		if !ok {
			// No client certificate, no identity to attribute a list to. This is
			// the same reason a relay must not run behind a terminating edge.
			s.audit("relay_allowlist", "recipient:unknown", "identity_required")
			writeCode(w, http.StatusUnauthorized, "identity_required")
			return
		}
		if s.Serves != nil && !s.Serves(callerFpr) {
			// Not a recipient this relay was configured to serve. Refuse before
			// reading the body, so an unserved caller cannot spend our memory.
			s.audit("relay_allowlist", "recipient:"+callerFpr, "permission_denied")
			writeCode(w, http.StatusForbidden, "permission_denied")
			return
		}
		var args struct {
			Senders []string `json:"senders"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAllowlistBody)).Decode(&args); err != nil {
			writeCode(w, http.StatusBadRequest, "bad_request")
			return
		}
		if len(args.Senders) > MaxAllowlist {
			writeCode(w, http.StatusBadRequest, "bad_request")
			return
		}
		// Every entry must look like PACT §2's identity. These strings are
		// stored and later compared against a sender's certificate; anything
		// that is not a fingerprint could never match one anyway.
		for _, f := range args.Senders {
			if !looksLikeFingerprint(f) {
				writeCode(w, http.StatusBadRequest, "bad_request")
				return
			}
		}
		if err := s.Store.SyncRelayAllowlist(r.Context(), callerFpr, args.Senders); err != nil {
			writeCode(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		s.audit("relay_allowlist", "recipient:"+callerFpr, fmt.Sprintf("%d", len(args.Senders)))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"synced":%d}`, len(args.Senders))
	})
}

// looksLikeFingerprint checks PACT §2's shape: "sha256:" + base64url of a
// 32-byte digest. It is a shape check, not a claim that the key exists.
func looksLikeFingerprint(f string) bool {
	rest, ok := strings.CutPrefix(f, "sha256:")
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil && len(raw) == sha256.Size
}

func writeCode(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q}`, code)
}

// Handler exposes one tool's handler by name — the seam a node uses to mount
// the relay surface on its own listener (and what in-process callers drive).
func (s *Server) Handler(tool string) mcp.ToolHandler {
	switch tool {
	case "relay_call":
		return s.relayCall
	case "fetch_queued":
		return s.fetchQueued
	case "ack":
		return s.ack
	default:
		return func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return errResult("unavailable"), nil
		}
	}
}
