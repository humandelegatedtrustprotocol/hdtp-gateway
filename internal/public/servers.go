package public

// Per-caller MCP servers (SPEC §2.4, §5.4): every tool lives in a registry as data;
// the node composes a dedicated server per (account, caller) containing exactly what
// policy.Allow grants — so tools/list is correct by construction — and re-checks
// Allow inside a uniform guard at call time, so revocation is instant.

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
)

// Entry is one registry row: the tool, its gating rule, and its handler.
type Entry struct {
	Tool    *mcp.Tool
	Rule    policy.Rule
	Handler mcp.ToolHandler
}

// Registry holds every tool an account can ever serve, as data (SPEC §2.4).
//
// Entries arrive in named GROUPS. The built-in HDTP tools are one group and
// never change; each integration is a group of its own, because an exposure set
// is versioned and republished (§6.5) and a withheld integration must stop being
// served (§6.10). With only Add(), an integration's tools could be put in and
// never taken out or revised — so an owner narrowing an exposure changed a row
// in the database and nothing else.
type Registry struct {
	mu     sync.RWMutex
	groups map[string][]Entry
	order  []string // stable iteration, so tools/list does not reshuffle
}

// builtinGroup is where entries added without a group name land.
const builtinGroup = ""

// Add appends to the built-in group — the HDTP tool set, which never changes.
func (r *Registry) Add(e ...Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups == nil {
		r.groups = map[string][]Entry{}
	}
	if _, seen := r.groups[builtinGroup]; !seen {
		r.order = append(r.order, builtinGroup)
	}
	r.groups[builtinGroup] = append(r.groups[builtinGroup], e...)
}

// Replace swaps a named group's entries wholesale, adding, revising or (with no
// entries) removing it. This is the operation an exposure set needs: republish
// and withhold are both "this integration now serves exactly these tools".
func (r *Registry) Replace(group string, entries []Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups == nil {
		r.groups = map[string][]Entry{}
	}
	if _, seen := r.groups[group]; !seen {
		r.order = append(r.order, group)
	}
	if len(entries) == 0 {
		delete(r.groups, group)
		kept := r.order[:0]
		for _, g := range r.order {
			if g != group {
				kept = append(kept, g)
			}
		}
		r.order = kept
		return
	}
	r.groups[group] = append([]Entry(nil), entries...)
}

// GatedPermissions is every contact-tier permission the registry currently
// gates a tool with. The switchboard is built from it, so a permission the node
// can actually serve — an integration's `integration.<slug>` (SPEC §6.4) —
// is offerable the moment its exposure goes live, and one it cannot serve is
// never offered. A hard-coded list could only ever name the core five, which
// left every exposed integration tool ungrantable and therefore invisible to
// the contact it was exposed for.
func (r *Registry) GatedPermissions() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, e := range r.snapshot() {
		if e.Rule.Tier != policy.TierContact || e.Rule.Permission == "" || seen[e.Rule.Permission] {
			continue
		}
		seen[e.Rule.Permission] = true
		out = append(out, e.Rule.Permission)
	}
	sort.Strings(out)
	return out
}

func (r *Registry) snapshot() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, 16)
	for _, g := range r.order {
		out = append(out, r.groups[g]...)
	}
	return out
}

// InvalidateOnChange is what tools call after they change a caller's tier or
// permissions (redemption, approval, switchboard edits): the cached per-caller
// server is dropped so the next request composes the caller's NEW surface
// (SPEC §2.4, §5.4).
type InvalidateOnChange func(ctx context.Context, accountID, fpr string) error

// CallerResolver returns the current caller context for a fingerprint — backed by
// the contact store; consulted at compose time AND at every call (SPEC §2.4).
type CallerResolver func(ctx context.Context, accountID, fingerprint string) (policy.Caller, error)

// Pool composes and caches per-caller servers. Cache key: account ‖ fingerprint;
// anonymous guests share one key per account. Bounded LRU — rebuilding is cheap,
// so eviction is harmless (SPEC §2.4).
type Pool struct {
	Registry *Registry
	Resolve  CallerResolver
	MaxSize  int
	// CallAudit records refusals, tagged with the tier the caller reached us at.
	// SPEC §5.8 is explicit that every deny on this surface produces an audit
	// event — a denial nobody can see afterwards is the one an operator most
	// needs after an incident.
	CallAudit func(actorKind, action, resource, outcome string)
	// AccountID names the identity this pool serves. It is prefixed onto every
	// audited resource so the row is attributed: the audit trail's account
	// column is what scopes a narrowed token's reads (SPEC §11.6) and the
	// portal's audit page, and a row with no account is readable by everyone.
	AccountID string
	// Limit, when set, charges one call to an HDTP §12 budget, which the limits sidecar decides
	// (internal/limits), and answers nil when the call may proceed. It runs per CALL, not per
	// request. `as` says which budget: the caller's own (ChargeCaller: a contact's, or a guest's),
	// a guest's whatever the caller is (ChargeGuest: a pinned root at an address not approved, the
	// pending tier), or the source address alone (ChargeSource: nothing proven).
	Limit func(ctx context.Context, as Charge) *Refusal
	// PreOpen, when set, is the check BEFORE a sealed call is opened (the owner's decision of
	// 2026-09-29 on the guest total): nil when it may go on to the open. It spends nothing, and it
	// runs before a key is read.
	PreOpen func(ctx context.Context) *Refusal
	// Gate, when set, is the per-call transport-policy check that runs before
	// authorization: the seal and client_cert knobs of SPEC §5.1. It sees the
	// call's context, so it can tell a sealed call (envelope facts present)
	// from a plaintext one and apply the plaintext rules only to the latter.
	// Every call — sealed or not — reaches it through guarded().
	Gate func(ctx context.Context, tool string) error

	mu    sync.Mutex
	cache map[string]*list.Element
	order *list.List // front = most recent; values are *poolEntry
}

// Charge is which budget a call spends (Pool.Limit).
type Charge int

const (
	ChargeCaller Charge = iota
	ChargeGuest
	ChargeSource
	// ChargeOpened is a call the open found and answered with a refusal that spends nothing else
	// (an envelope_invalid, a certificate_renewed, a client certificate that is not the envelope's
	// leaf): one call of the guest total, so a flood the open cannot place drains it.
	ChargeOpened
)

// Refusal is a budget's answer to a call that may not proceed: `rate_limited`, with the whole
// seconds until the budget holds a call again (HDTP §12), or `unavailable` when no budget could be
// asked — the limits sidecar is not answering, and the node refuses rather than guess (the owner's
// rule of 2026-09-29, docs/release/two-layer-limits-2026-09-28.md §6).
type Refusal struct {
	RetryAfter  time.Duration
	Unavailable bool
}

// Code is the refusal's HDTP §12 code.
func (r *Refusal) Code() string {
	if r.Unavailable {
		return "unavailable"
	}
	return "rate_limited"
}

// Result is the refusal as a tool error: `rate_limited` carries `retry_after`, whole seconds and
// at least one.
func (r *Refusal) Result() *mcp.CallToolResult {
	if r.Unavailable {
		return codeResult("unavailable")
	}
	secs := int(math.Ceil(r.RetryAfter.Seconds()))
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{
		&mcp.TextContent{Text: fmt.Sprintf(`{"code":"rate_limited","retry_after":%d}`, max(1, secs))},
	}}
}

// spend charges one call to the caller's budget; nil when the call may proceed.
// preOpen is Pool.PreOpen, or nil (the call may go on) when none is set.
func (p *Pool) preOpen(ctx context.Context) *Refusal {
	if p == nil || p.PreOpen == nil {
		return nil
	}
	return p.PreOpen(ctx)
}

func (p *Pool) spend(ctx context.Context) *Refusal {
	if p.Limit == nil {
		return nil
	}
	return p.Limit(ctx, ChargeCaller)
}

type poolEntry struct {
	key    string
	server *mcp.Server
}

func NewPool(reg *Registry, resolve CallerResolver, maxSize int) *Pool {
	if maxSize <= 0 {
		maxSize = 256
	}
	return &Pool{
		Registry: reg, Resolve: resolve, MaxSize: maxSize,
		cache: map[string]*list.Element{}, order: list.New(),
	}
}

func key(accountID, fpr string) string { return accountID + "\x00" + fpr }

// ServerFor returns the composed server for this caller, cached until invalidated.
func (p *Pool) ServerFor(ctx context.Context, accountID, fpr string) (*mcp.Server, error) {
	k := key(accountID, fpr)
	p.mu.Lock()
	if el, ok := p.cache[k]; ok {
		p.order.MoveToFront(el)
		s := el.Value.(*poolEntry).server
		p.mu.Unlock()
		return s, nil
	}
	p.mu.Unlock()

	s, err := p.compose(ctx, accountID, fpr)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if el, ok := p.cache[k]; ok { // raced: keep the existing one
		return el.Value.(*poolEntry).server, nil
	}
	el := p.order.PushFront(&poolEntry{key: k, server: s})
	p.cache[k] = el
	p.evict()
	return s, nil
}

// evict trims the cache to MaxSize, oldest first. Every request composes its own session over a
// cached server and closes it with the request (StatelessMCP), so no client holds a server past
// its request, and a dropped entry is only a server the next request composes again.
// Caller holds p.mu.
func (p *Pool) evict() {
	for p.order.Len() > p.MaxSize {
		el := p.order.Back()
		p.order.Remove(el)
		delete(p.cache, el.Value.(*poolEntry).key)
	}
}

// Invalidate drops a caller's composed server: the switchboard or the tier changed, so the next
// request composes the caller's new surface (SPEC §2.4). A request already being served finishes
// on the server it started with, and every tools/call on it re-checks policy.Allow (guarded), so
// a revoked tool is refused there too.
func (p *Pool) Invalidate(ctx context.Context, accountID, fpr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drop(key(accountID, fpr))
	return nil
}

// InvalidateAll drops EVERY cached caller on an account.
//
// Invalidate answers "this one caller's permissions changed". An exposure set
// being published, a stale guard narrowing, or an integration being withheld
// changes what is served to everybody at once (SPEC §6.5, §6.10).
func (p *Pool) InvalidateAll(ctx context.Context, accountID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix := accountID + "\x00"
	for k := range p.cache {
		if strings.HasPrefix(k, prefix) {
			p.drop(k)
		}
	}
}

// drop forgets one cached server. Caller holds p.mu.
func (p *Pool) drop(k string) {
	if el, ok := p.cache[k]; ok {
		p.order.Remove(el)
		delete(p.cache, k)
	}
}

func (p *Pool) compose(ctx context.Context, accountID, fpr string) (*mcp.Server, error) {
	caller, err := p.Resolve(ctx, accountID, fpr)
	if err != nil {
		return nil, err
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "hdtp-gateway", Version: "1"}, &mcp.ServerOptions{Capabilities: ToolsOnly()})
	// SPEC §5.8: every deny is audited, "at every stage of the pipeline". A call
	// for a tool this caller cannot see never reaches a handler — the SDK
	// refuses it as unknown — so without this the most interesting denials, the
	// ones probing for tools they were not granted, would leave no trace.
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil && method == "tools/call" {
				// An availability failure is NOT a denial — logging it as one
				// would send an operator hunting a permission problem that is
				// really a broken dependency.
				if errors.Is(err, ErrUnavailable) {
					p.audit(caller.Tier, "tools_call",
						"caller:"+fprOrAnonymous(fpr)+" tool:"+calledTool(req), "unavailable")
					return res, err
				}
				// A pinned root calling from an address the owner has not yet
				// approved (HDTP §5.3) is composed as a guest, so its contact
				// tools are not here — but the answer is the one the sealed
				// path gives: pending_approval, and pending for the
				// update_contact that brought the address.
				if tc, ok := TransportCallerFrom(ctx); ok && tc.Refusal != "" {
					tool := calledTool(req)
					p.audit(caller.Tier, "tools_call", "caller:"+fprOrAnonymous(fpr)+" tool:"+tool, tc.Refusal)
					if tool == "update_contact" {
						return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"status":"pending"}`}}}, nil
					}
					return codeResult(tc.Refusal), nil
				}
				// Otherwise the tool is not on this caller's surface, and the
				// SDK's own "unknown tool" error would both leak that the tool
				// exists elsewhere and differ from what the sealed path returns.
				// Answer with the protocol's code instead (HDTP §12, §5.4).
				code := refusalCode(caller.Tier)
				p.audit(caller.Tier, "tools_call",
					"caller:"+fprOrAnonymous(fpr)+" tool:"+calledTool(req), code)
				return codeResult(code), nil
			}
			return res, err
		}
	})
	for _, e := range p.Registry.snapshot() {
		if policy.Allow(caller, e.Rule) {
			s.AddTool(e.Tool, p.guarded(accountID, fpr, e))
		}
	}
	return s, nil
}

// ErrUnavailable marks a call that failed because something the node depends on
// is unreachable — not because the caller was refused. The two look similar at
// the transport and are deliberately distinguished in the audit trail (§5.8).
var ErrUnavailable = errors.New("unavailable")

// calledTool names the tool a request asked for, without trusting it further
// than a log line.
func calledTool(req mcp.Request) string {
	r, ok := req.(*mcp.CallToolRequest)
	if !ok || r.Params == nil || r.Params.Name == "" {
		return "unknown"
	}
	name := r.Params.Name
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// refusalCode is the code a caller sees when a tool is out of reach. The
// distinction is required by HDTP §12 and is a privacy rule, not cosmetics: at
// guest tier "you may not" and "there is no such tool" must be the SAME answer,
// because a blocked caller resolves to guest and must be indistinguishable from
// somebody this node has never met (§5.4). A contact, by contrast, is known — so
// a tool their switchboard does not grant is an honest `permission_denied`.
// resolveCaller is Resolve with one override: a `v: 1` envelope whose chain
// proved nothing for the pinned root — a blocked contact, or a leaf older than
// the pinned one (HDTP §14.3) — is a guest whatever row the root has. The
// envelope decided that before dispatch, and the store must not undo it.
func (p *Pool) resolveCaller(ctx context.Context, accountID, fpr string) (policy.Caller, error) {
	if f := EnvelopeFactsFrom(ctx); f != nil && f.Demote {
		return policy.Caller{AccountID: accountID, Fingerprint: fpr, Tier: policy.TierGuest}, nil
	}
	return p.Resolve(ctx, accountID, fpr)
}

func refusalCode(tier policy.Tier) string {
	if tier == policy.TierContact || tier == policy.TierPending {
		return "permission_denied"
	}
	return "blocked_or_unknown"
}

func codeResult(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"` + code + `"}`}}}
}

// audit maps the caller's tier onto the store's actor vocabulary
// (owner|token|contact|guest|cli|system) — a value outside it is refused by the
// schema, which is how this went unnoticed once already.
func (p *Pool) audit(tier policy.Tier, action, resource, outcome string) {
	if p.CallAudit == nil {
		return
	}
	kind := "guest"
	if tier == policy.TierContact || tier == policy.TierPending {
		kind = "contact"
	}
	if p.AccountID != "" {
		resource = "account:" + p.AccountID + " " + resource
	}
	p.CallAudit(kind, action, resource, outcome)
}

// fprOrAnonymous names an unidentified caller without pretending it had one.
func fprOrAnonymous(fpr string) string {
	if fpr == "" {
		return "anonymous"
	}
	return fpr
}

// guarded is the ONE wrapper every handler passes through: policy.Allow re-checked
// at call time so a permission flip denies instantly, even on a server composed before it (SPEC §2.4).
func (p *Pool) guarded(accountID, fpr string, e Entry) mcp.ToolHandler {
	run := p.checked(accountID, fpr, e)
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Transport policy precedes authorization (§4.11, §5.3): a call that
		// must be sealed is refused as `seal_required` before anything looks at
		// who the caller is.
		// Budget first: a refusal here must not cost the node any of the work a
		// permitted call would (HDTP §12, SPEC §5.7). The sealed_call wrapper is
		// exempt HERE and only here: at this point the envelope is unopened, so
		// the caller classifies by transport — behind a terminating edge that is
		// an anonymous guest, and every sealed contact was burning the shared
		// per-IP guest budget on the wrapper before spending their own contact
		// unit on the inner call. One call, one unit, correctly classified — the
		// inner call is where that happens: the sealed handler spends once, after
		// the replay and before Dispatch looks for the tool (so tools/list and a
		// tool that is not there spend as well), and Dispatch runs `checked`.
		if e.Tool.Name != SealedToolName {
			if r := p.spend(ctx); r != nil {
				return r.Result(), nil
			}
		}
		return run(ctx, req)
	}
}

// checked is guarded without the budget: the transport gate, the call-time policy check, and
// the handler. Dispatch runs it after spending for the inner call itself.
func (p *Pool) checked(accountID, fpr string, e Entry) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if p.Gate != nil {
			if err := p.Gate(ctx, e.Tool.Name); err != nil {
				if errors.Is(err, ErrPendingStatus) {
					// HDTP §5.3: the update_contact from a new address the owner
					// has not approved answers pending, and nothing runs.
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"status":"pending"}`}}}, nil
				}
				return &mcp.CallToolResult{IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"` + Code(err) + `"}`}}}, nil
			}
		}
		caller, err := p.resolveCaller(ctx, accountID, fpr)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		if !policy.Allow(caller, e.Rule) {
			code := refusalCode(caller.Tier)
			p.audit(caller.Tier, "tools_call", "caller:"+fprOrAnonymous(fpr)+" tool:"+e.Tool.Name, code)
			return codeResult(code), nil
		}
		// handlers that need the caller (idempotency keys, trust labeling)
		// read the RESOLVED identity — never a caller-supplied field
		return e.Handler(WithCaller(ctx, caller), req)
	}
}

type callerKey struct{}

// CallerFromContext returns the policy-resolved caller inside a guarded handler.
// WithCaller attaches a resolved caller: the pool's guard calls it per call, and
// a test exercising a handler built outside this package calls the same function.
func WithCaller(ctx context.Context, c policy.Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

func CallerFromContext(ctx context.Context) (policy.Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(policy.Caller)
	return c, ok
}
