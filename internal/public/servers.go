package public

// Per-caller MCP servers (SPEC §2.4, §5.4): every tool lives in a registry as data;
// the node composes a dedicated server per (account, caller) containing exactly what
// policy.Allow grants — so tools/list is correct by construction — and re-checks
// Allow inside a uniform guard at call time, so revocation is instant mid-session.

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/policy"
)

// Entry is one registry row: the tool, its gating rule, and its handler.
type Entry struct {
	Tool    *mcp.Tool
	Rule    policy.Rule
	Handler mcp.ToolHandler
}

// Registry holds every tool an account can ever serve, as data (SPEC §2.4).
//
// Entries arrive in named GROUPS. The built-in PACT tools are one group and
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

// Add appends to the built-in group — the PACT tool set, which never changes.
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
// server is dropped so the next call composes the caller's NEW surface, and
// connected sessions are told to re-list (SPEC §2.4, §5.4).
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
	// Limit, when set, consumes one unit of the caller's PACT §12 budget and
	// reports how long until it refills. It runs per CALL, not per request.
	Limit func(ctx context.Context) (ok bool, retryAfter time.Duration)
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

type poolEntry struct {
	key    string
	server *mcp.Server
	// recon serializes reconciliation of THIS entry. The tool mutations cannot
	// run under Pool.mu — RemoveTools/AddTool notify connected sessions, and a
	// session handler can re-enter the pool — so two invalidations racing on one
	// caller (a permission edit against an exposure republish) would otherwise
	// interleave their compute-then-mutate and leave a withdrawn tool installed.
	recon sync.Mutex
	// installed is what this server was last given. Reconciling has to remove
	// tools that are GONE from the registry, and a post-change snapshot cannot
	// name them — so the only honest source for "what is on this server now" is
	// what we put there. Guarded by Pool.mu.
	installed []string
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

	s, installed, err := p.compose(ctx, accountID, fpr)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if el, ok := p.cache[k]; ok { // raced: keep the existing one
		return el.Value.(*poolEntry).server, nil
	}
	el := p.order.PushFront(&poolEntry{key: k, server: s, installed: installed})
	p.cache[k] = el
	p.evict()
	return s, nil
}

// evict trims the cache to MaxSize, oldest first, but never drops an entry whose
// server still has a connected session.
//
// Eviction is how a live server used to become orphaned a second way: the pool
// forgot a server a client still held, so the next InvalidateAll found nothing
// to reconcile and a withdrawn tool stayed callable for the life of that
// session. A caller who can open MaxSize+1 sessions could arrange it. Keeping
// live entries means the cache can exceed MaxSize, bounded by the number of
// concurrent sessions rather than by nothing — which is the bound that matters,
// since those servers are referenced whether the pool tracks them or not.
// Caller holds p.mu.
func (p *Pool) evict() {
	for el := p.order.Back(); el != nil && p.order.Len() > p.MaxSize; {
		prev := el.Prev()
		if !hasLiveSession(el.Value.(*poolEntry).server) {
			p.order.Remove(el)
			delete(p.cache, el.Value.(*poolEntry).key)
		}
		el = prev
	}
}

func hasLiveSession(s *mcp.Server) bool {
	for range s.Sessions() {
		return true
	}
	return false
}

// Invalidate drops a caller's composed server AND live-updates it: the switchboard
// changed, so the cached server's tools are reconciled to the new grant set — a
// connected session receives tools/list_changed from the SDK (SPEC §2.4).
func (p *Pool) Invalidate(ctx context.Context, accountID, fpr string) error {
	k := key(accountID, fpr)
	p.mu.Lock()
	el, ok := p.cache[k]
	p.mu.Unlock()
	if !ok {
		return nil
	}
	entry := el.Value.(*poolEntry)
	entry.recon.Lock()
	defer entry.recon.Unlock()

	caller, err := p.Resolve(ctx, accountID, fpr)
	if err != nil {
		// This caller cannot be resolved any more — the contact was removed.
		// Drop the entry so nothing composes from it again; a call arriving on
		// a session that still holds the server is refused by guarded().
		p.mu.Lock()
		if cur, ok := p.cache[k]; ok && cur == el {
			p.order.Remove(el)
			delete(p.cache, k)
		}
		p.mu.Unlock()
		return err
	}

	allowed := map[string]Entry{}
	for _, e := range p.Registry.snapshot() {
		if policy.Allow(caller, e.Rule) {
			allowed[e.Tool.Name] = e
		}
	}

	// Reconcile the still-referenced (possibly connected) server IN PLACE, and
	// keep it cached. Dropping it here is what used to orphan a live session:
	// the pool forgot a server a client still held, so the NEXT change found
	// nothing to reconcile and silently did nothing.
	p.mu.Lock()
	var remove []string
	for _, n := range entry.installed {
		if _, ok := allowed[n]; !ok {
			remove = append(remove, n)
		}
	}
	names := make([]string, 0, len(allowed))
	for n := range allowed {
		names = append(names, n)
	}
	sort.Strings(names)
	entry.installed = names
	p.order.MoveToFront(el)
	p.mu.Unlock()

	srv := entry.server
	srv.RemoveTools(remove...)
	for _, n := range names {
		e := allowed[n]
		srv.AddTool(e.Tool, p.guarded(accountID, fpr, e))
	}
	return nil
}

// InvalidateAll reconciles EVERY cached caller on an account.
//
// Invalidate answers "this one caller's permissions changed". An exposure set
// being published, a stale guard narrowing, or an integration being withheld
// changes what is served to everybody at once (SPEC §6.5, §6.10), and there was
// no way to say that — so a withheld integration kept its tools listed for every
// session already open.
func (p *Pool) InvalidateAll(ctx context.Context, accountID string) {
	p.mu.Lock()
	fprs := make([]string, 0, len(p.cache))
	prefix := accountID + "\x00"
	for k := range p.cache {
		if strings.HasPrefix(k, prefix) {
			fprs = append(fprs, strings.TrimPrefix(k, prefix))
		}
	}
	p.mu.Unlock()
	for _, fpr := range fprs {
		// Best effort per caller: one unresolvable identity must not stop the
		// rest of the account from being brought up to date.
		_ = p.Invalidate(ctx, accountID, fpr)
	}
}

func (p *Pool) compose(ctx context.Context, accountID, fpr string) (*mcp.Server, []string, error) {
	caller, err := p.Resolve(ctx, accountID, fpr)
	if err != nil {
		return nil, nil, err
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "pact-gateway", Version: "1"}, nil)
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
				// approved (PACT §5.3) is composed as a guest, so its contact
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
				// Answer with the protocol's code instead (PACT §12, §5.4).
				code := refusalCode(caller.Tier)
				p.audit(caller.Tier, "tools_call",
					"caller:"+fprOrAnonymous(fpr)+" tool:"+calledTool(req), code)
				return codeResult(code), nil
			}
			return res, err
		}
	})
	var installed []string
	for _, e := range p.Registry.snapshot() {
		if policy.Allow(caller, e.Rule) {
			s.AddTool(e.Tool, p.guarded(accountID, fpr, e))
			installed = append(installed, e.Tool.Name)
		}
	}
	sort.Strings(installed)
	return s, installed, nil
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
// distinction is required by PACT §12 and is a privacy rule, not cosmetics: at
// guest tier "you may not" and "there is no such tool" must be the SAME answer,
// because a blocked caller resolves to guest and must be indistinguishable from
// somebody this node has never met (§5.4). A contact, by contrast, is known — so
// a tool their switchboard does not grant is an honest `permission_denied`.
// resolveCaller is Resolve with one override: a `v: 2` envelope whose chain
// proved nothing for the pinned root — a blocked contact, or a leaf older than
// the pinned one (PACT §14.3) — is a guest whatever row the root has. The
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
// at call time so a permission flip denies instantly, even mid-session (SPEC §2.4).
func (p *Pool) guarded(accountID, fpr string, e Entry) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Transport policy precedes authorization (§4.11, §5.3): a call that
		// must be sealed is refused as `seal_required` before anything looks at
		// who the caller is.
		// Budget first: a refusal here must not cost the node any of the work a
		// permitted call would (PACT §12, SPEC §5.7). The sealed_call wrapper is
		// exempt HERE and only here: at this point the envelope is unopened, so
		// the caller classifies by transport — behind a terminating edge that is
		// an anonymous guest, and every sealed contact was burning the shared
		// per-IP guest budget (10/hour) on the wrapper before spending their own
		// contact unit on the inner dispatch, which consumes through this same
		// path with the envelope facts attached. One call, one unit, correctly
		// classified — the inner dispatch is where that happens.
		if p.Limit != nil && e.Tool.Name != SealedToolName {
			if ok, retry := p.Limit(ctx); !ok {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf(`{"code":"rate_limited","retry_after":%d}`,
						int(retry.Seconds())+1)},
				}}, nil
			}
		}
		if p.Gate != nil {
			if err := p.Gate(ctx, e.Tool.Name); err != nil {
				if errors.Is(err, ErrPendingStatus) {
					// PACT §5.3: the update_contact from a new address the owner
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

// SessionBinder pins MCP session ids to the identity that created them (SPEC §5.6,
// §13.1): a session presented under any other fingerprint is refused.
// SessionTTL is how long a session binding survives with no traffic. A session
// that ends without a DELETE — a crash, a dropped connection, or a caller who
// simply never sends one — would otherwise hold its entry for the life of the
// process, and sessions are created by anyone who can reach the MCP endpoint.
const SessionTTL = time.Hour

// MaxSessionBindings is the hard ceiling. TTL alone bounds the map at "sessions
// created per hour", which a determined caller can still make large; past this
// the least recently seen bindings go early.
const MaxSessionBindings = 50_000

type binding struct {
	fpr  string
	seen time.Time
}

type SessionBinder struct {
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time

	mu        sync.Mutex
	sessions  map[string]binding
	lastSweep time.Time
}

func NewSessionBinder() *SessionBinder {
	return &SessionBinder{sessions: map[string]binding{}}
}

func (b *SessionBinder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Bind records or checks the session's identity. It returns false when the session
// is already bound to a DIFFERENT fingerprint.
func (b *SessionBinder) Bind(sessionID, fpr string) bool {
	if sessionID == "" {
		return true // no session layer (e.g. stateless call) — nothing to bind
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.sweepLocked(now)
	bound, ok := b.sessions[sessionID]
	if !ok {
		b.sessions[sessionID] = binding{fpr: fpr, seen: now}
		return true
	}
	if bound.fpr != fpr {
		return false
	}
	// Live traffic keeps the binding alive, so an active session is never
	// reclaimed out from under its caller.
	bound.seen = now
	b.sessions[sessionID] = bound
	return true
}

// Len reports how many bindings are held. Test and diagnostic use.
func (b *SessionBinder) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.sessions)
}

// sweepLocked drops bindings nothing has touched for SessionTTL, and enforces
// the hard ceiling. Caller holds b.mu.
func (b *SessionBinder) sweepLocked(now time.Time) {
	over := len(b.sessions) > MaxSessionBindings
	// O(n), so not on every call: once per TTL/4 is enough to keep the map
	// proportional to live sessions rather than to sessions ever created.
	if !over && now.Sub(b.lastSweep) < SessionTTL/4 {
		return
	}
	b.lastSweep = now
	for id, bd := range b.sessions {
		if now.Sub(bd.seen) >= SessionTTL {
			delete(b.sessions, id)
		}
	}
	if len(b.sessions) <= MaxSessionBindings {
		return
	}
	// Still over the ceiling: drop the least recently seen until it fits.
	type aged struct {
		id   string
		seen time.Time
	}
	all := make([]aged, 0, len(b.sessions))
	for id, bd := range b.sessions {
		all = append(all, aged{id, bd.seen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for _, a := range all[:len(all)-MaxSessionBindings] {
		delete(b.sessions, a.id)
	}
}

// Release forgets a finished session.
func (b *SessionBinder) Release(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, sessionID)
}
