// Package node is the composition root of the public surface: the one place
// where a config, a store and a keyring become a serving node.
//
// It wires, it does not decide. Every policy call it makes belongs to another
// package — `policy.Allow` for authorization, `public.Identifier` for the seal
// and client-cert knobs, `public.LANGuard` for source refusal, the tool set of
// `public.BuiltinEntries` for what a caller may reach. What lives here is the
// assembly those parts assume: per-account keypairs and certificates, one
// registry and pool per account, SNI certificate selection, the route table,
// and the listener lifecycle.
package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/internalui"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
	"github.com/tech-sumit/pact-gateway/internal/public"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// MaxBodyBytes is SPEC §5.7's pre-parse body cap: 5 MiB of inline media plus
// base64 expansion, envelope and JSON overhead, rounded up. Anything larger is
// refused before a parser ever sees it.
const MaxBodyBytes = 8 * 1024 * 1024

// Options are the node's inputs. Everything optional is genuinely optional: a
// node with no calendar provider still serves, answering `unavailable` for the
// tools that would need one.
type Options struct {
	Config  core.Config
	Store   store.Store
	Keyring *core.Keyring

	// Audit receives every refusal the surface issues before dispatch. Nil is
	// allowed only in tests; `serve` always supplies the hash-chain writer.
	Audit func(action, resource, outcome string)
	// AuditAs records events attributable to a resolved public caller, tagged
	// with that caller's tier. Nil falls back to Audit.
	AuditAs func(actorKind, action, resource, outcome string)
	Now     func() time.Time

	// Calendar and Status are per-account capability providers, keyed by
	// account id. A missing entry is not an error (SPEC §6.10).
	//
	// They are read ONCE, when the account is built, so they cannot express an
	// integration connected later. Prefer Capabilities for anything dynamic.
	Calendar map[string]public.Calendar
	Status   map[string]public.StatusSource

	// Capabilities resolves an account's providers at CALL time (escalation E5,
	// option B). The maps above are a snapshot taken during composition; an
	// integration connected, withheld or restored afterwards would never appear
	// through them, which contradicts §6.10's lifecycle. nil falls back to the
	// maps, and then to §6.7's node-local default.
	Capabilities func(accountID string) (public.Calendar, public.StatusSource)

	// Relay, when set, is mounted at /relay/mcp (SPEC §5.2). Mounting a relay
	// on an edge-mode listener is refused: the relay verifies signatures with
	// the caller's certificate key, which a terminating edge never delivers
	// (SPEC §10.5).
	Relay http.Handler

	// RelayControl is the relay's control plane at /relay/allowlist — a
	// recipient telling its relay who may queue for it. It rides the same mTLS
	// and carries the same edge restriction as Relay, and is plain HTTP rather
	// than a fourth MCP tool because PACT §9 defines exactly three relay verbs.
	RelayControl http.Handler

	// Adapter names the active tunnel adapter; it shapes the LAN guard and the
	// trusted source-IP header. "" or "direct" means the node's own listener.
	Adapter string

	// IngressFingerprint pins the terminating ingress on the onward leg
	// (SPEC §10.6). Empty means no ingress terminates for this node. It is a
	// TRANSPORT check only: caller identity in terminate mode comes from the
	// sealed envelope, and this certificate never reaches identification.
	IngressFingerprint string

	// BlobDir overrides where inline media is stored (default: <data_dir>/blobs).
	BlobDir string
	// DialContext overrides how outbound calls reach a contact's host; nil
	// dials it. Tests map the hosts leaves name onto local listeners with it.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// RateBudget reports the per-hour call cap for a caller kind while the node
	// runs; 0 = PACT §12's documented numbers. A function, not a snapshot, so
	// raising the cap from the portal takes effect on the next call.
	RateBudget func(kind public.LimitKind) int
	// Quota reports an account's media quota in bytes; 0 = the documented
	// default (SPEC §7.4). Read at build time, per account.
	Quota func(accountID string) int64

	// Bus is the node-wide event bus (SPEC §7.8). Supplying it lets the portal
	// and the owner MCP see the same events the public surface publishes; nil
	// makes one, reachable through Bus().
	Bus *messaging.Bus
}

// account is one identity's whole serving state.
type account struct {
	// seal is the account's live X-PACT-SEAL policy. It is read by BOTH the
	// card builder and the envelope gate, so the two can never disagree — a
	// card advertising `required` while the gate accepts plaintext would be a
	// wire-visible lie (SPEC §4.6).
	seal  atomic.Value // core.Seal
	rec   store.Account
	kp    *identity.Keypair
	cert  tls.Certificate
	spki  []byte
	pool  *public.Pool
	ident *public.Identifier
	cm    *contacts.Manager
	msg   *messaging.Service
	media *messaging.MediaService
	// sealedEntries is the prebuilt sealed_call group, held so SetSeal can
	// reinstall it when the policy comes back from none.
	sealedEntries []public.Entry
	// reg is the account's tool registry. It is kept so an integration's tool
	// group can be revised after startup (§6.5, §6.10) — it used to be created
	// inside per-account setup and dropped, so nothing could ever change.
	reg *public.Registry
}

// Node is a composed, not-yet-listening public surface.
type Node struct {
	opts    Options
	cfg     core.Config
	idm     *identity.Manager
	srv     *public.Server
	handler http.Handler

	mu       sync.RWMutex
	accounts map[string]*account // by account id
	bySlug   map[string]*account
	byHost   map[string]*account // PACT 2.0: the leaf's endpoint host → account

	limiter *public.Limiter
	// binder pins an MCP session id to the identity that created it (SPEC §5.6).
	// Without it a caller who gains or changes identity mid-connection keeps the
	// surface the session was composed for.
	binder *public.SessionBinder

	lnMu sync.Mutex
	ln   net.Listener
	http *http.Server

	// live knobs the portal changes while the node serves. They are read on
	// every use rather than captured, so a saved change takes effect without a
	// restart (SPEC §8.2).
	liveMu    sync.RWMutex
	publicURL string
	lanAllow  bool
}

func (o Options) audit(action, resource, outcome string) {
	if o.Audit != nil {
		o.Audit(action, resource, outcome)
	}
}

func (o Options) auditAs(kind, action, resource, outcome string) {
	if o.AuditAs != nil {
		o.AuditAs(kind, action, resource, outcome)
		return
	}
	o.audit(action, resource, outcome)
}

// New assembles the node. It loads every account's key eagerly: a node that
// cannot open one of its identities must fail at startup, not on the first call.
func New(ctx context.Context, o Options) (*Node, error) {
	if o.Store == nil {
		return nil, fmt.Errorf("node: no store")
	}
	if o.Relay != nil && o.Config.Mode == core.ModeEdge {
		return nil, fmt.Errorf("node: relay mode cannot run on an edge-mode listener (SPEC §10.5): " +
			"a terminating edge never delivers the caller's certificate, and the relay verifies signatures with it")
	}
	if o.Bus == nil {
		o.Bus = messaging.NewBus()
	}
	n := &Node{
		opts: o, cfg: o.Config,
		idm:      &identity.Manager{Store: o.Store, Keyring: o.Keyring},
		accounts: map[string]*account{},
		bySlug:   map[string]*account{},
		byHost:   map[string]*account{},
	}
	n.publicURL, n.lanAllow = o.Config.PublicURL, o.Config.LANConnections
	recs, err := o.Store.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("node: list accounts: %w", err)
	}
	for _, rec := range recs {
		a, err := n.buildAccount(ctx, rec)
		if errors.Is(err, errAwaitingLeaf) {
			o.audit("account_awaiting_leaf", "account:"+rec.ID+" slug:"+rec.Slug, "skipped")
			continue
		}
		if err != nil {
			return nil, err
		}
		n.accounts[rec.ID] = a
		n.bySlug[rec.Slug] = a
		n.indexHost(a)
	}

	n.srv = &public.Server{
		GetCertificate: n.certificate,
		Accounts:       n.Slugs,
		MCP:            n.mcpHandler(),
		Invite:         n.inviteHandler(),
		Relay:          http.NotFoundHandler(),
		RelayControl:   http.NotFoundHandler(),
		// the probe answers for whatever the node currently advertises
		Probe: probeHandler(n.PublicURL),
		SourceIP: func(r *http.Request) string {
			return tunnel.SourceIP(o.Adapter, o.Config.Mode == core.ModeEdge, r)
		},
		// A pinned terminating ingress presents ITS certificate on the onward
		// leg. It is checked at the handshake and must go no further: caller
		// identity in terminate mode comes from the sealed envelope (§10.1).
		IgnoreClientCert: func() bool { return o.IngressFingerprint != "" },
	}
	if o.Relay != nil {
		n.srv.Relay = o.Relay
	}
	if o.RelayControl != nil {
		n.srv.RelayControl = o.RelayControl
	}

	// Order matters, outermost first: cap the body before anything parses it,
	// refuse LAN sources before any handler runs, count the call against its
	// caller's budget, then the routes.
	// PACT §12's caps: 60 calls/hour per contact, 10/hour per guest IP+key.
	// Installed through Server.Inner so it runs INSIDE the facts middleware —
	// it classifies by the caller's fingerprint, which does not exist until the
	// TLS facts are attached — and still outside the routes, so a refusal costs
	// nothing downstream.
	n.limiter = public.NewLimiter(o.Now)
	if o.RateBudget != nil {
		n.limiter.Budget = func(k public.LimitKey) int { return o.RateBudget(k.Kind) }
	}
	n.binder = public.NewSessionBinder()
	h := n.srv.Handler()
	h = public.LANGuard{
		Adapter: o.Adapter, AllowFn: n.LANAllowed,
		TrustedHeader: tunnel.TrustedClientIPHeader(o.Adapter),
		Audit:         o.audit,
	}.Middleware(h)
	h = public.CapBody(h, MaxBodyBytes)
	n.handler = h
	return n, nil
}

// quotaFor is the account's configured media quota, or 0 for the default.
func (n *Node) quotaFor(accountID string) int64 {
	if n.opts.Quota == nil {
		return 0
	}
	return n.opts.Quota(accountID)
}

// consumeBudget spends one unit of this caller's PACT §12 allowance.
func (n *Node) consumeBudget(ctx context.Context) (bool, time.Duration) {
	key := n.classifyCtx(ctx)
	ok, retry := n.limiter.Allow(key)
	if !ok {
		n.opts.audit("rate_limited", string(key.Kind)+":"+fprOr(key.Fingerprint, key.IP), "refused")
	}
	return ok, retry
}

func fprOr(fpr, ip string) string {
	if fpr != "" {
		return fpr
	}
	return ip
}

// classify decides which budget a request counts against (SPEC §5.7). A
// contact has an identity and gets the per-contact budget; anyone else is a
// guest, budgeted per IP AND key so one address cannot exhaust every guest and
// one key cannot hop addresses. The source address comes from the adapter's
// trusted header behind a terminating edge and from the socket otherwise —
// never a generic forwarded-for header.
func (n *Node) classifyCtx(ctx context.Context) public.LimitKey {
	f := public.FactsFrom(ctx)
	ip := f.RemoteIP

	// WHO is calling, by the same rule CallerSPKI uses: the envelope when the
	// call was sealed, the client certificate when it was not.
	//
	// Reading only the certificate made this unusable in edge mode. Edge mode
	// FORCES client_cert off (§10.1) because the edge terminates TLS and the node
	// never sees one — identity there comes from the sealed envelope and nowhere
	// else. So every contact was classified as an anonymous guest and budgeted per
	// IP, and since a tunnelled peer arrives from its edge's address, all of them
	// shared one bucket: a normal exchange between two contacts exhausted the
	// guest allowance (PACT §12: 10/hour) and everything after it was refused
	// `rate_limited`. Cloudflare, ngrok and terminate-mode ingress were all
	// affected — which is to say every deployment that is not directly reachable.
	caller := f.ClientCertFingerprint
	if e := public.EnvelopeFactsFrom(ctx); e != nil && e.From != "" {
		// The envelope's sender is PROVEN: §4.4 verifies its signature before any
		// dispatch, so this is not a claim the caller can simply assert.
		caller = e.From
	}

	if caller != "" {
		// Budgets are per CALLER, not per account, so being a contact of any
		// account on this node earns the contact budget. An unknown fingerprint
		// is still a guest and keeps the IP dimension, so one key cannot hop
		// addresses and one address cannot exhaust every guest.
		n.mu.RLock()
		ids := make([]string, 0, len(n.accounts))
		for id := range n.accounts {
			ids = append(ids, id)
		}
		n.mu.RUnlock()
		for _, id := range ids {
			if c, err := n.opts.Store.GetContact(ctx, id, caller); err == nil && c.Status == "active" {
				return public.LimitKey{Kind: public.KindContact, Fingerprint: caller}
			}
		}
	}
	return public.LimitKey{Kind: public.KindGuest, Fingerprint: caller, IP: ip}
}

// probeHandler defers the public URL to call time; the owner can change it while
// the node serves, and a probe answering for the startup value would report on a
// URL nobody is using any more.
func probeHandler(publicURL func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tunnel.ProbeHandler(publicURL()).ServeHTTP(w, r)
	})
}

// buildAccount loads one account's key and composes its serving state.
// errAwaitingLeaf marks an account that holds no key: imported data-only,
// waiting for the wallet's leaf before it serves (PACT §9).
var errAwaitingLeaf = errors.New("node: account awaits a leaf from its wallet")

func (n *Node) buildAccount(ctx context.Context, rec store.Account) (*account, error) {
	sealed, err := n.opts.Store.GetAccountSealedKey(ctx, rec.ID)
	if err != nil {
		return nil, fmt.Errorf("node: account %s has no key: %w", rec.Slug, err)
	}
	if len(sealed) == 0 {
		// A data-only import (PACT §9): the account is here, its key is not,
		// and it serves nothing until the wallet issues a leaf to this host.
		return nil, errAwaitingLeaf
	}
	kp, err := n.idm.LoadKeypair(sealed)
	if err != nil {
		return nil, fmt.Errorf("node: account %s: %w", rec.Slug, err)
	}
	if kp.Fingerprint != rec.Fingerprint {
		return nil, fmt.Errorf("node: account %s: stored key does not match its pinned fingerprint", rec.Slug)
	}
	// A 2.0 account (PACT §2) serves under the leaf the person's root issued:
	// the leaf's key is the key above, and the chain — leaf then root — is what
	// TLS presents. A 1.x account keeps its self-signed certificate.
	var cert tls.Certificate
	if rec.Protocol == 2 {
		keys, err := n.idm.ActiveLeafKeypairs(ctx, rec.ID, n.now())
		if err != nil {
			return nil, fmt.Errorf("node: account %s leaves: %w", rec.Slug, err)
		}
		if len(keys) == 0 || !keys[0].Current || keys[0].Kid != rec.Fingerprint {
			return nil, fmt.Errorf("node: account %s is 2.0 but its current leaf is not the key it serves under", rec.Slug)
		}
		kp = keys[0].KP
		cert = tls.Certificate{Certificate: [][]byte{kp.Leaf, kp.Root}, PrivateKey: kp.Signer}
	} else {
		der, err := identity.SelfSignedCert(kp, rec.Slug)
		if err != nil {
			return nil, fmt.Errorf("node: account %s certificate: %w", rec.Slug, err)
		}
		cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
	}
	spki, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		return nil, err
	}
	a := &account{
		rec: rec, kp: kp, spki: spki,
		cert: cert,
		cm: &contacts.Manager{
			Store: n.opts.Store,
			// A guest's `request_contact` is the main way a request appears, so
			// this is the manager that must reach the bus (SPEC §8.5, §9.1).
			OnRequest: func(accountID, contactFpr string) {
				if n.opts.Bus != nil {
					n.opts.Bus.Publish(messaging.Event{
						Kind: messaging.EventRequest, AccountID: accountID, ContactFpr: contactFpr,
					})
				}
			},
		},
		msg: &messaging.Service{Store: n.opts.Store, Bus: n.opts.Bus, Now: n.opts.Now},
	}

	blobs := n.opts.BlobDir
	if blobs == "" {
		blobs = filepath.Join(n.cfg.DataDir, "blobs")
	}
	reg := &public.Registry{}
	a.reg = reg
	a.pool = public.NewPool(reg, public.StoreResolver(n.opts.Store), 256)
	a.pool.CallAudit = func(kind, action, resource, outcome string) {
		n.opts.auditAs(kind, action, "account:"+rec.ID+" "+resource, outcome)
	}

	// The account row is the card's source; the node policy is the truth. Mirror
	// it now so a card can never advertise a policy the gate does not enforce.
	eff := core.EffectiveSeal(n.cfg.Mode, n.cfg.Seal)
	a.seal.Store(eff)
	if rec.Seal != string(eff) {
		if err := n.opts.Store.UpdateAccountSeal(ctx, rec.ID, string(eff)); err != nil {
			return nil, fmt.Errorf("node: account %s seal: %w", rec.Slug, err)
		}
		rec.Seal = string(eff)
		a.rec = rec
	}
	ident := &public.Identifier{
		Store:     n.opts.Store,
		AccountID: rec.ID,
		// A contact re-pinned during rotation holds only a fingerprint until
		// its key next connects (§3.9); this is where that key is recorded.
		BindKey: a.cm.BindSPKI,
		Keypair: func(context.Context, string) (*identity.Keypair, error) { return kp, nil },
		Cert:    n.cfg.ClientCert,
		SealFn:  func() core.Seal { return a.sealValue() },
		Now:     n.opts.Now,
		Audit:   n.opts.audit,
		// PACT 2.0: what a `v: 2` envelope is decided against, read per call
		// so the owner's settings and a renewal take effect without a restart.
		State20: func(ctx context.Context) (*public.State20, error) { return n.state20(ctx, rec.ID, rec.Slug) },
		OnEvent: func(event, root, endpoint string) {
			if n.opts.Bus != nil {
				n.opts.Bus.Publish(messaging.Event{Kind: messaging.EventCall, AccountID: rec.ID, ContactFpr: root})
			}
		},
		OnPending: func(root, endpoint, why string) {
			// A contact at a new address awaiting the owner appears beside
			// contact requests (PACT §5.3), so it wakes the same feed.
			if n.opts.Bus != nil {
				n.opts.Bus.Publish(messaging.Event{Kind: messaging.EventRequest, AccountID: rec.ID, ContactFpr: root})
			}
		},
	}
	a.pool.Gate = ident.PoolGate()
	a.pool.Limit = n.consumeBudget
	a.pool.AccountID = rec.ID
	a.ident = ident

	// One MediaService per account, kept on the account so the OWNER's surface
	// (fetch, read) reaches the same quota and blob store the public surface
	// writes through — two instances would mean two views of one quota.
	a.media = &messaging.MediaService{
		Store: n.opts.Store, Blobs: messaging.BlobDir{Root: blobs},
		// read per call, not captured: the owner can change the quota from
		// the portal and it must take effect without a restart (§8.2).
		Quota: func() int64 { return n.quotaFor(rec.ID) },
		Now:   n.opts.Now,
		Audit: n.opts.audit,
	}
	reg.Add(public.BuiltinEntries(public.ToolDeps{
		AccountID: rec.ID,
		Contacts:  a.cm,
		Messages:  a.msg,
		Media:     a.media,
		Calendar:  calendarAt{n: n, accountID: rec.ID},
		Status:    statusAt{n: n, accountID: rec.ID},
		Card: func(ctx context.Context) (string, string, []byte, error) {
			card, err := n.Card(ctx, rec.ID)
			if err != nil {
				return "", "", nil, err
			}
			// The SAME signature the invite landing page serves: a card that is
			// signed over one transport and bare over another is a card a
			// redeemer cannot rely on (PACT §4).
			sig, err := n.idm.SignCard(ctx, rec.ID, card)
			return card, sig, spki, err
		},
		Invalidate: a.pool.Invalidate,
		Endpoint:   func() string { return identity.EndpointFor(n.PublicURL(), rec.Slug) },
		Chain:      func(ctx context.Context) ([][]byte, error) { return n.idm.Chain(ctx, rec.ID) },
		// Read per call, like Quota: the rate caps are owner knobs (§12), and a
		// card must advertise what the gate currently enforces.
		Limits: func() public.Limits {
			l := public.DefaultLimits()
			if rb := n.opts.RateBudget; rb != nil {
				if b := rb(public.KindContact); b > 0 {
					l.ContactCallsPerHour = b
				}
				if b := rb(public.KindGuest); b > 0 {
					l.GuestCallsPerHour = b
				}
			}
			return l
		},
		Audit: func(action, resource, outcome string) {
			n.opts.audit(action, "account:"+rec.ID+" "+resource, outcome)
			// A contact ACTED — wake the owner's change feed (§7.7). Messages
			// wake it through the messaging service; the calendar and media
			// tools would otherwise be invisible until the next poll.
			if n.opts.Bus != nil && wakesFeed(action, outcome) {
				n.opts.Bus.Publish(messaging.Event{Kind: messaging.EventCall, AccountID: rec.ID})
			}
		},
	})...)

	// sealed_call at every tier, wrapping the same pool (SPEC §4.5). A NAMED
	// group, not a builtin: at seal `none` the tool must be absent from
	// tools/list (PACT §13.4 — the card says senders must not seal, and the
	// list has to tell the same truth), so SetSeal replaces or deletes the
	// group the way integration tools come and go.
	a.sealedEntries = public.SealedEntries(public.SealedDeps{
		Pool: a.pool, Identifier: ident, AccountID: rec.ID, AccountFpr: kp.Fingerprint,
		Keypair: func(context.Context) (*identity.Keypair, error) { return kp, nil },
		Idem:    n.opts.Store,
		Now:     n.opts.Now,
		Audit:   n.opts.audit,
	})
	if a.sealValue() != core.SealNone {
		reg.Replace(sealedGroup, a.sealedEntries)
	}
	return a, nil
}

// sealedGroup names the registry group holding sealed_call, so a live policy
// change can install or remove it without touching anything else.
const sealedGroup = "sealed"

/* ------------------------------- accessors ------------------------------ */

// Slugs lists the account slugs, sorted so routing and the /mcp alias rule are
// deterministic.
func (n *Node) Slugs() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]string, 0, len(n.bySlug))
	for slug := range n.bySlug {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}

// Card renders an account's current vCard (SPEC §9.3).
func (n *Node) Card(ctx context.Context, accountID string) (string, error) {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil {
		return "", fmt.Errorf("node: unknown account %s", accountID)
	}
	rec, err := n.opts.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		rec = a.rec // a store blip must not stop us answering with what we know
	}
	// PACT §3: a 2.0 card carries the leaf and nothing the leaf already says.
	if rec.Protocol == 2 {
		chain, err := n.idm.Chain(ctx, accountID)
		if err != nil {
			return "", err
		}
		return contacts.BuildCard20(rec.DisplayName, chain[0], string(a.sealValue())), nil
	}
	endpoint := ""
	if base := n.PublicURL(); base != "" {
		endpoint = base + "/a/" + rec.Slug + "/mcp"
	}
	return contacts.BuildCard(contacts.Card{
		FN: rec.DisplayName, Endpoint: endpoint, Key: rec.Fingerprint,
		// the SAME value the gate enforces, never the raw row
		Seal: string(a.sealValue()),
		// A peer whose direct delivery fails looks here for somewhere to queue
		// (PACT §9). Without it, "your node was down" is simply a lost message.
		Gateway: n.cfg.GatewayURL,
	})
}

func (n *Node) now() time.Time {
	if n.opts.Now != nil {
		return n.opts.Now()
	}
	return time.Now()
}

// state20 is what a `v: 2` envelope for an account is decided against (PACT
// §13.3): the account's own endpoint and settings, its chain, the keys it holds
// today, the kids it once held, and the kids every OTHER account on this node
// holds — a key held for another identity must never answer at this one's path
// (§14.4).
func (n *Node) state20(ctx context.Context, accountID, slug string) (*public.State20, error) {
	rec, err := n.opts.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	st := &public.State20{
		Protocol: int(rec.Protocol), Endpoint: identity.EndpointFor(n.PublicURL(), slug),
		AcceptNewHosts: rec.AcceptNewHosts, Accept1x: rec.Accept1x,
	}
	if rec.Protocol != 2 {
		return st, nil
	}
	if st.Chain, err = n.idm.Chain(ctx, accountID); err != nil {
		return nil, err
	}
	if st.Keys, err = n.idm.ActiveLeafKeypairs(ctx, accountID, n.now()); err != nil {
		return nil, err
	}
	if st.Former, err = n.idm.FormerKids(ctx, accountID); err != nil {
		return nil, err
	}
	others, err := n.opts.Store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		if o.ID == accountID {
			continue
		}
		if o.Fingerprint != "" {
			st.SiblingKids = append(st.SiblingKids, o.Fingerprint)
		}
		if leaves, err := n.opts.Store.ListLeaves(ctx, o.ID); err == nil {
			for _, l := range leaves {
				st.SiblingKids = append(st.SiblingKids, l.Kid)
			}
		}
	}
	return st, nil
}

// PublicURL is the externally reachable base the card advertises.
func (n *Node) PublicURL() string {
	n.liveMu.RLock()
	defer n.liveMu.RUnlock()
	return n.publicURL
}

// SetPublicURL changes the advertised endpoint. Contacts hold the OLD one, so
// the caller is expected to follow this with AnnounceEndpointChange.
func (n *Node) SetPublicURL(url string) {
	n.liveMu.Lock()
	n.publicURL = url
	n.liveMu.Unlock()
	n.opts.auditAs("owner", "settings_public_url", "url:"+url, "ok")
}

// LANAllowed reports whether connections from private-range sources are served.
func (n *Node) LANAllowed() bool {
	n.liveMu.RLock()
	defer n.liveMu.RUnlock()
	return n.lanAllow
}

// SetLANConnections flips the LAN flag for the next connection.
func (n *Node) SetLANConnections(allow bool) {
	n.liveMu.Lock()
	n.lanAllow = allow
	n.liveMu.Unlock()
	n.opts.auditAs("owner", "settings_lan", "", boolWord(allow))
}

func boolWord(b bool) string {
	if b {
		return "allowed"
	}
	return "refused"
}

// sealValue reads the account's live seal policy.
func (a *account) sealValue() core.Seal {
	if v, ok := a.seal.Load().(core.Seal); ok {
		return v
	}
	return core.SealRequired
}

// SetSeal changes an account's seal policy while the node serves: the gate and
// the card both pick it up on the next call, with no restart (SPEC §8.2).
// A mode that forces sealing wins, so the caller cannot lower it below what the
// deployment can honor.
func (n *Node) SetSeal(ctx context.Context, accountID string, want core.Seal) error {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil {
		return fmt.Errorf("node: unknown account %s", accountID)
	}
	// Persist the EFFECTIVE value, never the requested one. The row is what card
	// emitters read and the cell is what the gate enforces; writing the raw
	// request here would let a forced mode split them apart, which is the exact
	// defect this method was introduced to close.
	eff := core.EffectiveSeal(n.cfg.Mode, want)
	if err := n.opts.Store.UpdateAccountSeal(ctx, accountID, string(eff)); err != nil {
		return err
	}
	a.seal.Store(eff)
	// The served surface must move with the policy: at `none` sealed_call
	// leaves tools/list (PACT §13.4), otherwise it is (re)installed — and the
	// cached per-caller servers are reconciled so live sessions see
	// tools/list_changed, the same mechanics integration tools use.
	if a.reg != nil {
		if eff == core.SealNone {
			a.reg.Replace(sealedGroup, nil)
		} else {
			a.reg.Replace(sealedGroup, a.sealedEntries)
		}
		n.InvalidateAccount(ctx, accountID)
	}
	n.opts.auditAs("owner", "settings_seal", "account:"+accountID, string(a.sealValue()))
	return nil
}

// SPKI returns an account's public key, for the invite landing page and any
// caller that must verify a fingerprint itself.
func (n *Node) SPKI(accountID string) ([]byte, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	a := n.accounts[accountID]
	if a == nil {
		return nil, fmt.Errorf("node: unknown account %s", accountID)
	}
	return a.spki, nil
}

// Bus is the node-wide event bus every account's messaging service publishes to.
func (n *Node) Bus() *messaging.Bus { return n.opts.Bus }

// Messages exposes an account's messaging service, so the portal and the owner
// MCP record through the same instance the public surface does.
func (n *Node) Messages(accountID string) *messaging.Service {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if a := n.accounts[accountID]; a != nil {
		return a.msg
	}
	return nil
}

// Contacts exposes an account's contact manager.
func (n *Node) Contacts(accountID string) *contacts.Manager {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if a := n.accounts[accountID]; a != nil {
		return a.cm
	}
	return nil
}

// Invalidate drops a caller's cached server on any account — the portal calls
// it when a switchboard changes (SPEC §5.5).
// ServedPermissions is every contact-tier permission this account's public
// surface currently gates a tool with: the core five, plus one per live
// integration exposure (SPEC §6.4). The portal's switchboard is built from it,
// so what the node can serve is exactly what the owner can grant.
func (n *Node) ServedPermissions(accountID string) []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if a := n.accounts[accountID]; a != nil && a.reg != nil {
		return a.reg.GatedPermissions()
	}
	return nil
}

func (n *Node) Invalidate(ctx context.Context, accountID, fpr string) error {
	if p := n.Pool(accountID); p != nil {
		return p.Invalidate(ctx, accountID, fpr)
	}
	return nil
}

// SignCard signs an account's card with its identity key (SPEC §9.3).
func (n *Node) SignCard(ctx context.Context, accountID, cardText string) (string, error) {
	return n.idm.SignCard(ctx, accountID, cardText)
}

// Certificate returns an account's identity certificate — what an outbound leg
// presents so the far side recognizes the key it pinned. Ingress pairing needs
// it (SPEC §10.6).
func (n *Node) Certificate(accountID string) (tls.Certificate, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	a := n.accounts[accountID]
	if a == nil {
		return tls.Certificate{}, fmt.Errorf("node: unknown account %s", accountID)
	}
	return a.cert, nil
}

// OutboundClient builds a client that calls out AS this account: its identity
// certificate, so the far side recognizes the key it pinned. Everything that
// leaves the node on the owner's behalf goes through this, so there is one
// place where outbound identity is decided.
func (n *Node) OutboundClient(accountID string) (*outbound.Client, error) {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil {
		return nil, fmt.Errorf("node: unknown account %s", accountID)
	}
	// Roots stays nil: nil means the SYSTEM roots, and an empty pool would mean
	// "trust nothing", which silently kills the WebPKI branch of PACT §2 — so
	// this node could reach pinned self-signed peers and nothing behind an edge.
	return n.wire20(accountID, &outbound.Client{Keypair: a.kp, Cert: a.cert}), nil
}

// Pool exposes an account's caller pool, so the portal can drop a cached server
// the moment a switchboard changes (SPEC §5.5).
func (n *Node) Pool(accountID string) *public.Pool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if a := n.accounts[accountID]; a != nil {
		return a.pool
	}
	return nil
}

// Handler is the fully wrapped public HTTP surface.
func (n *Node) Handler() http.Handler { return n.handler }

// TLSConfig is the listener posture of SPEC §5.1: request client certificates,
// never require them, and pick the server certificate through SNI.
func (n *Node) TLSConfig() *tls.Config {
	tc := n.srv.TLSConfig()
	if n.cfg.ClientCert == core.ClientCertOff {
		// No CertificateRequest at all: behind a terminating edge one would only
		// confuse the connector, and no certificate can reach us anyway (§5.1).
		tc.ClientAuth = tls.NoClientCert
	}
	// Behind a TERMINATING ingress the only party that may open this connection
	// is the ingress we paired with. Its certificate is a transport check and
	// nothing more: caller identity in terminate mode comes from the sealed
	// envelope (§10.1), and `public.Identifier` never sees this certificate — so
	// pinning here cannot promote the ingress into a caller (§10.6).
	if fpr := n.opts.IngressFingerprint; fpr != "" {
		tc.ClientAuth = tls.RequireAnyClientCert
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("node: this listener only accepts its paired ingress")
			}
			got, err := identity.Fingerprint(cs.PeerCertificates[0].PublicKey)
			if err != nil {
				return err
			}
			if got != fpr {
				n.opts.audit("ingress_leg", "presented:"+got, "not_the_paired_ingress")
				return fmt.Errorf("node: %s is not the paired ingress", got)
			}
			return nil
		}
	}
	return tc
}

/* ------------------------------ certificates ---------------------------- */

// certificate is the SNI callback. A hostname that matches an account's slug
// gets that account's identity certificate; anything else — including a caller
// that dialed by IP and sent no SNI — gets the first account's, which is the
// only sensible answer on a single-identity node and harmless on a multi-account
// one, where the caller pins by fingerprint anyway (PACT §2).
// AdoptAccount brings an account created while the node is RUNNING into the live
// node: its keypair, its certificate, and its per-caller MCP surface.
//
// Without it the node only knew the accounts that existed when it started, so
// `account create` on a running node produced an account the public listener
// could not serve — every handshake for it failed with `tls: internal error`
// (alert 80) until the node was restarted. The README quickstart tells a new
// owner to do exactly that: `docker compose up`, then `account create`.
//
// Idempotent: adopting an account the node already holds rebuilds it, which is
// also what makes it safe to call after a key rotation.
func (n *Node) AdoptAccount(ctx context.Context, accountID string) error {
	recs, err := n.opts.Store.ListAccounts(ctx)
	if err != nil {
		return fmt.Errorf("node: list accounts: %w", err)
	}
	var rec store.Account
	for _, r := range recs {
		if r.ID == accountID {
			rec = r
		}
	}
	if rec.ID == "" {
		return fmt.Errorf("node: adopt: unknown account %q", accountID)
	}
	a, err := n.buildAccount(ctx, rec)
	if err != nil {
		return fmt.Errorf("node: adopt %s: %w", rec.Slug, err)
	}
	n.mu.Lock()
	n.accounts[rec.ID] = a
	n.bySlug[rec.Slug] = a
	n.indexHost(a)
	n.mu.Unlock()
	return nil
}

// indexHost records the host a 2.0 account's leaf names, for SNI selection.
// Callers hold n.mu.
func (n *Node) indexHost(a *account) {
	if a.rec.Protocol != 2 || len(a.kp.Leaf) == 0 {
		return
	}
	if leaf, err := pactidentity.Parse(a.kp.Leaf); err == nil && len(leaf.URIs) == 1 {
		n.byHost[hostOfEndpoint(leaf.URIs[0])] = a
	}
}

func (n *Node) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if len(n.bySlug) == 0 {
		return nil, fmt.Errorf("node: no accounts, nothing to serve")
	}
	if hello != nil && hello.ServerName != "" {
		host := hello.ServerName
		if i := len(host); i > 0 {
			// A 2.0 leaf names its endpoint (PACT §14.1): the host it names
			// selects it, before any slug heuristic.
			if a := n.byHost[host]; a != nil {
				return &a.cert, nil
			}
			if a := n.bySlug[host]; a != nil {
				return &a.cert, nil
			}
			// `alice.example.com` selects account `alice`
			if dot := indexByte(host, '.'); dot > 0 {
				if a := n.bySlug[host[:dot]]; a != nil {
					return &a.cert, nil
				}
			}
		}
	}
	slugs := make([]string, 0, len(n.bySlug))
	for slug := range n.bySlug {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	a := n.bySlug[slugs[0]]
	return &a.cert, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

/* -------------------------------- routes -------------------------------- */

// mcpHandler serves /a/{slug}/mcp: the per-caller MCP server for the account
// the path names and the identity the transport earned.
func (n *Node) mcpHandler() http.Handler {
	inner := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		slug := r.PathValue("slug")
		n.mu.RLock()
		a := n.bySlug[slug]
		n.mu.RUnlock()
		if a == nil {
			return nil
		}
		f := public.FactsFrom(r.Context())
		caller := f.ClientCertFingerprint
		if f.ClientProtocol == 2 && a.rec.Protocol != 2 {
			caller = public.LegacyCaller(f) // Appendix C row 4: a 1.x identity reads the leaf's key
		}
		if tc, ok := public.TransportCallerFrom(r.Context()); ok {
			// A 2.0 chain earns exactly what the pin checks allowed
			// (resolveTransport): the root, or an anonymous guest.
			caller = tc.Fingerprint
		}
		srv, err := a.pool.ServerFor(r.Context(), a.rec.ID, caller)
		if err != nil {
			n.opts.audit("tools_list", "account:"+a.rec.ID, "unavailable")
			return nil
		}
		return srv
	}, &mcp.StreamableHTTPOptions{
		// The SDK auto-enables DNS-rebinding protection whenever the accepted
		// connection's LOCAL address is loopback and Host is not
		// (mcp/streamable.go:326). That is exactly what EVERY reverse tunnel
		// produces — the connector runs on this host and dials this bind — so it
		// refused every tunnelled MCP call, in direct mode as much as edge.
		//
		// Off here and only here. This surface is always TLS (see serve: the
		// listener is wrapped by tls.NewListener) and presents the node's own
		// certificate, so a rebinding page cannot complete a handshake for the
		// attacker's name and never reaches a Host check. The owner MCP is plain
		// HTTP on loopback and KEEPS the protection (§8.3, §8.4).
		DisableLocalhostProtection: true,
	})
	return n.resolveTransport(n.bindSession(inner))
}

// resolveTransport runs the pin checks of PACT §14.3 and §5.3 on a 2.0 client
// chain ONCE per request, before the per-caller server is composed and the
// session bound, and puts the outcome in the context. Without it the
// transport path composed the contact's surface for any chain that validated
// — a former host's still-valid leaf, a stolen and since-renewed one, a leaf
// for an address the owner has not approved — checks the sealed path always
// made. The two paths now reach the same outcome from the same rules.
func (n *Node) resolveTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := public.FactsFrom(r.Context())
		if f.ClientProtocol != 2 {
			next.ServeHTTP(w, r)
			return
		}
		n.mu.RLock()
		a := n.bySlug[r.PathValue("slug")]
		n.mu.RUnlock()
		if a == nil || a.rec.Protocol != 2 {
			next.ServeHTTP(w, r)
			return
		}
		tc := a.ident.ResolveTransport(r.Context(), f)
		next.ServeHTTP(w, r.WithContext(public.WithTransportCaller(r.Context(), tc)))
	})
}

// bindSession enforces SPEC §5.6 — "a session belongs to the identity that
// created it" — on EVERY request.
//
// This check used to live inside the getServer callback, where it never ran.
// The go-sdk calls getServer ONLY for a request carrying no session id: one that
// presents an id goes straight to the cached session, and GET and DELETE never
// call it at all. So the guard fired only in the case where it did not apply,
// and a caller who learned a session id was served the surface that session was
// composed for — holding no certificate of their own. The per-caller server
// closes over the identity it was composed for, so that is a full tier grant.
//
// Binding happens at CREATION, by observing the id the SDK writes into the
// response, not on the first follow-up request. Binding on the follow-up would
// be a race worth winning: whoever sent the next request first would claim the
// session, so an attacker could bind a legitimate caller's session to itself and
// lock the rightful owner of it out.
func (n *Node) bindSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fpr := public.FactsFrom(r.Context()).ClientCertFingerprint
		if tc, ok := public.TransportCallerFrom(r.Context()); ok {
			// The session belongs to the identity the server was composed
			// for — the resolved one, not the certificate's root.
			fpr = tc.Fingerprint
		}
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			if !n.binder.Bind(sid, fpr) {
				n.opts.audit("session_binding", "session:"+sid, "identity_mismatch")
				// The same answer the SDK gives for a session it does not know.
				// Session state must never substitute for identity resolution.
				http.NotFound(w, r)
				return
			}
			if r.Method == http.MethodDelete {
				// The session is ending; stop tracking it, or the map grows one
				// entry per session for the life of the process.
				defer n.binder.Release(sid)
			}
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&bindingWriter{ResponseWriter: w, bind: func(sid string) {
			n.binder.Bind(sid, fpr)
		}}, r)
	})
}

// bindingWriter binds a newly minted session to the identity that created it,
// at the moment the SDK announces the id in the response headers.
type bindingWriter struct {
	http.ResponseWriter
	bind  func(sid string)
	wrote bool
}

func (w *bindingWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if sid := w.Header().Get("Mcp-Session-Id"); sid != "" {
			w.bind(sid)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *bindingWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Flush keeps the streaming transport working: the SDK writes SSE through this
// wrapper, and a response that never flushes is a session that never answers.
func (w *bindingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// inviteHandler serves the landing page of SPEC §9.2 for whichever account
// issued the token.
func (n *Node) inviteHandler() http.Handler {
	return internalui.LandingHandler(internalui.LandingDeps{
		Store: n.opts.Store,
		SignCard: func(accountID string) (string, string, error) {
			card, err := n.Card(context.Background(), accountID)
			if err != nil {
				return "", "", err
			}
			sig, err := n.idm.SignCard(context.Background(), accountID, card)
			return card, sig, err
		},
		SPKI:      n.SPKI,
		Chain:     func(accountID string) ([][]byte, error) { return n.idm.Chain(context.Background(), accountID) },
		PublicURL: n.PublicURL,
		Now:       n.opts.Now,
	})
}

// DeliverSealed runs one envelope through the standard open order and dispatch
// (SPEC §4.4) on behalf of an account. The relay fetch loop uses it: an envelope
// handed over by a relay is NOT trusted because the relay handed it over — it
// takes the same path a directly delivered one would, with the documented
// timestamp relaxation that `d` selects.
func (n *Node) DeliverSealed(ctx context.Context, accountID string, e *envelope.Envelope, d public.Delivery) error {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil {
		return fmt.Errorf("node: unknown account %s", accountID)
	}
	facts, err := a.ident.OpenSealed(ctx, accountID, a.kp.Fingerprint, public.TransportFacts{}, e, d)
	if err != nil {
		return err
	}
	// Envelope idempotency (PACT §13.3) applies HERE most of all: relay-fetched
	// envelopes are the exp-bounded ones — no 300 s window protects them — so a
	// relay that re-serves an item must get "handled", never a re-execution.
	// This path skipped the check entirely; only the direct sealed_call wrapper
	// had it. A replay returns nil so the fetch loop acks and deletes the item.
	if _, replayed, rerr := a.ident.Replay(ctx, n.opts.Store, accountID, facts); rerr == nil && replayed {
		n.auditFor(accountID, "sealed_call", "contact:"+facts.From+" via:relay", "replayed")
		return nil
	}
	out, err := a.pool.Dispatch(public.WithEnvelopeFacts(ctx, facts), accountID, facts.From, facts.Payload)
	if err != nil {
		return err
	}
	// A refused call is still "handled": the item must not wedge the queue, and
	// the refusal is already audited by the surface that issued it.
	if len(out) == 0 {
		return fmt.Errorf("node: empty dispatch result")
	}
	// Finalize the idempotency record with the result, mirroring the direct
	// path: the reservation Replay made above holds the ack from now on.
	if facts.Header.MsgID != "" {
		_ = n.opts.Store.UpdateIdempotencyAck(ctx, accountID, facts.From,
			public.EnvelopeKey(facts.Header.MsgID), string(out))
	}
	return nil
}

/* ------------------------------- lifecycle ------------------------------ */

// Start listens and serves. A nil listener means "dial the configured bind";
// a tunnel adapter supplies its own.
func (n *Node) Start(ctx context.Context, ln net.Listener) error {
	n.lnMu.Lock()
	defer n.lnMu.Unlock()
	if n.http != nil {
		return fmt.Errorf("node: already started")
	}
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", n.cfg.PublicBind)
		if err != nil {
			return fmt.Errorf("node: listen %s: %w", n.cfg.PublicBind, err)
		}
	}
	tlsLn := tls.NewListener(ln, n.TLSConfig())
	srv := &http.Server{
		Handler:           n.handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	n.ln, n.http = tlsLn, srv
	// The goroutine holds its own references: Stop clears the fields, and
	// reading them from here would race with that.
	go func() { _ = srv.Serve(tlsLn) }()
	n.opts.audit("public_listener", "addr:"+tlsLn.Addr().String(), "started")
	return nil
}

// Addr is the listening address, or "" before Start.
func (n *Node) Addr() string {
	n.lnMu.Lock()
	defer n.lnMu.Unlock()
	if n.ln == nil {
		return ""
	}
	return n.ln.Addr().String()
}

// Stop shuts the listener down and releases the port.
func (n *Node) Stop(ctx context.Context) error {
	n.lnMu.Lock()
	srv, ln := n.http, n.ln
	n.http, n.ln = nil, nil
	n.lnMu.Unlock()
	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	if ln != nil {
		_ = ln.Close()
	}
	n.opts.audit("public_listener", "", "stopped")
	return err
}

// wakesFeed reports whether a public-surface audit row is a substantive
// contact action the change feed should wake for. Mirrors the owner MCP's
// callActions — messages are excluded because the messaging bus already wakes.
func wakesFeed(action, outcome string) bool {
	if outcome != "ok" && outcome != "delivered" {
		return false
	}
	// sealed_call is absent on purpose: the wrapper row fires on any opened
	// envelope, refusals included — the inner tool's own audited action is
	// what wakes the feed.
	switch action {
	case "book_slot", "cancel_booking", "check_availability", "send_media", "get_status":
		return true
	}
	return false
}
