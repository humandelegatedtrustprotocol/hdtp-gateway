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
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/ingress"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/tunnel"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// MaxBodyBytes is SPEC §5.7's pre-parse body cap: 5 MiB of inline media plus
// base64 expansion, envelope and JSON overhead, rounded up. Anything larger is
// refused before a parser ever sees it.
const MaxBodyBytes = 8 * 1024 * 1024

// Options are the node's inputs. Everything optional is genuinely optional: a
// node with no calendar provider still serves, answering `unavailable` for the
// tools that would need one.
type Options struct {
	// Config is the resolved configuration: mode, seal and client_cert knobs, public bind and URL,
	// proxy address, LAN flag.
	Config core.Config
	// Store holds accounts, contacts, messages and the audit chain. Required.
	Store store.Store
	// Keyring opens the sealed account keys.
	Keyring *core.Keyring

	// Landing builds the invite landing page of SPEC §9.2 from what the node gives it. It is the
	// portal's page (`serve` supplies internalui.LandingHandler), injected so that the node does not
	// import the portal. Required: New refuses to build a node without it.
	Landing func(LandingDeps) http.Handler

	// Audit receives every refusal the surface issues before dispatch. Nil is
	// allowed only in tests; `serve` always supplies the hash-chain writer.
	Audit func(action, resource, outcome string)
	// AuditAs records events attributable to a resolved public caller, tagged
	// with that caller's tier. Nil falls back to Audit.
	AuditAs func(actorKind, action, resource, outcome string)
	// Now is the node's clock (envelopes, chains, retries); nil means time.Now.
	Now func() time.Time

	// Calendar and Status are per-account capability providers, keyed by
	// account id. A missing entry is not an error (SPEC §6.10).
	//
	// They are read ONCE, when the account is built, so they cannot express an
	// integration connected later. Prefer Capabilities for anything dynamic.
	Calendar map[string]public.Calendar
	// Status is the same snapshot for get_status; with none, a node answers `available` (SPEC §6.7).
	Status map[string]public.StatusSource

	// Capabilities resolves an account's providers at CALL time (escalation E5,
	// option B). The maps above are a snapshot taken during composition; an
	// integration connected, withheld or restored afterwards would never appear
	// through them, which contradicts §6.10's lifecycle. nil falls back to the
	// maps, and then to §6.7's node-local default.
	Capabilities func(accountID string) (public.Calendar, public.StatusSource)

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
	// Limits is the client of the limits sidecar (internal/limits, cmd/hdtp-limitd), which decides
	// every HDTP §12 budget of every account: calls in, calls out, the pending-request cap and each
	// integration's cap. Required. While it does not answer, every call it would decide is refused
	// `unavailable`.
	Limits *limits.Client
	// ContactCap reports how many contacts each account may hold (limit.contacts) while the node
	// runs; nil or 0 = core.DefaultLimitContacts. It is enforced where contacts are added and it
	// sizes every account's call budget (HDTP §12). A function, not a snapshot, so raising it from
	// the portal takes effect on the next call.
	ContactCap func() int
	// Quota reports an account's media quota in bytes; 0 = the documented
	// default (SPEC §7.4). Read at build time, per account.
	Quota func(accountID string) int64

	// SealPolicy is the seal the owner set for the node, read when an account is built — at
	// start and at every adoption — so an account adopted after the owner changed it serves the
	// new one (SPEC §4.6, §8.2). serve supplies the settings service's; nil is Config.Seal.
	SealPolicy func() core.Seal

	// Bus is the node-wide event bus (SPEC §7.8). Supplying it lets the portal
	// and the owner MCP see the same events the public surface publishes; nil
	// makes one, reachable through Bus().
	Bus *messaging.Bus
}

// account is one identity's whole serving state.
type account struct {
	// seal is the account's live X-HDTP-SEAL policy. It is read by BOTH the
	// card builder and the envelope gate, so the two can never disagree — a
	// card advertising `required` while the gate accepts plaintext would be a
	// wire-visible lie (SPEC §4.6).
	seal  atomic.Value // core.Seal
	rec   store.Account
	kp    *identity.Keypair
	cert  tls.Certificate
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
	byHost   map[string]*account // HDTP 1.0: the leaf's endpoint host → account
	// Slugs the store holds that this node cannot serve yet: they have no
	// certificate, so there is nothing to present at a handshake. Kept so the
	// operator can be TOLD which ones and what to run, rather than meeting a
	// node that reports "serving" and answers for nobody.
	awaiting map[string]struct{}
	// Slugs this node holds and could not build, each with why. An account awaiting a leaf is
	// ordinary and says what to run; one of these is broken — most often a key sealed under a
	// master key that is not this one — and until 2026-09-19 it was an audit row and nothing
	// else, so `serve` printed "serving" over an account that answered nobody.
	unavailable map[string]string

	// follow is Follow's subscription, made with the node so nothing another process publishes
	// between the node's making and Follow's start is missed; room for followBuffer events.
	follow   <-chan messaging.Event
	unfollow func()
	// conns caps the connections the listener holds open (SPEC §5.7).
	conns *public.ConnCap

	lnMu sync.Mutex
	ln   net.Listener
	http *http.Server

	// live knobs the portal changes while the node serves. They are read on
	// every use rather than captured, so a saved change takes effect without a
	// restart (SPEC §8.2).
	liveMu    sync.RWMutex
	publicURL string
	lanAllow  bool

	// campaigns holds the identities whose move campaign is walking right now (campaign.go).
	campaigns sync.Map // account id → struct{}
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

// New assembles the node. It loads every account's key eagerly, so a key that will not open is
// found at startup and not on the first call.
//
// It returns an error when Store, Landing or Limits is missing, when listing accounts fails, and
// when no account's key opened under the master key while at least one account could not be built
// (the likely wrong master key; the message says what to do). An account that merely awaits a leaf
// (ErrAwaitingLeaf) is skipped and audited as `account_awaiting_leaf`; one that cannot be built is
// kept in Unavailable and audited as `account_unavailable`, and the others serve. New first retires
// the keys of leaves past their notAfter (RetireExpiredLeaves).
func New(ctx context.Context, o Options) (*Node, error) {
	if o.Store == nil {
		return nil, fmt.Errorf("node: no store")
	}
	if o.Landing == nil {
		return nil, fmt.Errorf("node: no invite landing page")
	}
	if o.Limits == nil {
		return nil, fmt.Errorf("node: no limits sidecar client")
	}
	if o.Bus == nil {
		o.Bus = messaging.NewBus(o.Store)
	}
	n := &Node{
		opts: o, cfg: o.Config,
		idm:         &identity.Manager{Store: o.Store, Keyring: o.Keyring},
		accounts:    map[string]*account{},
		bySlug:      map[string]*account{},
		byHost:      map[string]*account{},
		awaiting:    map[string]struct{}{},
		unavailable: map[string]string{},
	}
	n.publicURL, n.lanAllow = o.Config.PublicURL, o.Config.LANConnections
	n.follow, n.unfollow = o.Bus.SubscribeSized("", followBuffer)
	// Before anything is built: a leaf that ran out while the node was down loses its key now, and
	// its account then boots as what it is — awaiting a leaf — rather than as a broken one.
	n.RetireExpiredLeaves(ctx)
	recs, err := o.Store.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("node: list accounts: %w", err)
	}
	var unavailable []string
	// Whether any account's key opened under this master key — a served account's, or one that
	// has a key and is only waiting for its leaf. See the refusal below.
	keyProven := false
	for _, rec := range recs {
		a, err := n.buildAccount(ctx, rec)
		if errors.Is(err, ErrAwaitingLeaf) {
			if !errors.Is(err, errAwaitingKeyless) {
				keyProven = true
			}
			o.audit("account_awaiting_leaf", "account:"+rec.ID+" slug:"+rec.Slug, "skipped")
			n.awaiting[rec.Slug] = struct{}{}
			continue
		}
		if err != nil {
			// One account that cannot be built is one account that does not serve:
			// refusing to start took every OTHER account down with it. Kept, so a
			// broken account is visible and the rest of the node answers.
			o.audit("account_unavailable", "account:"+rec.ID+" slug:"+rec.Slug+" why:"+core.Redact(err.Error()), "error")
			unavailable = append(unavailable, fmt.Sprintf("%s: %v", rec.Slug, err))
			n.unavailable[rec.Slug] = err.Error()
			continue
		}
		keyProven = true
		n.accounts[rec.ID] = a
		n.bySlug[rec.Slug] = a
		n.indexHost(a)
	}
	// Every account failing is not one broken account: it is the node misconfigured
	// — the wrong keyring, an unreadable store — and it fails at New rather than at
	// call time, where the operator would meet it one request at a time.
	//
	// It stays a refusal, and it says the two things it can mean. The likelier one is the wrong
	// master key, and a node that started anyway would seal new settings and credentials under it
	// and leave the store sealed under two. The other is a master key that is gone for good, and
	// under HDTP that is recoverable — the identities are roots in wallets, not keys in this store —
	// by treating this node's own data as another host's (docs/operations.md, Recovery).
	//
	// "Every account failing" is judged by the master key, not by how many accounts are served.
	// The test used to be `len(n.accounts) == 0`, which counted an account that is merely awaiting
	// its leaf as a failure: a node holding one such account and one broken one refused to start,
	// and so took away the admin socket the waiting account needed to ask for its certificate. An
	// awaiting account whose key OPENED is the opposite of a failure — it is proof the master key
	// is the right one, and whatever else is broken is broken for a reason of its own, and named
	// on the banner. One with no key at all proves nothing either way.
	if !keyProven && len(unavailable) > 0 {
		return nil, fmt.Errorf("node: no account could be served: %s\n"+
			"if this is the wrong master key, supply the right one (HDTP_MASTER_KEY or keyring.key) and nothing is lost.\n"+
			"if the master key is gone for good, the identities are not — they are roots in wallets. Offline: "+
			"`hdtp-gateway export -slug <slug> -out <file>` for each, then `hdtp-gateway import <file> -slug <slug> -yes` into a fresh data directory; "+
			"the identities arrive with their contacts and chats, awaiting a leaf, and `serve` names the command for each",
			strings.Join(unavailable, "; "))
	}

	n.srv = &public.Server{
		Now:            n.now,
		GetCertificate: n.certificate,
		Accounts:       n.Slugs,
		MCP:            n.mcpHandler(),
		Invite:         n.inviteHandler(),
		// the probe answers for whatever the node currently advertises
		Probe: probeHandler(n.PublicURL),
		SourceIP: func(r *http.Request) string {
			return tunnel.SourceIP(o.Adapter, o.Config.Mode == core.ModeEdge, r)
		},
		// A pinned terminating ingress presents ITS certificate on the onward
		// leg. It is checked at the handshake and must go no further: caller
		// identity in terminate mode comes from the sealed envelope (§10.1).
		IgnoreClientCert: func() bool { return o.IngressFingerprint != "" },
		// The proxy in front (deploy/envoy, SPEC §5.1), whose forwarded chain and address are read
		// from its connections and no other's.
		ProxyAddress: o.Config.ProxyAddress,
	}

	// Order matters, outermost first: cap the body before anything parses it,
	// refuse LAN sources before any handler runs, count the call against its
	// caller's budget, then the routes.
	h := n.srv.Handler()
	h = public.LANGuard{
		Adapter: o.Adapter, AllowFn: n.LANAllowed,
		TrustedHeader: tunnel.TrustedClientIPHeader(o.Adapter),
		Audit:         o.audit,
	}.Middleware(h)
	h = public.CapBody(h, MaxBodyBytes)
	n.handler = h
	n.conns = &public.ConnCap{Max: public.DefaultMaxConns, Audit: o.audit, Now: o.Now}
	return n, nil
}

// LimitsAnswer asks the limits sidecar the one question that spends nothing (its rules) and
// reports whether it answered, and if not why: what /healthz, `doctor` and the serve banner say,
// since while it does not answer every sealed call is refused `unavailable`.
func (n *Node) LimitsAnswer(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := n.opts.Limits.Probe(ctx); err != nil {
		return fmt.Errorf("the limits sidecar at %s is not answering, so every sealed call is refused unavailable: %w", n.opts.Limits.Path, err)
	}
	return nil
}

// quotaFor is the account's configured media quota, or 0 for the default.
func (n *Node) quotaFor(accountID string) int64 {
	if n.opts.Quota == nil {
		return 0
	}
	return n.opts.Quota(accountID)
}

// ContactCap is the number of contacts each account may hold (limit.contacts): what every contact
// manager enforces and what sizes every account's call budget.
func (n *Node) ContactCap() int { return n.contactCap() }

// contactCap is the number of contacts each account may hold (limit.contacts).
func (n *Node) contactCap() int {
	if n.opts.ContactCap != nil {
		if c := n.opts.ContactCap(); c > 0 {
			return c
		}
	}
	return core.DefaultLimitContacts
}

// consumeBudget charges one call to an HDTP §12 budget of accountID — the caller's own, or the guest
// or source budget `as` names (public.Pool.Limit) — by asking the limits sidecar, which holds the
// numbers and the counters (internal/limits). nil when the call may proceed. A sidecar that does
// not answer refuses the call `unavailable`: a budget nobody can enforce is not one the node guesses
// at (docs/release/two-layer-limits-2026-09-28.md §6).
func (n *Node) consumeBudget(ctx context.Context, accountID string, as public.Charge) *public.Refusal {
	charges, known := n.chargeOf(ctx, accountID, as)
	return n.decide(ctx, accountID, charges, known)
}

// admit is the check BEFORE the open (the owner's decision of 2026-09-29 on the guest total): a
// sealed call to accountID goes on to the open while the account's guest total holds a call, or
// from a source that carried an active or pending contact's call in the last hour, which the
// sidecar remembers (`known` on a decision). Everything else is refused `rate_limited` with the
// total's wait, before a key is read; nothing is spent. A sidecar that does not answer refuses it
// `unavailable`, as every decision it would make.
func (n *Node) admit(ctx context.Context, accountID string) *public.Refusal {
	d, err := n.opts.Limits.Admit(ctx, accountID, public.FactsFrom(ctx).RemoteIP, n.now())
	return n.refusalOf(accountID, "admit", d, err)
}

// decide asks the sidecar for one call of accountID's budgets, charged to every one of charges or to
// none, remembering known (the source of a call the open proved a contact's) when it is set, and
// audits a refusal: `rate_limited` names the bucket that refused, `limits_unavailable` the sidecar
// that did not answer.
func (n *Node) decide(ctx context.Context, accountID string, charges []limits.Charge, known string) *public.Refusal {
	d, err := n.opts.Limits.Decide(ctx, accountID, charges, known, n.now())
	kinds := make([]string, 0, len(charges))
	for _, c := range charges {
		kinds = append(kinds, c.Kind())
	}
	return n.refusalOf(accountID, strings.Join(kinds, ","), d, err)
}

// refusalOf is a sidecar's answer as the node answers it, audited: nil when the call may go on.
func (n *Node) refusalOf(accountID, asked string, d limits.Decision, err error) *public.Refusal {
	if err != nil {
		n.opts.audit("limits_unavailable", "account:"+accountID+" charge:"+asked, "refused")
		return &public.Refusal{Unavailable: true}
	}
	if d.Allowed {
		return nil
	}
	n.opts.audit("rate_limited", "account:"+accountID+" bucket:"+d.RefusedBy, "refused")
	if !d.Countable {
		// A count no wait refills (the pending cap): no number of seconds is true of it.
		return &public.Refusal{Unavailable: true}
	}
	return &public.Refusal{RetryAfter: d.RetryAfter}
}

// chargeOf decides which of accountID's budgets a call counts against (HDTP §12), and the source
// to remember as known when the open proved the caller a contact. Every budget is the account's the
// call is ADDRESSED to: being a contact of another account on this node earns nothing here, and a
// contact's calls to one account never spend another's.
//
// WHO is calling: the envelope's proven sender when the call was sealed, the client certificate
// when it was not. Reading only the certificate made this unusable in edge mode, which forces
// client_cert off (§10.1): every contact was an anonymous guest keyed on the edge's address.
//
//   - an active contact of accountID whose proof the envelope did not demote: its own bucket and
//     the account's aggregate;
//   - any other proven root (a stranger, the pending tier, a blocked or superseded root, a pinned
//     root at an address not approved — ChargeGuest): the guest budget of that root at its source;
//   - nothing proven (ChargeSource, or no identity at all): the source address alone;
//   - an opened call answered with a refusal that spends nothing else (ChargeOpened): nothing but
//     the guest total.
//
// And the guest total (the owner's decision of 2026-09-29): every call that was OPENED — it
// carries envelope facts, or it is ChargeSource or ChargeOpened, which only an opened call is
// charged as — and did not prove an active or pending_out contact spends one call of the account's
// guest total, all or none with the rest. A proven contact never spends it, and its source is
// remembered (known). A plaintext call opens nothing and never spends it.
//
// The source comes from the adapter's trusted header behind a terminating edge, the proxy's
// (proxy_address) behind Envoy, and the socket otherwise — never a generic forwarded-for header.
func (n *Node) chargeOf(ctx context.Context, accountID string, as public.Charge) ([]limits.Charge, string) {
	ip := public.FactsFrom(ctx).RemoteIP
	source := limits.GuestIn("", ip, ip != "")
	switch as {
	case public.ChargeSource:
		return []limits.Charge{source, limits.GuestTotal()}, ""
	case public.ChargeOpened:
		return []limits.Charge{limits.GuestTotal()}, ""
	}
	caller := public.FactsFrom(ctx).ClientCertFingerprint
	e := public.EnvelopeFactsFrom(ctx)
	if e != nil && e.From != "" {
		// The envelope's sender is PROVEN: its signature verified before any dispatch.
		caller = e.From
	}
	if caller == "" {
		if e != nil {
			return []limits.Charge{source, limits.GuestTotal()}, ""
		}
		return []limits.Charge{source}, ""
	}
	status := ""
	if c, err := n.opts.Store.GetContact(ctx, accountID, caller); err == nil {
		status = c.Status
	}
	proven := e != nil && e.From != "" && !e.Demote && !e.Guest && (status == "active" || status == "pending_out")
	known := ""
	if proven {
		known = ip
	}
	guest := limits.GuestIn(caller, ip, ip != "")
	switch {
	case as != public.ChargeGuest && !(e != nil && (e.Demote || e.Guest)) && status == "active":
		return []limits.Charge{limits.ContactIn(caller, n.contactCap())}, known
	case proven || e == nil:
		return []limits.Charge{guest}, known
	default:
		return []limits.Charge{guest, limits.GuestTotal()}, known
	}
}

// probeHandler defers the public URL to call time; the owner can change it while
// the node serves, and a probe answering for the startup value would report on a
// URL nobody is using any more.
func probeHandler(publicURL func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tunnel.ProbeHandler(publicURL()).ServeHTTP(w, r)
	})
}

// ErrAwaitingLeaf marks an account that cannot serve yet: it holds no key (a
// data-only import), or it holds one and no leaf has been issued over it. Both
// wait on the same thing — the wallet (HDTP §9). Exported because `account
// create` has to tell "cannot serve yet" apart from "could not be created".
var ErrAwaitingLeaf = errors.New("node: account awaits a leaf from its wallet")

// errAwaitingKeyless is ErrAwaitingLeaf for an account that holds no key at all. Every caller
// treats the two alike except New, which needs to know whether an awaiting account's key OPENED:
// one that did is proof this master key is the store's, and one with no key proves nothing.
var errAwaitingKeyless = fmt.Errorf("%w (it holds no key here)", ErrAwaitingLeaf)

// buildAccount loads one account's key and composes its serving state.
func (n *Node) buildAccount(ctx context.Context, rec store.Account) (*account, error) {
	return n.buildAccountSealed(ctx, rec, n.sealPolicy())
}

// sealPolicy is the seal the owner set for the node, as it is now.
func (n *Node) sealPolicy() core.Seal {
	if n.opts.SealPolicy != nil {
		return n.opts.SealPolicy()
	}
	return n.cfg.Seal
}

// buildAccountSealed is buildAccount with the seal policy to serve under: the owner's (boot,
// adoption) or the account row's (a reload after another process changed it, which wrote the
// row before it said so).
func (n *Node) buildAccountSealed(ctx context.Context, rec store.Account, seal core.Seal) (*account, error) {
	sealed, err := n.opts.Store.GetAccountSealedKey(ctx, rec.ID)
	if err != nil {
		return nil, fmt.Errorf("node: account %s has no key: %w", rec.Slug, err)
	}
	if len(sealed) == 0 {
		// A data-only import (HDTP §9): the account is here, its key is not,
		// and it serves nothing until the wallet issues a leaf to this host.
		return nil, errAwaitingKeyless
	}
	kp, err := n.idm.LoadKeypair(sealed)
	if err != nil {
		return nil, fmt.Errorf("node: account %s: %w", rec.Slug, err)
	}
	if kp.Fingerprint != rec.Fingerprint {
		return nil, fmt.Errorf("node: account %s: stored key does not match its pinned fingerprint", rec.Slug)
	}
	// An account (HDTP §2) serves under the leaf the person's root issued: the
	// leaf's key is the key above, and the chain — leaf then root — is what TLS
	// presents. There is no other shape.
	var cert tls.Certificate
	if rec.HasRoot() {
		keys, err := n.idm.ActiveLeafKeypairs(ctx, rec.ID, n.now())
		if err != nil {
			return nil, fmt.Errorf("node: account %s leaves: %w", rec.Slug, err)
		}
		if len(keys) == 0 || !keys[0].Current {
			return nil, fmt.Errorf("node: account %s names a root and a key, and its ledger holds no current leaf over that key", rec.Slug)
		}
		if keys[0].Kid != rec.Fingerprint {
			// The ledger moved and the account row did not: an install that failed
			// between the two (five writes, no transaction). The ledger is the
			// truth — it is what validated — so the row is repaired here rather
			// than refusing to boot, which is what refusing did to every OTHER
			// account on the node as well.
			if err := n.idm.AdoptCurrentLeafKey(ctx, rec.ID, keys[0]); err != nil {
				return nil, fmt.Errorf("node: account %s: repair its key to the current leaf: %w", rec.Slug, err)
			}
			n.opts.audit("account_leaf_repaired", "account:"+rec.ID+" kid:"+keys[0].Kid, "ok")
			rec.Fingerprint = keys[0].Kid
		}
		kp = keys[0].KP
		// Through `tlsCertOf`, not inline: what a key presents on the wire is one
		// rule (leaf then root, or nothing at all) and it had two spellings, of
		// which only the guarded one carried the §2 reasoning — and only a test
		// called it. A key here with a leaf but no root would have gone out as a
		// malformed chain; it now goes out as no credential.
		cert = tlsCertOf(kp)
	} else {
		// No leaf, so no chain to present and no card to serve: this account has not
		// been to a wallet yet. It cannot serve, and the remedy is `account csr`, the
		// wallet, `account install-leaf`. Skipped and audited rather than fatal, so
		// one account waiting on its wallet does not take the node down.
		return nil, ErrAwaitingLeaf
	}
	a := &account{
		rec: rec, kp: kp,
		cert: cert,
		cm: &contacts.Manager{
			Store: n.opts.Store, ContactCap: n.contactCap,
			// The pending-request cap, decided by the sidecar; `decide` audits which refused it (the
			// cap, or a sidecar that did not answer), and the peer hears `unavailable` either way.
			AdmitRequest: func(ctx context.Context, accountID string, held int64) error {
				if n.decide(ctx, accountID, []limits.Charge{limits.PendingIn(held)}, "") != nil {
					return contacts.ErrRequestsFull
				}
				return nil
			},
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
		blobs = n.cfg.Blobs()
	}
	reg := &public.Registry{}
	a.reg = reg
	a.pool = public.NewPool(reg, public.StoreResolver(n.opts.Store), 256)
	a.pool.CallAudit = func(kind, action, resource, outcome string) {
		n.opts.auditAs(kind, action, "account:"+rec.ID+" "+resource, outcome)
	}

	// The account row is the card's source; the node policy is the truth. Mirror
	// it now so a card can never advertise a policy the gate does not enforce.
	eff := core.EffectiveSeal(n.cfg.Mode, seal)
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
		Cert:      n.cfg.ClientCert,
		SealFn:    func() core.Seal { return a.sealValue() },
		Now:       n.opts.Now,
		Audit:     n.opts.audit,
		// HDTP 1.0: what a `v: 1` envelope is decided against, read per call
		// so the owner's settings and a renewal take effect without a restart.
		RecipientState: func(ctx context.Context) (*public.RecipientState, error) {
			return n.recipientState(ctx, rec.ID, rec.Slug)
		},
		OnEvent: func(event, root, endpoint string) {
			if n.opts.Bus != nil {
				n.opts.Bus.Publish(messaging.Event{Kind: messaging.EventCall, AccountID: rec.ID, ContactFpr: root})
			}
		},
		OnPending: func(root, endpoint, why string) {
			// A contact at a new address awaiting the owner appears beside
			// contact requests (HDTP §5.3), so it wakes the same feed.
			if n.opts.Bus != nil {
				n.opts.Bus.Publish(messaging.Event{Kind: messaging.EventRequest, AccountID: rec.ID, ContactFpr: root})
			}
		},
	}
	a.pool.Gate = ident.PoolGate()
	a.pool.Limit = func(ctx context.Context, as public.Charge) *public.Refusal {
		return n.consumeBudget(ctx, rec.ID, as)
	}
	a.pool.PreOpen = func(ctx context.Context) *public.Refusal { return n.admit(ctx, rec.ID) }
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
		Card: func(ctx context.Context) (string, string, error) {
			card, err := n.Card(ctx, rec.ID)
			if err != nil {
				return "", "", err
			}
			// The SAME signature the invite landing page serves: a card that is
			// signed over one transport and bare over another is a card a
			// redeemer cannot rely on (HDTP §4).
			sig, err := n.idm.SignCard(ctx, rec.ID, card)
			return card, sig, err
		},
		// Through the node, so a redemption or an approval on this process drops the caller's
		// surface on every process (Invalidate).
		Invalidate: n.Invalidate,
		Endpoint:   func() string { return identity.EndpointFor(n.PublicURL(), rec.Slug) },
		Chain:      func(ctx context.Context) ([][]byte, error) { return n.idm.Chain(ctx, rec.ID) },
		// Read per call, like Quota: the contact cap is an owner knob and sizes the
		// account's budget (§12), and a card must advertise what the gate enforces.
		Limits: func(ctx context.Context) (public.Limits, error) {
			calls, err := n.opts.Limits.Advertise(ctx, n.contactCap())
			return public.LimitsWith(calls), err
		},
		AuditAs: func(kind, action, resource, outcome string) {
			n.opts.auditAs(kind, action, "account:"+rec.ID+" "+resource, outcome)
			// A contact ACTED — wake the owner's change feed (§7.7). Messages
			// wake it through the messaging service; the calendar and media
			// tools would otherwise be invisible until the next poll.
			if n.opts.Bus != nil && wakesFeed(action, outcome) {
				n.opts.Bus.Publish(messaging.Event{Kind: messaging.EventCall, AccountID: rec.ID,
					ContactFpr: callerOf(resource), Ref: action})
			}
		},
	})...)

	// sealed_call at every tier, wrapping the same pool (SPEC §4.5). A NAMED
	// group, not a builtin: at seal `none` the tool must be absent from
	// tools/list (HDTP §13.4 — the card says senders must not seal, and the
	// list has to tell the same truth), so SetSeal replaces or deletes the
	// group the way integration tools come and go.
	a.sealedEntries = public.SealedEntries(public.SealedDeps{
		Pool: a.pool, Identifier: ident, AccountID: rec.ID,
		Idem:    n.opts.Store,
		Now:     n.opts.Now,
		AuditAs: n.opts.auditAs,
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

// AwaitingLeaf names the accounts this node holds and cannot serve: each has no
// certificate, so it has nothing to present. The list is what the operator of a
// just-restored identity needs — every account is there and none of them answer,
// and the reason is one command away rather than invisible.
func (n *Node) AwaitingLeaf() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]string, 0, len(n.awaiting))
	for slug := range n.awaiting {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}

// Unavailable lists, by slug, the accounts this node holds and could not build, with the reason.
func (n *Node) Unavailable() map[string]string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make(map[string]string, len(n.unavailable))
	for slug, why := range n.unavailable {
		out[slug] = why
	}
	return out
}

// Card renders an account's current vCard (SPEC §9.3).
func (n *Node) Card(ctx context.Context, accountID string) (string, error) {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil {
		// Not an identity this node serves. One awaiting its wallet (no root yet) is skipped until it has a
		// leaf, so it has no card, and the portal says so; one the node could not open is a failure.
		rec, err := n.opts.Store.GetAccountByID(ctx, accountID)
		if err == nil && !rec.HasRoot() {
			return "", fmt.Errorf("node: %s awaits its wallet: %w", accountID, identity.ErrNoCertificate)
		}
		return "", fmt.Errorf("node: account %s is not served", accountID)
	}
	rec, err := n.opts.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		rec = a.rec // a store blip must not stop us answering with what we know
	}
	// HDTP §3: the card carries the leaf and nothing the leaf already says. The seal
	// is the SAME value the gate enforces, never the raw row.
	chain, err := n.idm.Chain(ctx, accountID)
	if err != nil {
		return "", err
	}
	return contacts.BuildCard(rec.DisplayName, chain[0], string(a.sealValue()))
}

func (n *Node) now() time.Time {
	if n.opts.Now != nil {
		return n.opts.Now()
	}
	return time.Now()
}

// recipientState is what a `v: 1` envelope for an account is decided against (HDTP
// §13.3): the account's own endpoint and settings, its chain, the keys it holds
// today, the kids it once held, and the kids every OTHER account on this node
// holds — a key held for another identity must never answer at this one's path
// (§14.4).
func (n *Node) recipientState(ctx context.Context, accountID, slug string) (*public.RecipientState, error) {
	rec, err := n.opts.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	st := &public.RecipientState{
		HasRoot: rec.HasRoot(), Endpoint: identity.EndpointFor(n.PublicURL(), slug),
		AcceptNewHosts: rec.AcceptNewHosts,
	}
	if !rec.HasRoot() {
		return st, nil
	}
	if st.Chain, err = n.idm.Chain(ctx, accountID); err != nil {
		return nil, err
	}
	if st.Keys, err = n.idm.ActiveLeafKeypairsFor(ctx, rec, n.now()); err != nil {
		return nil, err
	}
	if st.Former, err = n.idm.FormerKids(ctx, accountID, n.now()); err != nil {
		return nil, err
	}
	// The sibling kids: what this node holds for its OTHER identities, so a kid
	// that belongs to one of them is `envelope_invalid` and never
	// `certificate_renewed` with our chain (HDTP §13.3, §14.4).
	//
	// This used to walk every other account and ask for its leaves, one query
	// each — an N+1 paid on EVERY inbound envelope, so the cost of a message grew
	// with the number of identities the node hosts. Measured at 134µs for one
	// account and 262µs for eight, which is about 18µs per extra identity, per
	// message. It is two queries now, whatever the node holds.
	others, err := n.opts.Store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		if o.ID != accountID && o.Fingerprint != "" {
			st.SiblingKids = append(st.SiblingKids, o.Fingerprint)
		}
	}
	kids, err := n.opts.Store.ListKidsExcept(ctx, accountID)
	if err != nil {
		return nil, err
	}
	st.SiblingKids = append(st.SiblingKids, kids...)
	return st, nil
}

// PublicURL is the externally reachable base the card advertises.
func (n *Node) PublicURL() string {
	n.liveMu.RLock()
	defer n.liveMu.RUnlock()
	return n.publicURL
}

// SetPublicURL changes the base this node derives an account's address from, which is the
// address the NEXT certificate request will name. It moves nobody: every leaf still names the
// endpoint it was issued for, and an account changes address when its wallet issues a leaf for
// the new one (`account csr -purpose move`). The caller names the accounts that now need that.
func (n *Node) SetPublicURL(url string) {
	n.UsePublicURL(url)
	n.opts.auditAs("owner", "settings_public_url", "url:"+url, "ok")
}

// UsePublicURL is SetPublicURL without its audit row: another node process on the store saved the
// change, and audited it there.
func (n *Node) UsePublicURL(url string) {
	n.liveMu.Lock()
	n.publicURL = url
	n.liveMu.Unlock()
}

// LANAllowed reports whether connections from private-range sources are served.
func (n *Node) LANAllowed() bool {
	n.liveMu.RLock()
	defer n.liveMu.RUnlock()
	return n.lanAllow
}

// SetLANConnections flips the LAN flag for the next connection.
func (n *Node) SetLANConnections(allow bool) {
	n.UseLANConnections(allow)
	n.opts.auditAs("owner", "settings_lan", "", boolWord(allow))
}

// UseLANConnections is SetLANConnections without its audit row: another node process on the store
// saved the change, and audited it there.
func (n *Node) UseLANConnections(allow bool) {
	n.liveMu.Lock()
	n.lanAllow = allow
	n.liveMu.Unlock()
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
	// leaves tools/list (HDTP §13.4), otherwise it is (re)installed — and the
	// cached per-caller servers are dropped so the next request lists the
	// change, the same mechanics integration tools use.
	if a.reg != nil {
		if eff == core.SealNone {
			a.reg.Replace(sealedGroup, nil)
		} else {
			a.reg.Replace(sealedGroup, a.sealedEntries)
		}
		n.InvalidateAccount(ctx, accountID)
	}
	n.accountChanged(accountID, a.rec.Slug)
	n.opts.auditAs("owner", "settings_seal", "account:"+accountID, string(a.sealValue()))
	return nil
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

// ServedPermissions is every contact-tier permission this account's public
// surface currently gates a tool with: the core five, plus one per live
// integration exposure (SPEC §6.1, §6.5). The portal's switchboard is built from it,
// so what the node can serve is exactly what the owner can grant.
func (n *Node) ServedPermissions(accountID string) []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if a := n.accounts[accountID]; a != nil && a.reg != nil {
		return a.reg.GatedPermissions()
	}
	return nil
}

// Invalidate drops one caller's composed surface (SPEC §5.5) in this process and, through the
// change log, in every other process on the store: the caller's next request, wherever it lands,
// is composed from what the store now says.
func (n *Node) Invalidate(ctx context.Context, accountID, fpr string) error {
	n.invalidateLocal(ctx, accountID, fpr)
	n.publish(messaging.Event{Kind: messaging.EventInvalidate, AccountID: accountID, ContactFpr: fpr})
	return nil
}

func (n *Node) invalidateLocal(ctx context.Context, accountID, fpr string) {
	if p := n.Pool(accountID); p != nil {
		_ = p.Invalidate(ctx, accountID, fpr)
	}
}

// publish is n.opts.Bus.Publish, for a node built without a bus.
func (n *Node) publish(e messaging.Event) {
	if n.opts.Bus != nil {
		n.opts.Bus.Publish(e)
	}
}

// accountChanged tells every other process on the store to reload an account from it.
func (n *Node) accountChanged(accountID, slug string) {
	n.publish(messaging.Event{Kind: messaging.EventAccount, AccountID: accountID, Ref: slug})
}

// Follow applies what other node processes on the store change to this one's live state, until
// ctx ends (SPEC §11.1): a caller's surface invalidated there is dropped here; an account adopted,
// re-leafed, retired, re-sealed or gone there is reloaded here from the store. It passes over what
// this process published itself, which it has already applied. serve runs it in its joined
// background group.
func (n *Node) Follow(ctx context.Context) {
	if n.follow == nil {
		return
	}
	evs := n.follow
	defer n.unfollow()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-evs:
			if e.Local {
				continue
			}
			switch e.Kind {
			case messaging.EventInvalidate:
				if e.Ref == invalidateAccount {
					n.invalidateAccountLocal(ctx, e.AccountID)
				} else {
					n.invalidateLocal(ctx, e.AccountID, e.ContactFpr)
				}
			case messaging.EventAccount:
				n.reloadAccount(ctx, e.AccountID, e.Ref)
			}
		}
	}
}

// followBuffer is how many events Follow may fall behind by before one is dropped: every event
// of every account on the store passes it, and one it drops is a surface or an account this
// process goes on serving as it was.
const followBuffer = 4096

// invalidateAccount is the Ref of an EventInvalidate that drops every caller of an account.
const invalidateAccount = "account"

// reloadAccount brings this process's view of one account to what the store holds, after another
// process changed it: gone, awaiting a leaf, broken, or served as built from its row now. Its seal
// is the row's, which the process that changed it wrote (SetSeal), not this process's default.
func (n *Node) reloadAccount(ctx context.Context, accountID, slug string) {
	rec, err := n.opts.Store.GetAccountByID(ctx, accountID)
	if errors.Is(err, store.ErrNotFound) {
		n.forgetLocal(accountID, slug)
		return
	}
	if err != nil {
		return // the next change, or a restart, reloads it
	}
	a, err := n.buildAccountSealed(ctx, rec, core.Seal(rec.Seal))
	switch {
	case errors.Is(err, ErrAwaitingLeaf):
		n.stopServingLocal(rec)
	case err != nil:
		n.mu.Lock()
		n.unavailable[rec.Slug] = err.Error()
		n.mu.Unlock()
	default:
		n.serveAccount(a)
	}
}

// SignCard signs an account's card with its identity key (SPEC §9.3).
func (n *Node) SignCard(ctx context.Context, accountID, cardText string) (string, error) {
	return n.idm.SignCard(ctx, accountID, cardText)
}

// CertificateInfo is the account's certificate state — root, chain, dates,
// whether a renewal is due (§14). The portal and the owner MCP read the same
// function, so neither can drift from what the node actually serves.
func (n *Node) CertificateInfo(ctx context.Context, accountID string) (identity.CertificateInfo, error) {
	return n.idm.Certificate(ctx, accountID, n.now())
}

// Certificate returns an account's identity certificate — what an outbound leg
// presents so the far side recognizes the key it pinned. Ingress pairing needs
// it (SPEC §10.6). It is the chain, leaf then root, or no certificate at all for a key
// with no leaf; it errors for an account this node does not serve.
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
	// "trust nothing", which silently kills the WebPKI branch of HDTP §2 — so
	// this node could reach pinned self-signed peers and nothing behind an edge.
	return n.wireClient(accountID, &outbound.Client{Keypair: a.kp, Cert: a.cert}), nil
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

// Handler is the fully wrapped public HTTP surface: the body cap outermost, then the LAN guard,
// then the routes and the facts middleware (New). It does not include the TLS or the connection cap,
// which Start adds.
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
		ingress.PinOnwardLeg(tc, fpr, func(presented string) {
			n.opts.audit("ingress_leg", "presented:"+presented, "not_the_paired_ingress")
		})
	}
	return tc
}

/* ------------------------------ certificates ---------------------------- */

// certificate is the SNI callback. A hostname that matches an account's slug
// gets that account's identity certificate; anything else — including a caller
// that dialed by IP and sent no SNI — gets the first account's, which is the
// only sensible answer on a single-identity node and harmless on a multi-account
// one, where the caller pins by fingerprint anyway (HDTP §2).
// RetireExpiredLeaves destroys the key of every leaf past its notAfter, on every account, and stops
// serving any account whose CURRENT leaf was one of them. It is what makes "until one date" true
// of the key and not only of the certificate: an expired leaf is refused by every verifier, so
// past its date the key is a thing this host was never meant to still be holding.
//
// Three callers, all of them places the node already writes: New (so an account whose leaf ran
// out while the node was down boots as awaiting a leaf, not as broken), the hourly retention
// sweep (so a leaf that runs out while the node is up is noticed within the hour), and
// AdoptAccount. Never the read path.
func (n *Node) RetireExpiredLeaves(ctx context.Context) {
	recs, err := n.opts.Store.ListAccounts(ctx)
	if err != nil {
		if ctx.Err() != nil {
			// The node is stopping and this pass was told to end. Nothing failed, and New runs the
			// pass first thing at the next start — so the chain is not told that it could not run.
			return
		}
		// The pass could not start, which is a fact about the node and about no one account.
		n.opts.audit("leaf_retirement_pass", "store:accounts", "error")
		return
	}
	for _, rec := range recs {
		if ctx.Err() != nil {
			return
		}
		n.retireExpired(ctx, rec)
	}
}

func (n *Node) retireExpired(ctx context.Context, rec store.Account) {
	if !rec.HasRoot() {
		return
	}
	retired, err := n.idm.RetireExpiredLeafKeys(ctx, rec.ID, n.now())
	for _, r := range retired {
		// Key material was destroyed, so the chain says so, once per key.
		n.opts.audit("account_leaf_key_retired", "account:"+rec.ID+" slug:"+rec.Slug+" key:"+r.Kid+" reason:expired", "ok")
		if r.Current {
			n.stopServingLocal(rec)
			n.accountChanged(rec.ID, rec.Slug)
		}
	}
	if err != nil && ctx.Err() == nil {
		// (A pass ended by shutdown is not an error of this account's; the keys it did retire are
		// recorded above either way.)
		n.opts.audit("account_leaf_key_retired", "account:"+rec.ID+" slug:"+rec.Slug, "error")
	}
}

// stopServingLocal takes a live account out of every index the listener answers from and marks it as
// awaiting a leaf. The node had no way to do this: an account, once built, was served until the
// process ended, so a leaf that expired under a running node went on being presented — to peers
// who refuse it — and its key went on being held.
func (n *Node) stopServingLocal(rec store.Account) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.accounts, rec.ID)
	delete(n.bySlug, rec.Slug)
	for host, a := range n.byHost {
		if a.rec.ID == rec.ID {
			delete(n.byHost, host)
		}
	}
	n.awaiting[rec.Slug] = struct{}{}
}

// ForgetAccount takes an identity that has left this host out of the live node entirely: out of
// every index the listener answers from, and out of the lists of accounts awaiting a leaf or
// unavailable. Its address is then answered as an address this node never served (HDTP §9).
// stopServingLocal is the other way out and is not this one: it keeps the slug as awaiting a leaf,
// because that account is still here.
func (n *Node) ForgetAccount(accountID, slug string) {
	n.forgetLocal(accountID, slug)
	n.accountChanged(accountID, slug)
}

func (n *Node) forgetLocal(accountID, slug string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.accounts, accountID)
	delete(n.bySlug, slug)
	for host, a := range n.byHost {
		if a.rec.ID == accountID {
			delete(n.byHost, host)
		}
	}
	delete(n.awaiting, slug)
	delete(n.unavailable, slug)
}

// ErrCampaignWalking is WithoutCampaign's refusal: the identity's campaign is walking now.
var ErrCampaignWalking = errors.New("node: the identity's campaign is walking")

// WithoutCampaign runs fn with no campaign for the account walking, and none able to start until fn
// returns: it takes the account's one campaign slot (the one ResumeMove takes) for fn's duration, or
// refuses with ErrCampaignWalking when a walk holds it. A check followed by the work would leave a
// gap in which `account announce`, or an install, starts a walk over rows the work is erasing.
func (n *Node) WithoutCampaign(accountID string, fn func() error) error {
	if _, walking := n.campaigns.LoadOrStore(accountID, struct{}{}); walking {
		return ErrCampaignWalking
	}
	defer n.campaigns.Delete(accountID)
	return fn()
}

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
// also what makes it safe to call after a leaf install.
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
	// Adoption is a write already, so an expired leaf's key is destroyed here too — off the read
	// path every inbound request takes. (Boot and the hourly sweep are the other two places.)
	n.retireExpired(ctx, rec)
	// Every other process on the store reloads it too, whatever became of it here.
	defer n.accountChanged(rec.ID, rec.Slug)
	a, err := n.buildAccount(ctx, rec)
	if err != nil {
		if errors.Is(err, ErrAwaitingLeaf) {
			n.mu.Lock()
			n.awaiting[rec.Slug] = struct{}{}
			n.mu.Unlock()
		}
		return fmt.Errorf("node: adopt %s: %w", rec.Slug, err)
	}
	n.serveAccount(a)
	return nil
}

// serveAccount puts a built account into every index the listener answers from.
func (n *Node) serveAccount(a *account) {
	n.mu.Lock()
	defer n.mu.Unlock()
	// A rebuilt account replaces the one it was: its host may have changed with its leaf.
	for host, old := range n.byHost {
		if old.rec.ID == a.rec.ID {
			delete(n.byHost, host)
		}
	}
	n.accounts[a.rec.ID] = a
	n.bySlug[a.rec.Slug] = a
	n.indexHost(a)
	// It has a certificate now, so it is no longer waiting for one — nor broken, if it was.
	delete(n.awaiting, a.rec.Slug)
	delete(n.unavailable, a.rec.Slug)
}

// indexHost records the host an account's leaf names, for SNI selection.
// Callers hold n.mu.
func (n *Node) indexHost(a *account) {
	if !a.rec.HasRoot() || len(a.kp.Leaf) == 0 {
		return
	}
	if leaf, err := hdtpidentity.Parse(a.kp.Leaf); err == nil && len(leaf.URIs) == 1 {
		host := hostOfEndpoint(leaf.URIs[0])
		// Two accounts naming one host cannot both present their chain on it:
		// SNI carries the name and nothing else. The first keeps the host and the
		// clash is audited rather than overwritten in silence — a peer validating
		// to its own pinned root would refuse whichever chain arrived (docs:
		// direct TLS on a multi-account node wants a host per account, or an
		// edge that terminates).
		if other := n.byHost[host]; other != nil && other.rec.ID != a.rec.ID {
			n.opts.audit("account_host_clash", "account:"+a.rec.ID+" host:"+host+" kept:"+other.rec.Slug, "skipped")
			return
		}
		n.byHost[host] = a
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
			// A leaf names its endpoint (HDTP §14.1): the host it names
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
// the path names and the identity the transport earned, stateless (public.StatelessMCP): every
// request resolves its caller afresh, and no session outlives it (SPEC §5.5).
func (n *Node) mcpHandler() http.Handler {
	inner := public.StatelessMCP(func(r *http.Request) *mcp.Server {
		slug := r.PathValue("slug")
		n.mu.RLock()
		a := n.bySlug[slug]
		n.mu.RUnlock()
		if a == nil {
			return nil
		}
		f := public.FactsFrom(r.Context())
		caller := f.ClientCertFingerprint
		if tc, ok := public.TransportCallerFrom(r.Context()); ok {
			// A chain earns exactly what the pin checks allowed
			// (resolveTransport): the root, or an anonymous guest.
			caller = tc.Fingerprint
		}
		srv, err := a.pool.ServerFor(r.Context(), a.rec.ID, caller)
		if err != nil {
			n.opts.audit("tools_list", "account:"+a.rec.ID, "unavailable")
			return nil
		}
		return srv
	}, mcp.StreamableHTTPOptions{
		// The SDK auto-enables DNS-rebinding protection whenever the accepted
		// connection's LOCAL address is loopback and Host is not
		// (go-sdk v1.8.0 mcp/streamable.go:321). That is exactly what EVERY reverse tunnel
		// produces — the connector runs on this host and dials this bind — so it
		// refused every tunnelled MCP call, in direct mode as much as edge.
		//
		// Off here and only here. This surface is always TLS (see serve: the
		// listener is wrapped by tls.NewListener) and presents the node's own
		// certificate, so a rebinding page cannot complete a handshake for the
		// attacker's name and never reaches a Host check. The owner MCP is plain
		// HTTP on loopback and KEEPS the protection (§8.3, §8.4).
		DisableLocalhostProtection: true,
		// The body cap is CapBody's (New), and SPEC §5.7's number. Left at zero the SDK imposes its
		// own default (4 MiB), under the 8 MiB §5.7 sizes for 5 MiB of inline media, and a legitimate
		// send_media was refused by a limit no document named.
		MaxRequestBodyBytes: MaxBodyBytes,
	})
	return n.resolveTransport(inner)
}

// resolveTransport runs the pin checks of HDTP §14.3 and §5.3 on a client
// chain ONCE per request, before the per-caller server is composed, and puts the
// outcome in the context. Without it the
// transport path composed the contact's surface for any chain that validated
// — a former host's still-valid leaf, a stolen and since-renewed one, a leaf
// for an address the owner has not approved — checks the sealed path always
// made. The two paths now reach the same outcome from the same rules.
func (n *Node) resolveTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := public.FactsFrom(r.Context())
		if !f.ChainProven() {
			next.ServeHTTP(w, r)
			return
		}
		n.mu.RLock()
		a := n.bySlug[r.PathValue("slug")]
		n.mu.RUnlock()
		if a == nil || !a.rec.HasRoot() {
			next.ServeHTTP(w, r)
			return
		}
		tc := a.ident.ResolveTransport(r.Context(), f)
		next.ServeHTTP(w, r.WithContext(public.WithTransportCaller(r.Context(), tc)))
	})
}

// LandingDeps is what the node gives the invite landing page (SPEC §9.2): the store, a card signed
// for the account that issued the token, that account's chain, the base invite links are built
// from, and the clock.
type LandingDeps struct {
	// Store is read for the invite (looked up by the hash of the token in the URL) and for the issuing account.
	Store store.Store
	// SignCard returns the card and its signature for the account that issued the token.
	SignCard func(accountID string) (cardText string, sigB64 string, err error)
	// Chain returns that account's [leaf, root].
	Chain func(accountID string) ([][]byte, error)
	// PublicURL is the base invite links are built from, read when the page is served.
	PublicURL func() string
	// Now is the clock the invite's expiry is judged by; nil means time.Now.
	Now func() time.Time
}

// inviteHandler serves the landing page of SPEC §9.2 for whichever account
// issued the token.
func (n *Node) inviteHandler() http.Handler {
	return n.opts.Landing(LandingDeps{
		Store: n.opts.Store,
		SignCard: func(accountID string) (string, string, error) {
			card, err := n.Card(context.Background(), accountID)
			if err != nil {
				return "", "", err
			}
			sig, err := n.idm.SignCard(context.Background(), accountID, card)
			return card, sig, err
		},
		Chain:     func(accountID string) ([][]byte, error) { return n.idm.Chain(context.Background(), accountID) },
		PublicURL: n.PublicURL,
		Now:       n.opts.Now,
	})
}

// The public listener's bounds (SPEC §5.7): the headers in 10 s; the whole request in 60 s, which
// an 8 MiB body (MaxBodyBytes) needs a link of 140 KB/s to meet; the answer in 75 s, above the 30 s
// an agent-answered call is held (integrations.DefaultWaitBudget) with room for the call around it;
// an idle keep-alive connection kept 120 s; 64 KiB of headers. A proxy in front of the node holds
// requests to the same (deploy/envoy/envoy.yaml; internal/integrationtest/envoy_test.go).
const (
	PublicHeaderTimeout  = 10 * time.Second
	PublicRequestTimeout = 60 * time.Second
	PublicAnswerTimeout  = 75 * time.Second
	PublicIdleTimeout    = 120 * time.Second
	PublicMaxHeaderBytes = 64 << 10
)

// Start listens and serves. A nil listener means "listen on the configured bind";
// a tunnel adapter supplies its own. The listener is wrapped in the connection cap and then in TLS
// (TLSConfig), and served with the PublicHeaderTimeout, PublicRequestTimeout, PublicAnswerTimeout,
// PublicIdleTimeout and PublicMaxHeaderBytes bounds. It returns an error if the node is already
// started or the bind cannot be listened on; serving then runs in a goroutine.
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
	// The connection cap sits beneath TLS: a connection past it is closed before a handshake.
	tlsLn := tls.NewListener(n.conns.Listener(ln), n.TLSConfig())
	srv := &http.Server{
		Handler:           n.handler,
		ReadHeaderTimeout: PublicHeaderTimeout,
		ReadTimeout:       PublicRequestTimeout,
		WriteTimeout:      PublicAnswerTimeout,
		IdleTimeout:       PublicIdleTimeout,
		MaxHeaderBytes:    PublicMaxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	n.ln, n.http = tlsLn, srv
	// The goroutine holds its own references: Stop clears the fields, and
	// reading them from here would race with that.
	go func() { _ = srv.Serve(tlsLn) }()
	n.opts.audit("public_listener", "addr:"+tlsLn.Addr().String(), "started")
	return nil
}

// Addr is the listener's address as a string, or "" before Start and after Stop.
func (n *Node) Addr() string {
	n.lnMu.Lock()
	defer n.lnMu.Unlock()
	if n.ln == nil {
		return ""
	}
	return n.ln.Addr().String()
}

// Stop shuts the listener down gracefully (http.Server.Shutdown, bounded by ctx) and releases the
// port. It is a no-op returning nil when the node was never started or is already stopped.
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

// callerOf reads the caller a tool's audit resource names (`caller:<fpr>`, or `contact:<fpr>`
// where no caller field is written), for the call it records in the change log.
func callerOf(resource string) string {
	fpr := ""
	for _, f := range strings.Fields(resource) {
		if v, ok := strings.CutPrefix(f, "caller:"); ok && v != "" {
			fpr = v
		}
		if v, ok := strings.CutPrefix(f, "contact:"); ok && fpr == "" {
			fpr = v
		}
	}
	return fpr
}

// wakesFeed reports whether a public-surface audit row is a substantive
// contact action the change feed should wake for: one of messaging.FeedCalls,
// the list the owner MCP's feed reports from, and not a refusal.
func wakesFeed(action, outcome string) bool {
	return (outcome == "ok" || outcome == "delivered") && messaging.FeedCalls[action]
}
