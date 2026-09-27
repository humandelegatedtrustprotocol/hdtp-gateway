package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/internalui"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
	"github.com/tech-sumit/pact-gateway/internal/node"
	"github.com/tech-sumit/pact-gateway/internal/services/auditsink"
	"github.com/tech-sumit/pact-gateway/internal/services/integrationchain"
	"github.com/tech-sumit/pact-gateway/internal/services/presence"
	"github.com/tech-sumit/pact-gateway/internal/services/retention"
	"github.com/tech-sumit/pact-gateway/internal/services/settings"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
)

func serve(args []string, stdout, stderr io.Writer) int {
	// SIGINT/SIGTERM end the serving context; every surface shuts down from it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveWith(ctx, args, stdout, stderr)
}

// serveRun is what serve's stages share. The admin handlers are registered while nd and auditFn
// are still nil and run only after both are set, so every handler reads them through this pointer
// when it RUNS, never as a copy taken when it was registered.
type serveRun struct {
	ctx            context.Context
	cfg            *core.Config
	stdout, stderr io.Writer

	setup *internalui.SetupTokens
	st    store.Store
	kr    *core.Keyring
	admin *core.AdminServer
	idm   *identity.Manager
	// The serving node. Nil while the admin handlers are being REGISTERED and non-nil by the time
	// any of them runs, which is why each checks.
	nd *node.Node
	// The audit sink. Wired once the store and the listener exist; the handlers run only after
	// that, which is why they may reach it.
	auditFn func(action, resource, outcome string)
	ownerFn func(action, resource, outcome string)
	auditAs func(kind, action, resource, outcome string)

	authSvc *auth.Service
	tokSvc  *auth.TokenService

	settings    *settings.Service
	stored      map[string]string
	adapterName string
	info        tunnel.Info

	connector *integrations.Connector
	chain     *integrationchain.Chain
	binder    *capabilityBinder
	agent     *integrations.AgentAnswered
	presence  *presence.Tracker
	// surfaceChanged is filled in after node.New; the chain's hook reads it when it fires.
	surfaceChanged func(integrationID string)
}

// serveWith is serve with the lifetime injected, so a test can end it without
// signalling the whole process.
//
// It holds every deferred teardown itself, in the order the stages acquire what they undo, so the
// teardown runs in the reverse order: the background loops, the integrations, the node, the
// tunnel, the admin socket, the store, the lock. A stage that fails returns before the teardown of
// what it did not start is deferred.
func serveWith(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("serve", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s := &serveRun{ctx: ctx, stdout: stdout, stderr: stderr}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return fail(err)
	}
	s.cfg = cfg
	// Before anything is opened: a TLS configuration that does not load refuses to start.
	internalTLS, err := internalui.LoadTLS(cfg.InternalTLSCert, cfg.InternalTLSKey)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fail(err)
	}
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		return fail(err)
	}
	defer lock.Release()

	s.setup = internalui.NewSetupTokens()
	st, err := openStore(cfg)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	s.st = st
	if err := s.openKeyring(); err != nil {
		return fail(err)
	}
	s.registerAdminHandlers()
	if err := s.admin.Start(ctx); err != nil {
		return fail(err)
	}
	defer s.admin.Close()

	passkeys, err := st.CountCredentialsByKind(ctx, "passkey")
	if err != nil {
		return fail(err)
	}
	adapter, err := s.startTunnel()
	if err != nil {
		return fail(err)
	}
	defer func() { _ = adapter.Stop() }()

	if err := s.startNode(); err != nil {
		return fail(err)
	}
	s.wireSurface()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.nd.Stop(shutCtx)
	}()

	s.announce(adapter, passkeys)

	// ---- integrations: bring back what the owner configured (SPEC §6.10) ----
	// The dialling is the first of the background loops below; this is its undoing.
	defer disconnectIntegrations(s.chain.Manager, st)

	// ---- background work: everything serve starts, it waits for ----
	// Three loops run beside the listeners. Each used to be a bare `go`, and `serve` returned — and
	// the deferred st.Close() above ran — while one could still be mid-pass: using a closed store,
	// reading its cancelled context as a failure, AUDITING that failure, and writing to a stderr
	// nobody was reading any more. CI's race detector caught the last of those on 2026-09-21.
	//
	// So they are blocking functions in one group, and this defer — registered after the store's and
	// the integrations', so it runs BEFORE them — ends their context and waits. It has its own
	// context so that it also joins on the paths that return before ctx has ended.
	// TestNoGoroutineInThisPackageIsStartedAndAbandoned keeps a fourth from being added the old way.
	bgCtx, stopBackground := context.WithCancel(ctx)
	var background sync.WaitGroup
	defer func() { stopBackground(); background.Wait() }()
	s.startBackground(bgCtx, &background)

	return runErr(internalui.Serve(ctx, cfg.InternalBind, internalTLS, s.internalSurface()), stderr)
}

// openKeyring migrates the store, opens the keyring and creates the admin socket's server and the
// identity manager the admin handlers use.
func (s *serveRun) openKeyring() error {
	if err := s.st.Migrate(s.ctx); err != nil {
		return err
	}
	keyPath := s.cfg.MasterKeyFile
	if keyPath == "" {
		keyPath = filepath.Join(s.cfg.DataDir, "keyring.key")
	}
	kr, err := core.OpenKeyring(keyPath, os.LookupEnv)
	if err != nil {
		return err
	}
	s.kr = kr
	s.admin = core.NewAdminServer(core.AdminSocketPath(s.cfg.DataDir))
	s.idm = &identity.Manager{Store: s.st, Keyring: kr}
	return nil
}

// startTunnel wires the audit sink and the owner's settings, then starts the tunnel the settings
// and the environment choose. It returns the adapter, whose Stop is the caller's to defer.
func (s *serveRun) startTunnel() (tunnel.Adapter, error) {
	// ---- the public surface (SPEC §2.2) ----
	auditLog := auditsink.New(s.ctx, s.st, s.stderr)
	s.auditFn = auditLog.System() // the node's own lifecycle and surface events
	s.ownerFn = auditLog.Owner()  // the portal and the owner MCP act for the owner
	s.auditAs = auditLog.Kinded()

	// Owner-set configuration layers under the environment and re-derives, so a
	// tunnel chosen in the portal forces the same knobs an env-set one would
	// (SPEC §10.1, §12.2).
	s.settings = settings.New(s.st, s.kr, s.cfg, s.ownerFn)
	stored, err := s.settings.Values(s.ctx)
	if err != nil {
		return nil, err
	}
	s.stored = stored
	if err := s.cfg.ApplyStoreSettings(stored); err != nil {
		return nil, err
	}
	adapterName, adapter, info, err := startTunnel(s.ctx, s.cfg, stored)
	if err != nil {
		return nil, err
	}
	s.adapterName, s.info = adapterName, info
	return adapter, nil
}

// startNode builds the integration chain, then creates the node and opens its public listener.
// The node's Stop is the caller's to defer once the surface is wired.
func (s *serveRun) startNode() error {
	ctx, st := s.ctx, s.st
	// One Connector, shared: the portal's OAuth flow pushes an authorization URL
	// into it and the manager's connect path reads from it. Two instances meant
	// the push never reached the wait (P10-04h).
	s.connector = &integrations.Connector{}
	// One wired chain, shared by the node and the portal (SPEC §6). `nd` does
	// not exist yet, so the surface-change hook is filled in after node.New.
	bus := messaging.NewBus()
	s.chain = integrationchain.Build(st, s.kr, s.connector, portalBase(s.cfg), s.auditFn, func(id string) {
		if s.surfaceChanged != nil {
			s.surfaceChanged(id)
		}
	}, s.settings.Values, func(integrationID string) {
		// The token died; only the owner can fix it. Wake the change feed NOW —
		// needs_attention is derived from the store, the event only says "look".
		if in, err := st.GetIntegrationByID(ctx, integrationID); err == nil {
			bus.Publish(messaging.Event{Kind: messaging.EventAttention, AccountID: in.AccountID})
		}
	})
	s.binder = &capabilityBinder{store: st, chain: s.chain, auditFn: s.auditFn, settings: s.settings.Values}
	// Paired on purpose: the tracker must exist before nd.Start opens the public
	// listener, not when the owner-MCP handler is built hundreds of lines later.
	s.agent, s.presence = presence.NewAgentAnswered(st, s.auditFn)
	nodeOpts := node.Options{
		Config: *s.cfg, Store: st, Keyring: s.kr, Audit: s.auditFn, Adapter: s.adapterName, Bus: bus,
		Landing: landingPage,
		// Only a TERMINATING ingress opens the onward leg; a passthrough one
		// forwards raw TLS and never presents a certificate of its own.
		IngressFingerprint: settings.PinnedIngress(s.adapterName, s.stored),
		AuditAs:            s.auditAs,
		RateBudget:         s.settings.RateBudget,
		Quota: func(accountID string) int64 {
			q, _ := s.settings.StorageFor(ctx, accountID)
			return q
		},
		// Mapped-mode providers, resolved per call so an integration connected
		// or withheld after startup is reflected without a restart (§6.6, E5).
		Capabilities: s.binder.forAccount,
	}
	nd, err := node.New(ctx, nodeOpts)
	if err != nil {
		return err
	}
	s.nd = nd
	return nd.Start(ctx, s.info.Listener)
}

// wireSurface connects what could only be connected once the node existed, and brings every
// configured integration's served surface up.
func (s *serveRun) wireSurface() {
	ctx, st, nd := s.ctx, s.st, s.nd
	s.settings.AttachNode(nd)
	// Now the node exists, an exposure change or a withhold can actually reach
	// the served surface (SPEC §6.5, §6.10). Until this was wired, publishing an
	// exposure set rebuilt nothing and a withheld integration kept its tools
	// listed for every session already open.
	// An exposure change rebuilds that integration's served tools, then sweeps
	// the callers. Before this, the picker wrote a row and no contact ever
	// gained or lost a tool (§6.5, §6.10).
	// The agent-answered bus only exists once the node does; without it the
	// first parked request would nil-panic on Publish.
	s.agent.Bus = nd.Bus()
	surface := &integrationSurface{
		store: st, chain: s.chain, node: nd, auditFn: s.auditFn, agent: s.agent,
		pass: &integrations.Passthrough{Manager: s.chain.Manager, Audit: s.auditFn},
	}
	s.surfaceChanged = func(integrationID string) {
		// Rebuild the served tools AND drop the cached capability resolution:
		// both derive from the same exposure state, so one hook owns both.
		s.binder.invalidate()
		surface.rebuild1(integrationID)
	}
	// Bring every configured integration's surface up at boot, so a node that
	// restarts serves what it served before rather than nothing until an edit.
	if accts, aerr := st.ListAccounts(ctx); aerr == nil {
		for _, a := range accts {
			list, lerr := st.ListIntegrations(ctx, a.ID)
			if lerr != nil {
				continue
			}
			for _, in := range list {
				surface.rebuild(ctx, in.ID)
			}
		}
	}
}

// announce prints what the operator needs at startup: where the node serves, each account it does
// not serve and why, and on a first run the portal and its setup URL.
func (s *serveRun) announce(adapter tunnel.Adapter, passkeys int64) {
	ctx, st, nd, cfg, stdout := s.ctx, s.st, s.nd, s.cfg, s.stdout
	fmt.Fprintf(stdout, "pact-gateway serving: data=%s internal=%s public=%s mode=%s tunnel=%s\n",
		cfg.DataDir, cfg.InternalBind, nd.Addr(), cfg.Mode, s.adapterName)
	if cfg.PublicURL != "" {
		fmt.Fprintf(stdout, "public:  %s\n", cfg.PublicURL)
	}
	if tst := adapter.Status(); tst.Detail != "" {
		fmt.Fprintf(stdout, "tunnel:  %s\n", tst.Detail)
	}
	// An account that is broken rather than waiting, first. A leaf's key that will not unseal is the
	// usual reason, and a renewal is the usual cure: it needs no old key, and the install retires
	// what this node can no longer open.
	unavailable := nd.Unavailable()
	brokenSlugs := make([]string, 0, len(unavailable))
	for slug := range unavailable {
		brokenSlugs = append(brokenSlugs, slug)
	}
	sort.Strings(brokenSlugs)
	for _, slug := range brokenSlugs {
		fmt.Fprintf(stdout, "NOT SERVED: %s — %s. If its key was sealed under a master key this node no longer has, run `pact-gateway account csr -slug %s -purpose renew`, have the wallet sign it, then `pact-gateway account install-leaf -slug %s -chain <file>`\n", slug, unavailable[slug], slug, slug)
	}
	// An account with no certificate is not served. Saying only "serving" leaves
	// the operator of a restored identity with a host that looks healthy and
	// answers for nobody, so name each one and the commands that end the wait.
	//
	// Which request to ask for follows from what the account already is, not from whether it
	// holds a key. "No key, so a move" was the rule, and it was right only while a data-only
	// import was the one way to be keyless. Every restore leaves an account keyless now (no
	// bundle carries a leaf key), and so does a leaf that simply ran out — and neither is a move.
	//   - no root: it has never been to a wallet, so it signs up;
	//   - a root, and the last leaf it held named the address this node answers at: a renewal;
	//   - a root, and the last leaf named somewhere else, or there is none on record: a move
	//     (PACT §5.3).
	for _, slug := range nd.AwaitingLeaf() {
		purpose := identity.PurposeSignup
		if a, aerr := st.GetAccountBySlug(ctx, slug); aerr == nil && a.HasRoot() {
			purpose = identity.PurposeMove
			if leaves, lerr := st.ListLeaves(ctx, a.ID); lerr == nil {
				var last store.Leaf
				for _, l := range leaves {
					if len(l.Leaf) > 0 && l.NotBefore >= last.NotBefore {
						last = l
					}
				}
				if last.Endpoint != "" && last.Endpoint == identity.EndpointFor(nd.PublicURL(), slug) {
					purpose = identity.PurposeRenew
				}
			}
		}
		fmt.Fprintf(stdout, "awaiting a certificate, not served: %s — run `pact-gateway account csr -slug %s -purpose %s`, have the wallet sign it, then `pact-gateway account install-leaf -slug %s -chain <file>`\n", slug, slug, purpose, slug)
	}
	// And an account that IS served, at an address this node no longer advertises.
	if accts, aerr := st.ListAccounts(ctx); aerr == nil {
		for _, a := range accts {
			if line := addressDriftLine(nd.PublicURL(), a.Slug, settings.LeafAddress(ctx, st, a.ID)); line != "" {
				fmt.Fprintf(stdout, "address: %s\n", line)
			}
		}
	}
	if passkeys == 0 {
		// First run (SPEC §12.4): print the portal URL and the setup token.
		// The token is NOT burned on first use — a WebAuthn ceremony is two
		// requests, so it stays valid until a passkey exists. Saying "one-time"
		// told an operator the URL was harmless once opened, when in fact anyone
		// holding it can reach the wizard until setup completes.
		fmt.Fprintf(stdout, "portal:  %s/\n", portalBase(cfg))
		fmt.Fprintf(stdout, "setup:   %s\n", setupURL(cfg, s.setup.Mint()))
		fmt.Fprintf(stdout, "         valid until a passkey is registered, at most 24h — treat it as a password\n")
		if warn := secureContextWarning(cfg); warn != "" {
			fmt.Fprintln(stdout, warn)
		}
	}
}

// startBackground starts serve's background loops in the group serveWith joins.
func (s *serveRun) startBackground(bgCtx context.Context, background *sync.WaitGroup) {
	nd := s.nd
	background.Go(func() { connectStoredIntegrations(bgCtx, s.chain.Manager, s.st, s.auditFn, s.stderr) })

	// ---- retention: delete what the owner's window says to (SPEC §7.9) ----
	// The owner sets the policy; the SYSTEM applies it on a ticker. Attributing
	// an unattended sweep to the owner would misreport who deleted the data.
	background.Go(func() {
		retention.Run(bgCtx, s.settings, s.st, s.cfg, s.auditFn, s.stderr, nd.RetireExpiredLeaves, nd.Invalidate)
	})

	// ---- outbound retries (PACT §7.1) ----
	// Undelivered outbound messages retry with backoff until their deadline.
	// Without this a send that failed once stayed failed forever and the owner had to
	// notice and retype it. The heading here used to say "relay mode as a CLIENT:
	// fetch our own mail (SPEC §10.5)", naming a role and a section both deleted with
	// 1.x on 2026-09-18; there is no mail to fetch, only sends to retry.
	background.Go(func() { nd.RunRetries(bgCtx) })

	// There is no contact sweep here. There was: every active contact of every account had its
	// card re-fetched two minutes after start and every six hours after. The owner's rule is that
	// a pin is confirmed when it is needed and the node does nothing proactively, and PACT 2.1
	// §14.3 says the same of the protocol — a newer leaf arrives ON USE (the chain in the first
	// envelope after a renewal, `certificate_renewed`, `get_card` when somebody asks) and needs no
	// poll. The sweep itself is gone too: what remains is `node.RefreshContact`, ONE contact, for
	// the button on that contact's page and the owner MCP's `refresh_contact`.
	// `TestNothingRefreshesContactsByItself` fails if a ticker or a loop finds its way back.
}

// internalSurface builds the internal surface's handler: the portal and the owner MCP.
func (s *serveRun) internalSurface() http.Handler {
	ctx, st, cfg, setup, nd, idm := s.ctx, s.st, s.cfg, s.setup, s.nd, s.idm
	// ---- the internal surface; blocks until the context ends ----
	// SPEC §8.3: binding decides authentication, and it is fixed at startup —
	// A session is required on EVERY bind (§8.3) — there is no binding that
	// serves the portal without one. A non-loopback bind additionally refuses to
	// start without passkeys+TLS, enforced at config load.
	// Two nodes on one host share a cookie jar — cookies are scoped by host and
	// path, never by port — so each node's cookies carry its own tag. Without it
	// a second local node silently signs the first one out (§8.3).
	internalui.SetCookieTag(cfg.Tag())
	authDeps := &internalui.AuthDeps{
		Service: s.authSvc,
		Origin:  internalui.OriginPolicy{InternalHost: cfg.InternalHost, TLS: cfg.InternalTLSCert != ""},
		Secure:  cfg.InternalTLSCert != "",
		Audit:   s.ownerFn,
		SetupAllowed: func(r *http.Request) bool {
			n, err := st.CountCredentialsByKind(r.Context(), "passkey")
			if err != nil {
				return false
			}
			if n > 0 {
				// Recovery only, and only with the token in hand (§8.6).
				return setup.ValidRecovery(r.URL.Query().Get("token"))
			}
			return core.IsLoopbackBind(cfg.InternalBind) || setup.Valid(r.URL.Query().Get("token"))
		},
		SetupDone: func(r *http.Request) { setup.Consume(r.URL.Query().Get("token")) },
	}
	setStatic := func(ctx context.Context, integrationID, header, value string) error {
		return integrations.SealStatic(st, s.kr, integrationID, header, value)
	}
	setOAuthClient := func(ctx context.Context, integrationID, clientID, clientSecret string) error {
		return integrations.SealClient(st, s.kr, core.SettingsAAD(), integrationID, clientID, clientSecret)
	}
	identityDeps := internalui.IdentityDeps{
		Accounts: st.ListAccounts, Audit: s.auditFn,
		Certificate: func(ctx context.Context, accountID string) (identity.CertificateInfo, error) {
			return idm.Certificate(ctx, accountID, time.Now())
		},
		// The SAME call `account create` makes, so the portal cannot become a
		// second way of minting identities that drifts from the CLI's.
		Create: func(ctx context.Context, slug, displayName, algo string) (store.Account, error) {
			a, err := idm.CreateAccount(ctx, slug, displayName, identity.Algo(algo))
			if err != nil {
				return a, err
			}
			// Servable without a restart: the node adopts it live, the way the
			// admin socket's account.create does (P14-05c).
			if aerr := nd.AdoptAccount(ctx, a.ID); aerr != nil {
				return a, aerr
			}
			return a, nil
		},
	}
	return internalHandler(ctx, nd, st, setup, s.tokSvc, s.authSvc, s.chain, s.connector, s.agent, s.presence, identityDeps,
		setStatic, setOAuthClient, s.ownerFn,
		cfg.PublicURL, s.settings.Deps(), authDeps, cfg)
}
