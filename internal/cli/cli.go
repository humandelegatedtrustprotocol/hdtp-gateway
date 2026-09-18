// Package cli implements the command-line interface of SPEC §12.1: one binary,
// subcommand-per-concern, stdlib flag parsing. Against a running node the CLI talks
// over the admin unix socket; offline database commands take the store lock and
// therefore refuse to run while the node is serving.
package cli

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/audit"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/internalui"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
	"github.com/tech-sumit/pact-gateway/internal/node"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
)

// Run dispatches os.Args-style arguments; version is the build-stamped version
// string. Returns a process exit code.
func Run(args []string, version string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, "pact-gateway "+version)
		return 0
	case "serve":
		return serve(rest, stdout, stderr)
	case "ingress":
		return ingressCmd(rest, stdout, stderr)
	case "migrate":
		return migrate(rest, stdout, stderr)
	case "doctor":
		return doctor(rest, stdout, stderr)
	case "healthcheck":
		return healthcheck(rest, stderr)
	case "account":
		return account(rest, stdout, stderr)
	case "passkey":
		return passkey(rest, stdout, stderr)
	case "token":
		return token(rest, stdout, stderr)
	case "audit":
		return auditCmd(rest, stdout, stderr)
	case "backup":
		return backupCmd(rest, stdout, stderr)
	case "__child":
		// hidden: the resource-cap shim for supervised stdio children (SPEC §6.2)
		if err := integrations.RunChildShim(rest); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "pact-gateway: unknown command %q\n", cmd)
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: pact-gateway <command> [flags]

commands:
  serve     run the node
  ingress   serve|token — the ingress role (own-domain front door for paired nodes)
  migrate   run store migrations (node must be stopped)
  doctor    diagnose configuration, data dir, store, lock
  healthcheck  probe the internal /healthz (container HEALTHCHECK)
  account   create|list accounts and identity keys; csr|install-leaf|certificate|address|announce the leaf a wallet issues and the move it may be (node must be running; talks over the admin socket)
  passkey   list|remove|reset-wizard (node must be running)
  token     create|list|revoke owner-MCP bearer tokens (node must be running)
  audit     verify|export|archive|repair the hash chain (offline; node must be stopped)
  backup    create|restore a consistent snapshot (offline; node must be stopped)
  version   print the version
`)
}

// commonFlags returns a FlagSet with the -config flag every subcommand shares.
//
// It takes the caller's stderr because `Run` is handed writers and must use them.
// Without SetOutput, flag writes usage and parse errors to the process's
// os.Stderr instead: invisible to an embedder capturing output, noisy in tests
// that asked for silence, and — because the documentation lint asks each command
// for its flag set by running it with -h and reading what comes back — it read
// nothing and silently skipped every flag check in every doc.
func commonFlags(name string, cfgPath *string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(cfgPath, "config", os.Getenv("PACT_CONFIG"), "path to config file (JSON)")
	return fs
}

func loadConfig(cfgPath string) (*core.Config, error) {
	return core.Load(cfgPath, os.LookupEnv)
}

func serve(args []string, stdout, stderr io.Writer) int {
	// SIGINT/SIGTERM end the serving context; every surface shuts down from it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveWith(ctx, args, stdout, stderr)
}

// serveWith is serve with the lifetime injected, so a test can end it without
// signalling the whole process.
func serveWith(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("serve", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	defer lock.Release()

	setup := internalui.NewSetupTokens()
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	keyPath := cfg.MasterKeyFile
	if keyPath == "" {
		keyPath = filepath.Join(cfg.DataDir, "keyring.key")
	}
	kr, err := core.OpenKeyring(keyPath, os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	admin := core.NewAdminServer(core.AdminSocketPath(cfg.DataDir))
	admin.Handle("ping", func(map[string]string) (any, error) {
		return map[string]string{"status": "serving"}, nil
	})
	idm := &identity.Manager{Store: st, Keyring: kr}
	// Declared before the admin handlers because several of them close over it.
	// It is nil while they are being REGISTERED and non-nil by the time any of
	// them runs, which is why each checks.
	var nd *node.Node
	// The audit sink is wired once the store and the listener exist; the
	// handlers below run only after that, which is why they may close over it.
	var auditFn func(action, resource, outcome string)
	// PACT 2.0 (PACT §9): the certificate signing request a wallet answers, the
	// install of the chain it returns, the certificate state, and the owner's
	// answer to a contact waiting at a new address (§5.3).
	accountBySlug := func(slug string) (store.Account, error) {
		accts, err := st.ListAccounts(ctx)
		if err != nil {
			return store.Account{}, err
		}
		for _, a := range accts {
			if a.Slug == slug {
				return a, nil
			}
		}
		return store.Account{}, fmt.Errorf("unknown slug %q", slug)
	}
	endpointFor := func(slug string) string {
		if nd != nil {
			return identity.EndpointFor(nd.PublicURL(), slug)
		}
		return identity.EndpointFor(cfg.PublicURL, slug)
	}
	csrFor := func(acct store.Account, purpose, endpoint string) (map[string]any, error) {
		if purpose == "" {
			purpose = identity.PurposeRenew
			if acct.Protocol != 2 {
				purpose = identity.PurposeSignup
			}
		}
		if endpoint == "" {
			endpoint = endpointFor(acct.Slug)
		}
		if endpoint == "" {
			return nil, fmt.Errorf("account.csr: no public URL is configured; pass -endpoint")
		}
		res, err := idm.IssueCSR(ctx, acct.ID, purpose, endpoint, time.Now())
		if err != nil {
			return nil, err
		}
		auditFn("account_csr", "account:"+acct.ID+" slug:"+acct.Slug+" purpose:"+purpose+" endpoint:"+endpoint+" key:"+res.Kid, "ok")
		out := map[string]any{
			"Slug": acct.Slug, "Purpose": res.Purpose, "Endpoint": res.Endpoint, "Kid": res.Kid,
			"CSR":               string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: res.CSR})),
			"SuggestedNotAfter": res.SuggestedNotAfter.UTC().Format(time.RFC3339),
		}
		if res.PreviousNotBefore != nil {
			out["PreviousNotBefore"] = res.PreviousNotBefore.UTC().Format(time.RFC3339)
		}
		return out, nil
	}

	admin.Handle("account.create", func(args map[string]string) (any, error) {
		if args["slug"] == "" || args["name"] == "" {
			return nil, fmt.Errorf("account.create needs slug and name")
		}
		acct, err := idm.CreateAccount(ctx, args["slug"], args["name"], identity.Algo(args["algo"]))
		if err != nil {
			return nil, err
		}
		// The node only knows the accounts that existed when it started, so
		// without this the public listener cannot serve the one just created —
		// every handshake for it fails with `tls: internal error` until a restart
		// (P14-05a). The README tells a new owner to create an account on a
		// running node, so this is the ordinary path, not an edge case.
		// A brand-new account has a key and no leaf, so the node cannot serve it yet
		// and says so — that is the normal state between `account create` and
		// `account install-leaf`, not a failure to create. Anything else is.
		if nd != nil {
			if aerr := nd.AdoptAccount(ctx, acct.ID); aerr != nil && !errors.Is(aerr, node.ErrAwaitingLeaf) {
				return nil, aerr
			}
		}
		// An account starts as a signup request for its key (PACT §9): it has no
		// card and no chain to present until the wallet's leaf is installed.
		// The request is a convenience, not part of creating the account: a node with
		// no public URL configured yet cannot name an endpoint, and that must not stop
		// the account existing. `account csr -endpoint …` asks for it later.
		out, cerr := csrFor(acct, identity.PurposeSignup, args["endpoint"])
		if cerr != nil {
			return map[string]any{
				"Slug": acct.Slug, "Fingerprint": acct.Fingerprint,
				"CSRPending": "no endpoint yet: run `account csr -slug " + acct.Slug + " -endpoint <https url>` when the node has one",
			}, nil
		}
		out["Fingerprint"] = acct.Fingerprint
		return out, nil
	})
	admin.Handle("account.list", func(map[string]string) (any, error) {
		return st.ListAccounts(ctx)
	})
	// SPEC §3.9 rotation: new key + grace, then update_contact fan-out over the
	// outbound client PRESENTING THE OLD CERTIFICATE (the identity contacts
	// still pin); per-contact progress is durable, so re-running resumes.
	// The serving node, assigned below. The admin handlers registered here close
	// over it so they render cards through the ONE renderer the public surface
	// uses, rather than assembling a second one (SPEC §9.3).
	admin.Handle("account.csr", func(args map[string]string) (any, error) {
		if args["slug"] == "" {
			return nil, fmt.Errorf("account.csr needs slug")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		return csrFor(acct, args["purpose"], args["endpoint"])
	})
	admin.Handle("account.install", func(args map[string]string) (any, error) {
		if args["slug"] == "" || args["chain"] == "" {
			return nil, fmt.Errorf("account.install needs slug and chain")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		chain, err := parseChainPEM(args["chain"])
		if err != nil {
			return nil, err
		}
		res, err := idm.InstallLeaf(ctx, acct.ID, chain, time.Now())
		if err != nil {
			auditFn("account_leaf_install", "account:"+acct.ID+" slug:"+acct.Slug, "error")
			return nil, err
		}
		auditFn("account_leaf_install", "account:"+acct.ID+" slug:"+acct.Slug+" root:"+res.RootFingerprint+" key:"+res.Kid+" endpoint:"+res.Endpoint, "ok")
		// The node loaded the account's key and certificate when it started;
		// the install changed both in the store. Rebuild it live.
		if nd != nil {
			if aerr := nd.AdoptAccount(ctx, acct.ID); aerr != nil {
				return nil, fmt.Errorf("install: reloading the account on the live node: %w", aerr)
			}
		}
		out := map[string]any{
			"Slug": acct.Slug, "Root": res.RootFingerprint, "Kid": res.Kid, "Endpoint": res.Endpoint,
			"NotAfter": res.NotAfter.UTC().Format(time.RFC3339), "First": res.FirstInstall, "KeyChanged": res.KeyChanged,
		}
		// The campaign an install can start — the move's update_contact toward
		// contacts pinned by our root (PACT §5.3, §9) — runs DETACHED.
		//
		// They used to run inside this call. One unreachable contact costs up to
		// the outbound timeout, the admin client waits 30 seconds, and the leaf
		// was already installed: so a single dead host timed out the CLI on a
		// success, and the obvious retry answered "no certificate request is
		// pending". The install is the durable part and it answers now; the walks
		// are durable too (`rotation_fanout`), so `account announce` reports and
		// resumes them.
		moved := !res.FirstInstall && res.OldEndpoint != "" && res.OldEndpoint != res.Endpoint && nd != nil
		if moved {
			out["Campaigns"] = "started; `pact-gateway account announce -slug " + acct.Slug + "` reports and resumes them"
			accountID, kid := acct.ID, res.Kid
			go func() {
				// The admin call's context ends with the call; these outlive it.
				bg := context.WithoutCancel(ctx)
				if moved {
					if d, f, merr := nd.AnnounceMove(bg, accountID, kid); merr != nil {
						auditFn("account_move_campaign", "account:"+accountID, "error")
					} else {
						auditFn("account_move_campaign", fmt.Sprintf("account:%s done:%d failed:%d", accountID, d, f), "ok")
					}
				}
			}()
		}
		return out, nil
	})
	// account.announce resumes the campaign an install starts — the move's
	// update_contact walk — for the current leaf. The walk is durable, so contacts
	// already told are skipped and the rest are tried.
	admin.Handle("account.announce", func(args map[string]string) (any, error) {
		if args["slug"] == "" {
			return nil, fmt.Errorf("account.announce needs slug")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		if acct.Protocol != 2 || nd == nil {
			return nil, fmt.Errorf("account.announce: %s is not a 2.0 identity on the live node", acct.Slug)
		}
		done, failed, err := nd.AnnounceMove(ctx, acct.ID, acct.Fingerprint)
		if err != nil {
			return nil, err
		}
		return map[string]any{"Slug": acct.Slug, "MoveDone": done, "MoveFailed": failed}, nil
	})
	admin.Handle("account.certificate", func(args map[string]string) (any, error) {
		if args["slug"] == "" {
			return nil, fmt.Errorf("account.certificate needs slug")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		info, err := idm.Certificate(ctx, acct.ID, time.Now())
		if err != nil {
			return nil, err
		}
		out := map[string]any{
			"Slug": acct.Slug, "Protocol": info.Protocol, "Root": info.RootFingerprint, "Kid": info.Kid, "Endpoint": info.Endpoint,
			"RenewalDue": info.RenewalDue, "PendingCSR": info.PendingCSR, "Superseded": info.Superseded, "Former": info.Former,
		}
		if info.Protocol == 2 {
			out["NotBefore"], out["NotAfter"] = info.NotBefore.Format(time.RFC3339), info.NotAfter.Format(time.RFC3339)
			var chain strings.Builder
			for _, c := range info.Chain {
				chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c}))
			}
			out["Chain"] = chain.String()
		}
		return out, nil
	})
	admin.Handle("account.address", func(args map[string]string) (any, error) {
		if args["slug"] == "" || args["root"] == "" || (args["decision"] != "approve" && args["decision"] != "reject") {
			return nil, fmt.Errorf("account.address needs slug, root and decision approve|reject")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		cm := &contacts.Manager{Store: st}
		p, err := cm.DecideAddress(ctx, acct.ID, args["root"], args["decision"] == "approve")
		if err != nil {
			return nil, err
		}
		auditFn("contact_address_"+args["decision"], "account:"+acct.ID+" contact:"+args["root"]+" endpoint:"+p.Endpoint, "ok")
		if nd != nil {
			_ = nd.Invalidate(ctx, acct.ID, args["root"])
		}
		return map[string]any{"Slug": acct.Slug, "Root": args["root"], "Endpoint": p.Endpoint, "Decision": args["decision"]}, nil
	})
	admin.Handle("account.addresses", func(args map[string]string) (any, error) {
		if args["slug"] == "" {
			return nil, fmt.Errorf("account.addresses needs slug")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		return st.ListPendingAddresses(ctx, acct.ID)
	})

	// The relying party is decided PER CEREMONY from the request's host
	// (SPEC §8.3): a fixed pairing cannot serve both a loopback portal and one on
	// a domain, and the previous fixed values — RP ID `localhost` with a
	// 127.0.0.1 origin — could never have completed a ceremony at all.
	authSvc := auth.New(st)
	admin.Handle("passkey.list", func(map[string]string) (any, error) {
		return authSvc.ListPasskeys(ctx)
	})
	admin.Handle("passkey.remove", func(args map[string]string) (any, error) {
		if args["id"] == "" {
			return nil, fmt.Errorf("passkey.remove needs id")
		}
		return "removed", authSvc.RemovePasskey(ctx, args["id"])
	})
	tokSvc := &auth.TokenService{Store: st}
	admin.Handle("token.create", func(args map[string]string) (any, error) {
		if args["owner"] == "" || args["label"] == "" {
			return nil, fmt.Errorf("token.create needs owner and label")
		}
		plain, id, err := tokSvc.Create(ctx, args["owner"], args["label"], args["account"])
		if err != nil {
			return nil, err
		}
		return map[string]string{"token": plain, "id": id}, nil
	})
	admin.Handle("token.list", func(map[string]string) (any, error) {
		return tokSvc.List(ctx)
	})
	admin.Handle("token.revoke", func(args map[string]string) (any, error) {
		if args["id"] == "" {
			return nil, fmt.Errorf("token.revoke needs id")
		}
		return "revoked", tokSvc.Revoke(ctx, args["id"])
	})
	admin.Handle("passkey.reset-wizard", func(map[string]string) (any, error) {
		// SPEC §3.1: mint a fresh one-time setup URL for a locked-out owner.
		// RECOVERY, not an ordinary token: with the portal requiring a session
		// on every bind (§8.3), this is the ONLY way back in for an owner who
		// lost their passkeys, and an ordinary token is refused the moment one
		// exists. Registering through it ADDS a passkey; nothing is removed.
		return map[string]string{
			"url": setupURL(cfg, setup.MintRecovery()),
		}, nil
	})
	if err := admin.Start(ctx); err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	defer admin.Close()

	n, err := st.CountCredentialsByKind(ctx, "passkey")
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	// ---- the public surface (SPEC §2.2) ----
	auditLog := auditWriter(ctx, st, stderr)
	auditFn = auditLog.system() // the node's own lifecycle and surface events
	ownerFn := auditLog.owner() // the portal and the owner MCP act for the owner

	// Owner-set configuration layers under the environment and re-derives, so a
	// tunnel chosen in the portal forces the same knobs an env-set one would
	// (SPEC §10.1, §12.2).
	settings := &settingsService{store: st, kr: kr, cfg: cfg, audit: ownerFn}
	// A credential stored while isSecretKey was case-sensitive is sitting in the
	// clear; fixing the predicate only protects the next write. Repairing at
	// startup is not optional cleanup — an owner cannot be expected to notice.
	if n, err := settings.resealLegacySecrets(ctx); err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	} else if n > 0 {
		fmt.Fprintf(stdout, "settings: sealed %d credential(s) that were stored in the clear\n", n)
	}
	stored, err := settings.values(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	if err := cfg.ApplyStoreSettings(stored); err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	adapterName, adapter, info, err := startTunnel(ctx, cfg, stored)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	defer func() { _ = adapter.Stop() }()

	// One Connector, shared: the portal's OAuth flow pushes an authorization URL
	// into it and the manager's connect path reads from it. Two instances meant
	// the push never reached the wait (P10-04h).
	connector := &integrations.Connector{}
	// One wired chain, shared by the node and the portal (SPEC §6). `nd` does
	// not exist yet, so the surface-change hook is filled in after node.New.
	var surfaceChanged func(integrationID string)
	bus := messaging.NewBus()
	chain := buildIntegrationChain(st, kr, connector, portalBase(cfg), auditFn, func(id string) {
		if surfaceChanged != nil {
			surfaceChanged(id)
		}
	}, settings.values, func(integrationID string) {
		// The token died; only the owner can fix it. Wake the change feed NOW —
		// needs_attention is derived from the store, the event only says "look".
		if in, err := st.GetIntegrationByID(ctx, integrationID); err == nil {
			bus.Publish(messaging.Event{Kind: messaging.EventAttention, AccountID: in.AccountID})
		}
	})
	ints := chain.Manager
	binder := &capabilityBinder{store: st, chain: chain, auditFn: auditFn, settings: settings.values}
	// Paired on purpose: the tracker must exist before nd.Start opens the public
	// listener, not when the owner-MCP handler is built hundreds of lines later.
	agent, presence := newAgentAnswered(st, auditFn)
	nodeOpts := node.Options{
		Config: *cfg, Store: st, Keyring: kr, Audit: auditFn, Adapter: adapterName, Bus: bus,
		// Only a TERMINATING ingress opens the onward leg; a passthrough one
		// forwards raw TLS and never presents a certificate of its own.
		IngressFingerprint: pinnedIngress(adapterName, stored),
		AuditAs:            auditLog.kinded(),
		RateBudget:         settings.rateBudget,
		Quota: func(accountID string) int64 {
			q, _ := settings.storageFor(ctx, accountID)
			return q
		},
		// Mapped-mode providers, resolved per call so an integration connected
		// or withheld after startup is reflected without a restart (§6.6, E5).
		Capabilities: binder.forAccount,
	}
	nd, err = node.New(ctx, nodeOpts)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	if err := nd.Start(ctx, info.Listener); err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	settings.node = nd
	// Now the node exists, an exposure change or a withhold can actually reach
	// the served surface (SPEC §6.5, §6.10). Until this was wired, publishing an
	// exposure set rebuilt nothing and a withheld integration kept its tools
	// listed for every session already open.
	// An exposure change rebuilds that integration's served tools, then sweeps
	// the callers. Before this, the picker wrote a row and no contact ever
	// gained or lost a tool (§6.5, §6.10).
	// The agent-answered bus only exists once the node does; without it the
	// first parked request would nil-panic on Publish.
	agent.Bus = nd.Bus()
	surface := &integrationSurface{
		store: st, chain: chain, node: nd, auditFn: auditFn, agent: agent,
		pass: &integrations.Passthrough{Manager: chain.Manager, Audit: auditFn},
	}
	surfaceChanged = func(integrationID string) {
		// Rebuild the served tools AND drop the cached capability resolution:
		// both derive from the same exposure state, so one hook owns both.
		binder.invalidate()
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
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = nd.Stop(shutCtx)
	}()

	fmt.Fprintf(stdout, "pact-gateway serving: data=%s internal=%s public=%s mode=%s tunnel=%s\n",
		cfg.DataDir, cfg.InternalBind, nd.Addr(), cfg.Mode, adapterName)
	if cfg.PublicURL != "" {
		fmt.Fprintf(stdout, "public:  %s\n", cfg.PublicURL)
	}
	if tst := adapter.Status(); tst.Detail != "" {
		fmt.Fprintf(stdout, "tunnel:  %s\n", tst.Detail)
	}
	// An account with no certificate is not served. Saying only "serving" leaves
	// the operator of a restored identity with a host that looks healthy and
	// answers for nobody, so name each one and the commands that end the wait.
	// A data-only import has no key of its own here — that is a move (PACT §5.3);
	// an account created on this host already has one, so it signs up.
	for _, slug := range nd.AwaitingLeaf() {
		purpose := "signup"
		if a, aerr := st.GetAccountBySlug(ctx, slug); aerr == nil {
			if sealed, serr := st.GetAccountSealedKey(ctx, a.ID); serr == nil && len(sealed) == 0 {
				purpose = "move"
			}
		}
		fmt.Fprintf(stdout, "awaiting a certificate, not served: %s — run `pact-gateway account csr -slug %s -purpose %s`, have the wallet sign it, then `pact-gateway account install-leaf -slug %s -chain <file>`\n", slug, slug, purpose, slug)
	}
	if n == 0 {
		// First run (SPEC §12.4): print the portal URL and the setup token.
		// The token is NOT burned on first use — a WebAuthn ceremony is two
		// requests, so it stays valid until a passkey exists. Saying "one-time"
		// told an operator the URL was harmless once opened, when in fact anyone
		// holding it can reach the wizard until setup completes.
		fmt.Fprintf(stdout, "portal:  %s/\n", portalBase(cfg))
		fmt.Fprintf(stdout, "setup:   %s\n", setupURL(cfg, setup.Mint()))
		fmt.Fprintf(stdout, "         valid until a passkey is registered, at most 24h — treat it as a password\n")
		if warn := secureContextWarning(cfg); warn != "" {
			fmt.Fprintln(stdout, warn)
		}
	}

	// ---- integrations: bring back what the owner configured (SPEC §6.10) ----
	connectStoredIntegrations(ctx, ints, st, auditFn, stderr)
	defer disconnectIntegrations(ints, st)

	// ---- retention: delete what the owner's window says to (SPEC §7.9) ----
	// The owner sets the policy; the SYSTEM applies it on a ticker. Attributing
	// an unattended sweep to the owner would misreport who deleted the data.
	startRetentionSweeper(ctx, settings, st, cfg, auditFn, stderr)

	// ---- relay mode as a CLIENT: fetch our own mail (SPEC §10.5) ----
	// Undelivered outbound messages retry with backoff until their deadline
	// (SPEC §7.1). Without this a send that failed once stayed failed forever
	// and the owner had to notice and retype it.
	go nd.RunRetries(ctx)

	// Contacts in sync (PACT §3): pull each active contact's signed card on a
	// slow cadence, so an endpoint change whose announcement missed us — we
	// were offline — heals without waiting for a failed call. The card must name the
	// pinned ROOT and verify under the leaf the answered chain proves: a renewal is
	// learned here, an address change is not (node.SyncContacts documents the rule).
	go func() {
		const every = 6 * time.Hour
		t := time.NewTicker(every)
		defer t.Stop()
		// First sweep shortly after start, once the tunnels have settled.
		first := time.NewTimer(2 * time.Minute)
		defer first.Stop()
		sweep := func() {
			sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			checked, changed := nd.SyncContacts(sctx)
			cancel()
			if checked > 0 {
				auditFn("contact_sync_sweep", fmt.Sprintf("checked:%d updated:%d", checked, changed), "ok")
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-first.C:
				sweep()
			case <-t.C:
				sweep()
			}
		}
	}()

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
		Service: authSvc,
		Origin:  internalui.OriginPolicy{InternalHost: cfg.InternalHost, TLS: cfg.InternalTLSCert != ""},
		Secure:  cfg.InternalTLSCert != "",
		Audit:   ownerFn,
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
		return integrations.SealStatic(st, kr, integrationID, header, value)
	}
	setOAuthClient := func(ctx context.Context, integrationID, clientID, clientSecret string) error {
		return integrations.SealClient(st, kr, settingsAAD(), integrationID, clientID, clientSecret)
	}
	identityDeps := internalui.IdentityDeps{
		Accounts: st.ListAccounts, Audit: auditFn,
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
	handler := internalHandler(ctx, nd, st, setup, tokSvc, authSvc, chain, connector, agent, presence, identityDeps,
		setStatic, setOAuthClient, ownerFn,
		cfg.PublicURL, settings.deps(), authDeps, cfg)
	return runErr(internalui.Serve(ctx, cfg.InternalBind, handler), stderr)
}

func account(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway account <create|list|csr|install-leaf|certificate|address|announce> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath, slug, name, algo, purpose, endpoint, chainPath, root, decision string
	fs := commonFlags("account "+sub, &cfgPath, stderr)
	fs.StringVar(&slug, "slug", "", "account slug (endpoint path segment)")
	fs.StringVar(&name, "name", "", "display name")
	fs.StringVar(&algo, "algo", "p256", "key algorithm: p256|ed25519")
	fs.StringVar(&purpose, "purpose", "", "csr: signup|renew|move (default: signup before the first leaf, renew after)")
	fs.StringVar(&endpoint, "endpoint", "", "csr, create -protocol 2: the https URL the leaf names (default: the node's public URL for the slug)")
	fs.StringVar(&chainPath, "chain", "", "install-leaf: file holding the wallet's answer, two PEM CERTIFICATE blocks, leaf then root")
	fs.StringVar(&root, "root", "", "address: the root fingerprint waiting at a new address")
	fs.StringVar(&decision, "decision", "", "address: approve|reject; omitted lists what is pending")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "account:", err)
		return 1
	}
	sock := core.AdminSocketPath(cfg.DataDir)
	switch sub {
	case "create":
		var out map[string]any
		if err := core.AdminCall(sock, "account.create", map[string]string{"slug": slug, "name": name, "algo": algo, "endpoint": endpoint}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "created %v  fingerprint %v\n", out["Slug"], out["Fingerprint"])
		if csr, ok := out["CSR"].(string); ok {
			fmt.Fprintf(stdout, "certificate signing request for %v (hand it to the wallet, then `account install-leaf`):\n%s", out["Endpoint"], csr)
		}
		return 0
	case "csr":
		var out map[string]any
		if err := core.AdminCall(sock, "account.csr", map[string]string{"slug": slug, "purpose": purpose, "endpoint": endpoint}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stderr, "%v request for %v, key %v; suggested notAfter %v\n", out["Purpose"], out["Endpoint"], out["Kid"], out["SuggestedNotAfter"])
		fmt.Fprint(stdout, out["CSR"])
		return 0
	case "install-leaf":
		if chainPath == "" {
			fmt.Fprintln(stderr, "account: install-leaf needs -chain FILE")
			return 2
		}
		chain, err := os.ReadFile(chainPath)
		if err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		var out map[string]any
		if err := core.AdminCall(sock, "account.install", map[string]string{"slug": slug, "chain": string(chain)}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "installed leaf %v for %v under root %v, valid until %v\n", out["Kid"], out["Endpoint"], out["Root"], out["NotAfter"])
		if d, ok := out["MoveDone"]; ok {
			fmt.Fprintf(stdout, "contacts told of the new address: done=%v failed=%v (re-run `account announce` for the rest)\n", d, out["MoveFailed"])
		}
		return 0
	case "announce":
		var out map[string]any
		if err := core.AdminCall(sock, "account.announce", map[string]string{"slug": slug}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "contacts told of the address: done=%v failed=%v\n", out["MoveDone"], out["MoveFailed"])
		return 0
	case "certificate":
		var out map[string]any
		if err := core.AdminCall(sock, "account.certificate", map[string]string{"slug": slug}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		if p, _ := out["Protocol"].(float64); p != 2 {
			fmt.Fprintf(stdout, "%v has no leaf yet; `account csr -slug %v` prints the request for the wallet\n", out["Slug"], out["Slug"])
			return 0
		}
		fmt.Fprintf(stdout, "%v: root %v\n  leaf %v for %v, %v to %v\n  renewal due: %v\n", out["Slug"], out["Root"], out["Kid"], out["Endpoint"], out["NotBefore"], out["NotAfter"], out["RenewalDue"])
		if p, _ := out["PendingCSR"].(string); p != "" {
			fmt.Fprintf(stdout, "  a request for key %v awaits the wallet\n", p)
		}
		fmt.Fprint(stdout, out["Chain"])
		return 0
	case "address":
		if decision == "" {
			var out []map[string]any
			if err := core.AdminCall(sock, "account.addresses", map[string]string{"slug": slug}, &out); err != nil {
				fmt.Fprintln(stderr, "account:", err)
				return 1
			}
			for _, p := range out {
				fmt.Fprintf(stdout, "%v\t%v\t%v\n", p["Root"], p["Endpoint"], p["Why"])
			}
			return 0
		}
		var out map[string]any
		if err := core.AdminCall(sock, "account.address", map[string]string{"slug": slug, "root": root, "decision": decision}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "%v: %v at %v\n", out["Decision"], out["Root"], out["Endpoint"])
		return 0
	case "list":
		var out []map[string]any
		if err := core.AdminCall(sock, "account.list", nil, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		for _, a := range out {
			fmt.Fprintf(stdout, "%v\t%v\t%v\t%v\n", a["Slug"], a["DisplayName"], a["Algo"], a["Fingerprint"])
		}
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway account <create|list|csr|install-leaf|certificate|address|announce> [flags]")
		return 2
	}
}

// parseChainPEM reads the wallet's answer: two CERTIFICATE blocks, leaf then root.
func parseChainPEM(text string) ([][]byte, error) {
	var chain [][]byte
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("chain: unexpected PEM block %q (want CERTIFICATE)", block.Type)
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) != 2 {
		return nil, fmt.Errorf("chain: want exactly two certificates, leaf then root; got %d", len(chain))
	}
	return chain, nil
}

func passkey(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway passkey <list|remove|reset-wizard> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath, id string
	fs := commonFlags("passkey "+sub, &cfgPath, stderr)
	fs.StringVar(&id, "id", "", "passkey id (for remove)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "passkey:", err)
		return 1
	}
	sock := core.AdminSocketPath(cfg.DataDir)
	switch sub {
	case "list":
		var out []map[string]any
		if err := core.AdminCall(sock, "passkey.list", nil, &out); err != nil {
			fmt.Fprintln(stderr, "passkey:", err)
			return 1
		}
		for _, k := range out {
			fmt.Fprintf(stdout, "%v\t%v\towner=%v\n", k["id"], k["tag"], k["owner_id"])
		}
		return 0
	case "remove":
		var out string
		if err := core.AdminCall(sock, "passkey.remove", map[string]string{"id": id}, &out); err != nil {
			fmt.Fprintln(stderr, "passkey:", err)
			return 1
		}
		fmt.Fprintln(stdout, out)
		return 0
	case "reset-wizard":
		var out map[string]string
		if err := core.AdminCall(sock, "passkey.reset-wizard", nil, &out); err != nil {
			fmt.Fprintln(stderr, "passkey:", err)
			return 1
		}
		fmt.Fprintln(stdout, "one-time setup URL (24h, single use):")
		fmt.Fprintln(stdout, out["url"])
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway passkey <list|remove|reset-wizard> [flags]")
		return 2
	}
}

func token(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway token <create|list|revoke> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath, owner, label, accountID, id string
	fs := commonFlags("token "+sub, &cfgPath, stderr)
	fs.StringVar(&owner, "owner", "", "owner id")
	fs.StringVar(&label, "label", "", "token label")
	fs.StringVar(&accountID, "account", "", "optional account scope")
	fs.StringVar(&id, "id", "", "token id (for revoke)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "token:", err)
		return 1
	}
	sock := core.AdminSocketPath(cfg.DataDir)
	switch sub {
	case "create":
		var out map[string]string
		if err := core.AdminCall(sock, "token.create", map[string]string{"owner": owner, "label": label, "account": accountID}, &out); err != nil {
			fmt.Fprintln(stderr, "token:", err)
			return 1
		}
		fmt.Fprintln(stdout, "token (shown once):", out["token"])
		fmt.Fprintln(stdout, "id:", out["id"])
		return 0
	case "list":
		var out []map[string]any
		if err := core.AdminCall(sock, "token.list", nil, &out); err != nil {
			fmt.Fprintln(stderr, "token:", err)
			return 1
		}
		for _, k := range out {
			fmt.Fprintf(stdout, "%v\t%v\trevoked=%v\n", k["id"], k["label"], k["revoked"])
		}
		return 0
	case "revoke":
		var out string
		if err := core.AdminCall(sock, "token.revoke", map[string]string{"id": id}, &out); err != nil {
			fmt.Fprintln(stderr, "token:", err)
			return 1
		}
		fmt.Fprintln(stdout, out)
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway token <create|list|revoke> [flags]")
		return 2
	}
}

func auditCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway audit <verify|export|archive|repair> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath string
	var throughSeq int64
	fs := commonFlags("audit "+sub, &cfgPath, stderr)
	fs.Int64Var(&throughSeq, "through", 0, "archive: archive events up to and including this seq")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	// Offline command (SPEC §12.1): refuse while the node holds the lock.
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	defer lock.Release()
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	defer st.Close()
	rows, err := st.ListAuditEvents(context.Background(), "")
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	events := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		events = append(events, audit.Event{
			Seq: r.Seq, TS: r.TS, AccountID: r.AccountID, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Action: r.Action, Resource: r.Resource, Outcome: r.Outcome,
			RequestID: r.RequestID, Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
		})
	}
	as := auditStore{st: st}
	switch sub {
	case "verify":
		// Anchored: the retained rows must extend genesis, or the terminal hash
		// of whatever was archived. Verifying a chain against its own first row
		// cannot see a head that was removed (SPEC §11.6).
		if idx, err := audit.VerifyChain(context.Background(), as); err != nil {
			// An unfinished archive run is not tampering, and saying "BROKEN"
			// would send an owner hunting an intruder who is not there.
			if errors.Is(err, audit.ErrArchiveInterrupted) {
				fmt.Fprintf(stderr, "audit: %v\n", err)
				return 1
			}
			fmt.Fprintf(stderr, "audit: chain BROKEN at row %d: %v\n", idx, err)
			return 1
		}
		anchor, _ := st.AuditAnchor(context.Background())
		if anchor.TerminalHash != "" {
			// The archive is PART of the chain, so a missing archive is a
			// missing chain — not a reason to report success. Verifying only
			// what happens to still be on disk would reintroduce exactly the
			// "deleted history is invisible" hole §11.6 exists to close.
			archives := archiveFiles(cfg.DataDir)
			if len(archives) == 0 {
				fmt.Fprintf(stderr, "audit: chain BROKEN: the anchor names an archive through seq %d "+
					"but no archive files are present in %s\n", anchor.ArchivedThroughSeq, archiveDir(cfg.DataDir))
				return 1
			}
			if _, err := os.Stat(anchor.ArchivePath); err != nil && anchor.ArchivePath != "" {
				fmt.Fprintf(stderr, "audit: chain BROKEN: the archive the anchor names (%s) is gone\n",
					anchor.ArchivePath)
				return 1
			}
			if idx, err := audit.VerifyWithArchives(context.Background(), as, archives); err != nil {
				fmt.Fprintf(stderr, "audit: chain BROKEN at row %d: %v\n", idx, err)
				return 1
			}
			fmt.Fprintf(stdout, "audit chain verified across %d archive file(s) + %d live events, intact\n",
				len(archives), len(events))
			return 0
		}
		fmt.Fprintf(stdout, "audit chain verified: %d events, intact\n", len(events))
		return 0
	case "repair":
		// Finish an archive run that died between recording the anchor and
		// removing the rows it covers. Safe because the archive file was
		// written, read back and verified before the anchor was ever written.
		n, err := audit.Repair(context.Background(), as)
		if err != nil {
			fmt.Fprintln(stderr, "audit:", err)
			return 1
		}
		if n == 0 {
			fmt.Fprintln(stdout, "audit: nothing to repair")
			return 0
		}
		fmt.Fprintf(stdout, "audit: repaired an interrupted archive; removed %d row(s)\n", n)
		return 0
	case "archive":
		res, err := audit.Archive(context.Background(), as, archiveDir(cfg.DataDir), throughSeq, nil)
		if err != nil {
			fmt.Fprintln(stderr, "audit:", err)
			return 1
		}
		if res.Archived == 0 {
			fmt.Fprintln(stdout, "audit: nothing to archive")
			return 0
		}
		fmt.Fprintf(stdout, "archived %d events through seq %d to %s\n", res.Archived, res.Through, res.Path)
		return 0
	case "export":
		if err := audit.ExportJSONL(stdout, events); err != nil {
			fmt.Fprintln(stderr, "audit:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway audit <verify|export|archive|repair> [flags]")
		return 2
	}
}

// archiveDir is where audit archives live: beside the store, so a backup that
// copies the data directory copies the chain's history with it.
func archiveDir(dataDir string) string { return filepath.Join(dataDir, "audit") }

// archiveFiles lists the archive segments in seq order — the filenames are
// zero-padded, so lexical order is chain order.
func archiveFiles(dataDir string) []string {
	matches, err := filepath.Glob(filepath.Join(archiveDir(dataDir), "audit-*.jsonl"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

func runErr(err error, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return 1
	}
	return 0
}

func migrate(args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("migrate", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	// SPEC §12.1: offline command — refuse while the node holds the lock.
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	defer lock.Release()

	s, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		fmt.Fprintln(stderr, "migrate:", err)
		return 1
	}
	fmt.Fprintln(stdout, "migrations applied")
	return 0
}

func openStore(cfg *core.Config) (store.Store, error) {
	switch cfg.StoreEngine {
	case "postgres":
		return store.OpenPostgres(context.Background(), cfg.PostgresDSN)
	default:
		return store.OpenSQLite(filepath.Join(cfg.DataDir, "pact.db"))
	}
}

// healthcheck probes the internal listener's /healthz; the container HEALTHCHECK
// runs this (distroless has no shell or curl). Exit 0 iff healthy.
func healthcheck(args []string, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("healthcheck", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + cfg.InternalBind + "/healthz")
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "healthcheck: status", resp.Status)
		return 1
	}
	return 0
}

func doctor(args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("doctor", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := 0
	report := func(name string, err error) {
		if err != nil {
			fmt.Fprintf(stdout, "FAIL %-12s %v\n", name, err)
			fail = 1
			return
		}
		fmt.Fprintf(stdout, "ok   %s\n", name)
	}

	cfg, err := loadConfig(cfgPath)
	report("config", err)
	if cfg == nil {
		return 1
	}
	_, statErr := os.Stat(cfg.DataDir)
	report("data-dir", statErr)

	if lock, err := core.AcquireLock(cfg.DataDir); err != nil {
		// A held lock means a node is serving — report, don't fail.
		fmt.Fprintln(stdout, "ok   lock         held (node appears to be running)")
		var pong map[string]string
		report("admin-sock", core.AdminCall(core.AdminSocketPath(cfg.DataDir), "ping", nil, &pong))
	} else {
		lock.Release()
		fmt.Fprintln(stdout, "ok   lock         free (node not running)")
	}

	var pin string
	if statErr == nil {
		s, err := openStore(cfg)
		report("store-open", err)
		if err == nil {
			if accts, err := s.ListAccounts(context.Background()); err == nil && len(accts) > 0 {
				pin = accts[0].Fingerprint
				// PACT 2.0 (PACT §2): a host asks for renewal thirty days ahead;
				// doctor is where an operator without the portal hears it.
				idm := &identity.Manager{Store: s}
				for _, a := range accts {
					if a.Protocol != 2 {
						continue
					}
					info, cerr := idm.Certificate(context.Background(), a.ID, time.Now())
					switch {
					case cerr != nil:
						fmt.Fprintf(stdout, "FAIL leaf         %s: %v\n", a.Slug, cerr)
						fail = 1
					case info.RenewalDue:
						fmt.Fprintf(stdout, "warn leaf         %s expires %s: renewal due (run `account csr -slug %s -purpose renew`)\n", a.Slug, info.NotAfter.Format("2006-01-02"), a.Slug)
					default:
						fmt.Fprintf(stdout, "ok   leaf         %s valid until %s (root %s)\n", a.Slug, info.NotAfter.Format("2006-01-02"), info.RootFingerprint)
					}
				}
			}
			s.Close()
		}
	}

	// tunnel + reachability (SPEC §10.4): mode is derived, so say what it derived
	name := cfg.Tunnel
	if name == "" {
		name = "direct"
	}
	fmt.Fprintf(stdout, "ok   tunnel       %s (mode %s, seal %s, client_cert %s)\n", name, cfg.Mode, cfg.Seal, cfg.ClientCert)
	if cfg.PublicURL == "" {
		fmt.Fprintln(stdout, "warn probe        skipped: public_url not configured")
		return fail
	}
	if cfg.Mode == core.ModeEdge {
		pin = "" // the edge's WebPKI certificate is what peers see
	}
	res := tunnel.Probe(context.Background(), cfg.PublicURL, tunnel.ProbeOptions{
		PinnedFingerprint: pin, Timeout: 5 * time.Second, SelfOriginated: true,
	})
	switch res.Verdict {
	case tunnel.VerdictReachable:
		fmt.Fprintf(stdout, "ok   probe        %s reachable (%s)\n", cfg.PublicURL, res.Caveat)
	default:
		fmt.Fprintf(stdout, "FAIL probe        %s %s: %s\n", cfg.PublicURL, res.Verdict, res.Detail)
		fail = 1
	}
	return fail
}
