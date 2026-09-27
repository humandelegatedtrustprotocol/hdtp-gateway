package cli

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/node"
	"github.com/pact-cloud/pact-gateway/internal/services/settings"
)

// registerAdminHandlers registers the admin socket's commands (SPEC §12.1): the account, passkey
// and token commands the CLI sends to a running node. They are registered before the node and the
// audit sink exist and run only after both do, so each reads s.nd and s.auditFn when it runs.
func (s *serveRun) registerAdminHandlers() {
	ctx, st, cfg, idm, admin, setup := s.ctx, s.st, s.cfg, s.idm, s.admin, s.setup
	admin.Handle("ping", func(map[string]string) (any, error) {
		return map[string]string{"status": "serving"}, nil
	})
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
		if s.nd != nil {
			return identity.EndpointFor(s.nd.PublicURL(), slug)
		}
		return identity.EndpointFor(cfg.PublicURL, slug)
	}
	leaves := s.leafService(idm, endpointFor)
	s.leaves = leaves
	csrFor := func(acct store.Account, purpose, endpoint string) (map[string]any, error) {
		res, err := leaves.Mint(ctx, acct, purpose, endpoint, "")
		if err != nil {
			return nil, err
		}
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
		if s.nd != nil {
			if aerr := s.nd.AdoptAccount(ctx, acct.ID); aerr != nil && !errors.Is(aerr, node.ErrAwaitingLeaf) {
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
		res, err := leaves.Install(ctx, acct, chain, "")
		if err != nil {
			return nil, err
		}
		out := map[string]any{
			"Slug": acct.Slug, "Root": res.RootFingerprint, "Kid": res.Kid, "Endpoint": res.Endpoint,
			"NotAfter": res.NotAfter.UTC().Format(time.RFC3339), "First": res.FirstInstall, "KeyChanged": res.KeyChanged,
		}
		if len(res.Retired) > 0 {
			out["Retired"] = res.Retired
		}
		if res.Campaign {
			out["Campaigns"] = "started; `pact-gateway account announce -slug " + acct.Slug + "` reports and resumes them"
		}
		if res.Notice != "" {
			out["Notice"] = res.Notice
		}
		return out, nil
	})
	// account.announce reports the campaign an install starts — the move's update_contact walk —
	// for the current leaf, and resumes it if contacts are still waiting and no walk is running.
	//
	// It REPORTS THE LEDGER and returns. It used to run the walk and answer when the walk ended:
	// 17 seconds for one unreachable contact on the container harness, more for each further one,
	// out of the thirty the admin socket gives a command — and beside the walk the install had
	// started, not instead of it (internal/node/campaign.go).
	admin.Handle("account.announce", func(args map[string]string) (any, error) {
		if args["slug"] == "" {
			return nil, fmt.Errorf("account.announce needs slug")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		if !acct.HasRoot() || s.nd == nil {
			return nil, fmt.Errorf("account.announce: %s has no certificate yet, or the node is not running", acct.Slug)
		}
		before, err := s.nd.MoveProgress(ctx, acct.ID, acct.Fingerprint)
		if err != nil {
			return nil, err
		}
		resumed := before.Waiting > 0 && s.nd.ResumeMove(ctx, acct.ID, acct.Fingerprint)
		return map[string]any{
			"Slug": acct.Slug, "Told": before.Told, "Waiting": before.Waiting,
			"Walking": before.Walking || resumed, "Resumed": resumed, "Unreached": before.Unreached,
			"NoLeaf": before.NoLeaf,
		}, nil
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
			"Slug": acct.Slug, "Certified": info.Certified, "Root": info.RootFingerprint, "Kid": info.Kid, "Endpoint": info.Endpoint,
			"RenewalDue": info.RenewalDue, "PendingCSR": info.PendingCSR, "Superseded": info.Superseded, "Former": info.Former,
		}
		if info.Certified {
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
		// The one decision the portal and the owner MCP also make (contacts.Owner.DecideAddress).
		o := contacts.Owner{Manager: &contacts.Manager{Store: st}, Invalidate: func(ctx context.Context, accountID, fpr string) error {
			if s.nd == nil {
				return nil
			}
			return s.nd.Invalidate(ctx, accountID, fpr)
		}}
		p, err := o.DecideAddress(ctx, acct.ID, args["root"], args["decision"] == "approve")
		if err != nil {
			return nil, err
		}
		s.auditFn("contact_address_"+args["decision"], "account:"+acct.ID+" contact:"+args["root"]+" endpoint:"+p.Endpoint, "ok")
		return map[string]any{"Slug": acct.Slug, "Root": args["root"], "Endpoint": p.Endpoint, "Decision": args["decision"]}, nil
	})
	// account.host_policy is the owner's PACT §5.3 choice for one identity: what happens when a
	// pinned contact turns up at a new address. `auto` follows a leaf the contact's own root
	// signed; `ask` parks it until the owner decides (`account address`). The node has always read
	// this setting and honoured it, and until 2026-09-19 NOTHING could set it: the store method
	// was called from tests and from nowhere else, so `ask` was unreachable through the shipped
	// binary and every test proving the `ask` flow proved something no owner could turn on.
	admin.Handle("account.host_policy", func(args map[string]string) (any, error) {
		if args["slug"] == "" {
			return nil, fmt.Errorf("account.host_policy needs slug")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		if args["policy"] == "" {
			return map[string]any{"Slug": acct.Slug, "Policy": acct.AcceptNewHosts}, nil
		}
		if args["policy"] != "auto" && args["policy"] != "ask" {
			return nil, fmt.Errorf("account.host_policy: policy is auto or ask, not %q", args["policy"])
		}
		if err := st.SetAccountHostPolicy(ctx, acct.ID, args["policy"]); err != nil {
			return nil, err
		}
		s.auditFn("settings_accept_new_hosts", "account:"+acct.ID+" policy:"+args["policy"], "ok")
		return map[string]any{"Slug": acct.Slug, "Policy": args["policy"]}, nil
	})
	// account.leave is the person leaving this host (PACT §9, "What a host must do when the person
	// leaves"): every record of the identity and every leaf key it held are erased at once, the
	// live node forgets it so its address answers as one never served, and the address stays
	// reserved until the last leaf issued for it expires. It is on the admin socket only, like
	// `import`: shell access on the host is its authorisation, and no portal or owner-MCP door has
	// it (a named divergence: README "Leave this node", SPEC.md §3.11).
	admin.Handle("account.leave", func(args map[string]string) (any, error) {
		if args["slug"] == "" {
			return nil, fmt.Errorf("account.leave needs slug")
		}
		acct, err := accountBySlug(args["slug"])
		if err != nil {
			return nil, err
		}
		// A move campaign that is walking holds the account's key and writes its rows; erasing
		// them under it would leave the walk failing against records that are gone.
		if s.nd != nil && s.nd.MoveWalking(acct.ID) {
			s.auditFn("account_leave", "account:"+acct.ID+" slug:"+acct.Slug+" reason:campaign_walking", "refused")
			return nil, fmt.Errorf("account.leave: %s is telling its contacts of a move right now; run `account announce -slug %s` until it has finished, then leave", acct.Slug, acct.Slug)
		}
		res, err := idm.Leave(ctx, acct.ID, settings.AccountKeys(acct.ID), messaging.BlobDir{Root: filepath.Join(cfg.DataDir, "blobs")}.Remove, time.Now())
		if err != nil && res.AccountID == "" {
			s.auditFn("account_leave", "account:"+acct.ID+" slug:"+acct.Slug, "error")
			return nil, err
		}
		// The records are gone from here on, whatever the media files did.
		if s.nd != nil {
			s.nd.ForgetAccount(acct.ID, acct.Slug)
		}
		reserved := make([]map[string]any, 0, len(res.Vacated))
		for _, v := range res.Vacated {
			reserved = append(reserved, map[string]any{"Endpoint": v.Endpoint, "Until": time.Unix(v.UntilAt, 0).UTC().Format(time.RFC3339)})
		}
		erased := " leaves:" + strconv.Itoa(res.Leaves) + " reserved:" + strconv.Itoa(len(res.Vacated)) + " media:" + strconv.Itoa(res.BlobsRemoved)
		out := map[string]any{"Slug": acct.Slug, "Leaves": res.Leaves, "Reserved": reserved, "MediaRemoved": res.BlobsRemoved}
		if err != nil {
			// Erased, with media files left on disk that no record refers to any more.
			s.auditFn("account_leave", "account:"+acct.ID+" slug:"+acct.Slug+erased, "partial")
			out["Warning"] = err.Error()
			return out, nil
		}
		s.auditFn("account_leave", "account:"+acct.ID+" slug:"+acct.Slug+erased, "ok")
		return out, nil
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
	s.authSvc = auth.New(st)
	authSvc := s.authSvc
	admin.Handle("passkey.list", func(map[string]string) (any, error) {
		return authSvc.ListPasskeys(ctx)
	})
	admin.Handle("passkey.remove", func(args map[string]string) (any, error) {
		if args["id"] == "" {
			return nil, fmt.Errorf("passkey.remove needs id")
		}
		return "removed", authSvc.RemovePasskey(ctx, args["id"])
	})
	s.tokSvc = &auth.TokenService{Store: st}
	tokSvc := s.tokSvc
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
}
