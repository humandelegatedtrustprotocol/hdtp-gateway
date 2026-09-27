package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
)

// leafService is the one implementation of an identity's signing request and of installing the
// wallet's answer (PACT §9, §9.1). The admin socket (`account csr`, `account create`,
// `account install-leaf`) and the portal's web-wallet pages (internalui/wallet_pages.go) both call
// it, so the audit rows, the live node's reload and the move campaign cannot differ between them.
//
// It is built before the node and the audit sink exist (registerAdminHandlers runs first), so both
// are read when a call runs, never captured.
type leafService struct {
	idm         *identity.Manager
	audit       func(action, resource, outcome string)
	endpointFor func(slug string) string
	// adopt reloads an account on the live node and resume starts its campaign there; both are
	// nil while no node is running. They are the node's AdoptAccount and ResumeMove.
	adopt  func(ctx context.Context, accountID string) error
	resume func(ctx context.Context, accountID, kid string) bool
}

func (s *serveRun) leafService(idm *identity.Manager, endpointFor func(string) string) leafService {
	return leafService{
		idm: idm, endpointFor: endpointFor,
		audit: func(action, resource, outcome string) { s.auditFn(action, resource, outcome) },
		adopt: func(ctx context.Context, accountID string) error {
			if s.nd == nil {
				return nil
			}
			return s.nd.AdoptAccount(ctx, accountID)
		},
		resume: func(ctx context.Context, accountID, kid string) bool {
			return s.nd != nil && s.nd.ResumeMove(ctx, accountID, kid)
		},
	}
}

// actingFor is the same service auditing through another sink: the portal's door records the
// owner as the actor (the audit log's Owner sink), the admin socket the node's own (System).
func (l leafService) actingFor(audit func(action, resource, outcome string)) leafService {
	l.audit = audit
	return l
}

// Mint makes the pending request. `walletOrigin` is "" for a request handed over by the CLI, and the
// origin of the web wallet it is sent to otherwise; it is audited either way (account_csr).
func (l leafService) Mint(ctx context.Context, acct store.Account, purpose, endpoint, walletOrigin string) (identity.CSRResult, error) {
	if purpose == "" {
		purpose = identity.PurposeRenew
		if !acct.HasRoot() {
			purpose = identity.PurposeSignup
		}
	}
	if endpoint == "" {
		endpoint = l.endpointFor(acct.Slug)
	}
	if endpoint == "" {
		return identity.CSRResult{}, fmt.Errorf("account.csr: no public URL is configured; pass -endpoint")
	}
	var res identity.CSRResult
	var err error
	if walletOrigin == "" {
		res, err = l.idm.IssueCSR(ctx, acct.ID, purpose, endpoint, time.Now())
	} else {
		res, err = l.idm.IssueWalletCSR(ctx, acct.ID, purpose, endpoint, walletOrigin, time.Now())
	}
	via := ""
	if walletOrigin != "" {
		via = " wallet_origin:" + walletOrigin
	}
	if err != nil {
		// A request that was not made is audited too, on either door: `refused` when the request
		// itself is not one this node makes (a purpose, an address), `error` when this node failed.
		// The reason is a code, never the error's text.
		outcome, reason := "error", "failed"
		switch {
		case errors.Is(err, store.ErrAddressVacated):
			outcome, reason = "refused", "vacated"
		case errors.Is(err, identity.ErrEndpointRefused):
			outcome, reason = "refused", "address"
		case errors.Is(err, identity.ErrLeafRefused):
			outcome, reason = "refused", "purpose"
		}
		l.audit("account_csr", "account:"+acct.ID+" slug:"+acct.Slug+" purpose:"+purpose+" endpoint:"+endpoint+via+" reason:"+reason, outcome)
		return identity.CSRResult{}, err
	}
	detail, outcome := " purpose:"+purpose+" endpoint:"+endpoint+" key:"+res.Kid+via, "ok"
	for _, w := range res.Warnings {
		detail, outcome = detail+" warning:"+w.Code, "partial"
	}
	l.audit("account_csr", "account:"+acct.ID+" slug:"+acct.Slug+detail, outcome)
	return res, nil
}

// installed is what an install did, for either door to report.
type installed struct {
	identity.InstallResult
	// Campaign is set when the install moved the identity, or left imported contacts owed the
	// handshake, and the node started telling its contacts (node.ResumeMove).
	Campaign bool
	// Notice is the move notice (identity.MoveNotice), "" when the identity did not move.
	Notice string
	// Warnings are what was not finished although the leaf is installed (identity's own, and a
	// live node that could not reload the account). Each door shows them; the install stands.
	Warnings []identity.Warning
}

// Install installs the wallet's answer. `state` is "" for the CLI's `install-leaf -chain FILE`, and
// the request's state for a web wallet's answer, which is then accepted once (PACT §9.1). A refused
// answer is audited as account_leaf_install_refused with the reason; a failure of this host as
// account_leaf_install `error`.
func (l leafService) Install(ctx context.Context, acct store.Account, chain [][]byte, state string) (installed, error) {
	var res identity.InstallResult
	var err error
	if state == "" {
		res, err = l.idm.InstallLeaf(ctx, acct.ID, chain, time.Now())
	} else {
		res, err = l.idm.InstallWalletLeaf(ctx, acct.ID, chain, state, time.Now())
	}
	switch {
	case errors.Is(err, identity.ErrRequestState):
		l.audit("account_leaf_install_refused", "account:"+acct.ID+" slug:"+acct.Slug+" reason:state", "refused")
		return installed{}, err
	case errors.Is(err, identity.ErrLeafRefused):
		l.audit("account_leaf_install_refused", "account:"+acct.ID+" slug:"+acct.Slug+" reason:chain", "refused")
		return installed{}, err
	case err != nil:
		l.audit("account_leaf_install", "account:"+acct.ID+" slug:"+acct.Slug, "error")
		return installed{}, err
	}
	// Key material was destroyed, so the chain says so, once per key: a superseded leaf whose
	// key this node could no longer open (its master key is not the one that sealed it).
	for _, kid := range res.Retired {
		l.audit("account_leaf_key_retired", "account:"+acct.ID+" slug:"+acct.Slug+" key:"+kid+" reason:unopenable", "ok")
	}
	out := installed{InstallResult: res, Notice: identity.MoveNotice(res), Warnings: append([]identity.Warning(nil), res.Warnings...)}
	// The node loaded the account's key and certificate when it started; the install changed both
	// in the store. Rebuild it live. The install is committed whatever this does: a node that could
	// not reload is a warning with what to do, never a failed install (the wallet's answer is used,
	// and asking the person to sign again would change nothing).
	adopted := true
	if l.adopt != nil {
		if aerr := l.adopt(ctx, acct.ID); aerr != nil {
			adopted = false
			out.Warnings = append(out.Warnings, identity.Warning{Code: "not_loaded",
				Text: "the leaf is installed and the running node could not load it; restart the node, then run `account announce -slug " + acct.Slug + "`"})
		}
	}
	// One row for the install: `partial` when the leaf is installed and something after it was not
	// finished, each thing named.
	detail, outcome := " root:"+res.RootFingerprint+" key:"+res.Kid+" endpoint:"+res.Endpoint, "ok"
	if state != "" {
		detail += " via:wallet"
	}
	for _, w := range out.Warnings {
		detail, outcome = detail+" warning:"+w.Code, "partial"
	}
	l.audit("account_leaf_install", "account:"+acct.ID+" slug:"+acct.Slug+detail, outcome)
	// The campaign an install can start — the move's update_contact toward contacts pinned by
	// our root (PACT §5.3, §9) — runs DETACHED (node.ResumeMove): an unreachable contact holds
	// the walk until the call gives up, and the leaf is already installed. The install is the
	// durable part and it answers now; the walk is durable too (`move_fanout`), and
	// `account announce` reports it and resumes it.
	//
	// Whether it moved is the install's to say (identity.InstallResult.Moved). An import also
	// leaves contacts owed this host's handshake (PACT §9.2), and they are owed it after the next
	// leaf whether or not that leaf moved the identity (identity.InstallResult.HandshakesDue).
	//
	// Not when the node could not load the account: it would announce the card it still holds,
	// the old leaf's. The warning says to restart and announce.
	if (res.Moved || res.HandshakesDue > 0) && adopted && l.resume != nil {
		l.resume(ctx, acct.ID, res.Kid)
		out.Campaign = true
	}
	return out, nil
}

// warningTexts is what a door shows of a request's or an install's warnings.
func warningTexts(ws []identity.Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Text)
	}
	return out
}
