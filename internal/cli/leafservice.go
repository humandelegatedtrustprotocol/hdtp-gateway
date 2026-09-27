package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/node"
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
	node        func() *node.Node
	audit       func(action, resource, outcome string)
	endpointFor func(slug string) string
}

func (s *serveRun) leafService(idm *identity.Manager, endpointFor func(string) string) leafService {
	return leafService{
		idm: idm, endpointFor: endpointFor,
		node:  func() *node.Node { return s.nd },
		audit: func(action, resource, outcome string) { s.auditFn(action, resource, outcome) },
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
	if err != nil {
		return identity.CSRResult{}, err
	}
	if walletOrigin != "" {
		l.audit("account_csr", "account:"+acct.ID+" slug:"+acct.Slug+" purpose:"+purpose+" endpoint:"+endpoint+" key:"+res.Kid+" wallet_origin:"+walletOrigin, "ok")
	} else {
		l.audit("account_csr", "account:"+acct.ID+" slug:"+acct.Slug+" purpose:"+purpose+" endpoint:"+endpoint+" key:"+res.Kid, "ok")
	}
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
	// One row for the install: `partial` when the leaf is installed and something after it was not
	// finished, each thing named.
	detail, outcome := " root:"+res.RootFingerprint+" key:"+res.Kid+" endpoint:"+res.Endpoint, "ok"
	if state != "" {
		detail += " via:wallet"
	}
	for _, w := range res.Warnings {
		detail, outcome = detail+" warning:"+w, "partial"
	}
	l.audit("account_leaf_install", "account:"+acct.ID+" slug:"+acct.Slug+detail, outcome)
	// Key material was destroyed, so the chain says so, once per key: a superseded leaf whose
	// key this node could no longer open (its master key is not the one that sealed it).
	for _, kid := range res.Retired {
		l.audit("account_leaf_key_retired", "account:"+acct.ID+" slug:"+acct.Slug+" key:"+kid+" reason:unopenable", "ok")
	}
	out := installed{InstallResult: res, Notice: identity.MoveNotice(res)}
	nd := l.node()
	// The node loaded the account's key and certificate when it started; the install changed both
	// in the store. Rebuild it live.
	if nd != nil {
		if aerr := nd.AdoptAccount(ctx, acct.ID); aerr != nil {
			return out, fmt.Errorf("install: reloading the account on the live node: %w", aerr)
		}
	}
	// The campaign an install can start — the move's update_contact toward contacts pinned by
	// our root (PACT §5.3, §9) — runs DETACHED (node.ResumeMove): an unreachable contact holds
	// the walk until the call gives up, and the leaf is already installed. The install is the
	// durable part and it answers now; the walk is durable too (`move_fanout`), and
	// `account announce` reports it and resumes it.
	//
	// Whether it moved is the install's to say (identity.InstallResult.Moved). An import also
	// leaves contacts owed this host's handshake (PACT §9.2), and they are owed it after the next
	// leaf whether or not that leaf moved the identity (identity.InstallResult.HandshakesDue).
	if (res.Moved || res.HandshakesDue > 0) && nd != nil {
		nd.ResumeMove(ctx, acct.ID, res.Kid)
		out.Campaign = true
	}
	return out, nil
}
