package cli

// What the SPEC §8.4/§8.6 owner-MCP tools need from outside their package: the
// node's card renderer, its outbound path, the passkey service and the audit
// chain. Assembling it here keeps `ownermcp` free of those dependencies.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
	"github.com/tech-sumit/pact-gateway/internal/internalui/ownermcp"
	"github.com/tech-sumit/pact-gateway/internal/node"
)

func ownerExtra(nd *node.Node, st store.Store, authSvc *auth.Service, chain *integrationChain,
	auditFn func(action, resource, outcome string)) ownermcp.Extra {

	return ownermcp.Extra{
		Integrations: func(ctx context.Context, accountID string) ([]ownermcp.IntegrationView, error) {
			list, err := st.ListIntegrations(ctx, accountID)
			if err != nil {
				return nil, err
			}
			out := make([]ownermcp.IntegrationView, 0, len(list))
			for _, in := range list {
				v := ownermcp.IntegrationView{ID: in.ID, Slug: in.Slug, Status: in.Status, Auth: in.AuthKind}
				// What is EXPOSED, not what the upstream offers: an agent has no
				// business seeing a catalog the owner has not published (§6).
				if entries, err := chain.Exposures.AllEntries(ctx, in.ID); err == nil {
					for _, en := range entries {
						if en.Stale {
							v.Stale = append(v.Stale, en.ExposedName)
							continue
						}
						v.Exposed = append(v.Exposed, en.ExposedName)
					}
				}
				out = append(out, v)
			}
			return out, nil
		},

		SetExposure: func(ctx context.Context, accountID, integrationID string, tools []string) error {
			// The owner's agent names UPSTREAM tools; the exposed names and the
			// confirmed hashes come from the bound snapshot, so an agent cannot
			// smuggle in a name or a hash of its own.
			cat, err := st.LatestCatalog(ctx, integrationID)
			if err != nil {
				return err
			}
			var defs []integrations.ToolDef
			if err := json.Unmarshal([]byte(cat.Tools), &defs); err != nil {
				return err
			}
			byName := map[string]integrations.ToolDef{}
			for _, d := range defs {
				byName[d.Name] = d
			}
			in, err := st.GetIntegrationByID(ctx, integrationID)
			if err != nil {
				return err
			}
			// The caller was authorized for `accountID`; this integration must
			// actually be that account's. Without this a token scoped to one
			// account could name its own account and another account's
			// integration, and republish — or withdraw — that account's entire
			// served surface.
			if in.AccountID != accountID {
				auditFn("set_exposure", "integration:"+integrationID, "permission_denied")
				return fmt.Errorf("that integration belongs to another account")
			}
			entries := make([]integrations.ExposureEntry, 0, len(tools))
			for _, t := range tools {
				d, ok := byName[t]
				if !ok {
					return fmt.Errorf("%s does not offer a tool called %q", in.Slug, t)
				}
				entries = append(entries, integrations.ExposureEntry{
					Tool: d.Name, Mode: integrations.ModePassthrough,
					ExposedName: integrations.SnakeName(in.Slug + "_" + d.Name), ConfirmedHash: d.Hash,
				})
			}
			_, err = chain.Exposures.Publish(ctx, integrationID, entries)
			return err
		},
		Card: nd.Card,
		// SPEC §9's `none --> pending_out`. Without this the node can only ever
		// hold the agents that called IN; it can never reach out (E16).
		AddContact: func(ctx context.Context, accountID, inviteURL, card, note, grant string) (ownermcp.AddContactResult, error) {
			ci := newContactInitiator(st, nd, auditFn)
			var res addContactResult
			var err error
			if inviteURL != "" {
				res, err = ci.RedeemInvite(ctx, accountID, inviteURL, grant)
			} else {
				res, err = ci.RequestContact(ctx, accountID, card, note)
			}
			if err != nil {
				return ownermcp.AddContactResult{}, err
			}
			return ownermcp.AddContactResult(res), nil
		},
		Passkeys:      authSvc.ListPasskeys,
		RemovePasskey: authSvc.RemovePasskey,
		// A bearer token acted, which is not the same as the owner at the
		// portal — the chain distinguishes them (SPEC §11).
		Log: func(action, resource, outcome string) { auditFn(action, resource, outcome) },

		Audit: func(ctx context.Context, actorFilter string, limit int, permit func(string) bool) ([]store.AuditRow, error) {
			return auditPageFor(ctx, st, actorFilter, limit, permit)
		},

		// One definition of "call a contact", on the node, shared with the portal.
		CallContact: nd.CallContact,
		// The same certificate reader the portal's identity page uses.
		Certificate: nd.CertificateInfo,
	}
}

// newCallID mints an idempotency key for an owner-initiated call that carries
// none. A sealed envelope is deduplicated on `msg_id` (§4.4 step 8), so one is
// required; leaving it empty would make every retry look like the same call.
func newCallID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "call-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "call-" + hex.EncodeToString(b)
}

// auditPageFor is the newest `limit` rows of the trail that `permit` lets this caller read, oldest
// of them first.
//
// It asks the store for a PAGE per account the caller may read. It used to ask for the whole chain
// and cut it down here, which on a node with a long history was every row of the trail, in memory,
// on every call of `audit_query` — a read that is bounded by design everywhere else.
//
// A page for an account also carries the node's own rows, which belong to no account. A caller
// scoped to some accounts may not see those (`permit("")` is false), so they are dropped here —
// and a page made mostly of them would then come back short although older rows exist. So the
// page grows until enough rows survive, or until the store has no more to give.
func auditPageFor(ctx context.Context, st store.Store, actor string, limit int, permit func(string) bool) ([]store.AuditRow, error) {
	if permit == nil {
		permit = func(string) bool { return true }
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	// No account yet: the node's own rows are all there is, and "-" is no account's id.
	scope := []string{}
	for _, a := range accounts {
		if permit(a.ID) {
			scope = append(scope, a.ID)
		}
	}
	if len(scope) == 0 && permit("") {
		scope = []string{"-"}
	}
	const mostPages = 6 // limit x 4^5: past this a caller is asking for a needle, and gets what was found
	var rows []store.AuditRow
	for page, tries := limit, 0; tries < mostPages; page, tries = page*4, tries+1 {
		rows = rows[:0]
		seen := map[int64]bool{}
		exhausted := true
		for _, id := range scope {
			part, err := st.ListAuditEventsPage(ctx, store.AuditPage{Actor: actor, Account: id, Limit: page})
			if err != nil {
				return nil, err
			}
			if len(part) == page {
				exhausted = false
			}
			for _, r := range part {
				if !seen[r.Seq] && permit(r.AccountID) {
					seen[r.Seq] = true
					rows = append(rows, r)
				}
			}
		}
		if len(rows) >= limit || exhausted {
			break
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Seq < rows[j].Seq })
	if len(rows) > limit {
		rows = rows[len(rows)-limit:]
	}
	return rows, nil
}
