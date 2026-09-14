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
		// hold the agents that called IN; it can never reach out, and
		// relay-assisted delivery cannot be set up at all (E16).
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
			rows, err := st.ListAuditEvents(ctx, actorFilter)
			if err != nil {
				return nil, err
			}
			// Scope first, then cap: capping first would hand back fewer rows
			// than asked for whenever an unreadable row occupied the window.
			kept := rows[:0]
			for _, r := range rows {
				if permit == nil || permit(r.AccountID) {
					kept = append(kept, r)
				}
			}
			rows = kept
			// newest first, capped
			if len(rows) > limit {
				rows = rows[len(rows)-limit:]
			}
			return rows, nil
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
