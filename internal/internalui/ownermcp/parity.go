package ownermcp

// The owner-MCP tools SPEC §8.4 names and §8.6 requires, which the server did
// not register: `audit_query`, `call_contact`, `export_card`, and the passkey
// pair.
//
// One boundary shapes this file. SPEC §8.6 allows an owner-MCP session to LIST
// and REMOVE passkeys but never to register one: a bearer token cannot perform a
// WebAuthn ceremony, and keeping creation portal-only guarantees a token can
// never mint a durable credential for itself. So `list_passkeys` and
// `remove_passkey` exist here and `register_passkey` deliberately does not.
//
// `call_contact` is the tool with teeth: it lets the owner's agent make a call
// to a contact. It does not get its own path to the wire — it goes through the
// same outbound client a portal-initiated call uses, and the peer applies its
// own switchboard, so this cannot reach anything the contact has not granted.
// The sender label is `agent` and is set here, never taken from the caller
// (SPEC §7.3).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Extra is what the parity tools need beyond Deps. Each is optional: a nil field
// means that tool is not registered, which is how a node that cannot serve a
// capability says so rather than failing at call time.
type Extra struct {
	// Card renders an account's current card — the same one peers receive.
	Card func(ctx context.Context, accountID string) (string, error)
	// Certificate reports the account's certificate state (§14): the root
	// that is the identity, the leaf this host serves under, its dates, and
	// whether a renewal is due. Nil omits the tool, which is what a node with no
	// account wants.
	Certificate func(ctx context.Context, accountID string) (identity.CertificateInfo, error)
	// Passkeys lists and removes registered passkeys (§8.6). Registration is
	// deliberately absent.
	Passkeys      func(ctx context.Context) ([]auth.PasskeyInfo, error)
	RemovePasskey func(ctx context.Context, id string) error
	// CallContact performs one permitted call to a contact on the owner's
	// behalf, through the ordinary outbound path.
	CallContact func(ctx context.Context, accountID, contactFpr, tool string, args map[string]any) (string, error)
	// Audit reads the audit chain (§11.6: owner-visible only). `permit` decides
	// which accounts' rows this caller may see, and is applied BEFORE the limit
	// truncates — filtering afterwards would silently return fewer rows than
	// asked for whenever a row the caller cannot see got there first.
	Audit func(ctx context.Context, actorFilter string, limit int, permit func(accountID string) bool) ([]store.AuditRow, error)
	// Log records a mutation. Owner-MCP actions are `token`-attributed: a bearer
	// token acted, which is not the same as the owner sitting at the portal.
	Log func(action, resource, outcome string)
	// Integrations serves §8.4's "integration management" row: what is
	// connected, and what each one currently exposes. Nil omits the tools.
	Integrations func(ctx context.Context, accountID string) ([]IntegrationView, error)
	// SetExposure republishes an integration's exposure set (§6.5). It takes the
	// ACCOUNT as well as the integration, and must refuse when the integration
	// does not belong to it: authorizing the account the caller NAMES while
	// acting on an integration id they also supply is not authorization at all.
	SetExposure func(ctx context.Context, accountID, integrationID string, tools []string) error
	// AddContact is the OWNER-initiated half of contact establishment (SPEC §9's
	// `none --> pending_out`): redeem somebody's invite link, or ask to be added
	// using a card received out of band. Exactly one of inviteURL / card is
	// given. Without it a node can only ever hold the agents that called IN, and
	// can never reach out.
	AddContact func(ctx context.Context, accountID, inviteURL, card, note, grant string) (AddContactResult, error)
}

// AddContactResult is what the owner learns from an initiated contact.
type AddContactResult struct {
	Fingerprint string   `json:"fingerprint"`
	DisplayName string   `json:"display_name,omitempty"`
	Status      string   `json:"status"` // active | pending_out
	Permissions []string `json:"permissions,omitempty"`
}

// IntegrationView is what an agent may see about an upstream. It deliberately
// carries no credential, no endpoint secret and no raw upstream schema: an
// agent needs to know what is connected and what is exposed, not how to reach
// it directly (SPEC §6.3).
type IntegrationView struct {
	ID      string   `json:"id"`
	Slug    string   `json:"slug"`
	Status  string   `json:"status"`
	Auth    string   `json:"auth"`
	Exposed []string `json:"exposed"`
	Stale   []string `json:"stale,omitempty"`
}

func (e Extra) log(action, resource, outcome string) {
	if e.Log != nil {
		e.Log(action, resource, outcome)
	}
}

// AddParityTools registers the §8.4/§8.6 tools on an owner-MCP server.
func AddParityTools(s *mcp.Server, d Deps, e Extra, ident auth.Identity, allow func(ctx context.Context, accountID string) bool) {
	ot := ownerTools{d: d, e: e, ident: ident, allow: allow}
	if e.Card != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "export_card",
			Description: "This account's current signed contact card (vCard)"},
			ot.exportCardTool)
	}

	if e.Certificate != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "identity_certificate",
			Description: "This identity's certificate state (HDTP 1.0): the root that is the identity, the leaf this host serves under, its validity, and whether a renewal is due"},
			ot.identityCertificateTool)
	}

	if e.Passkeys != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "list_passkeys",
			Description: "Registered passkeys. Registering a new one is portal-only (SPEC §8.6)"},
			ot.listPasskeysTool)
	}

	if e.RemovePasskey != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "remove_passkey",
			Description: "Remove a registered passkey by id"},
			ot.removePasskeyTool)
	}

	if e.CallContact != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "call_contact",
			Description: "Call a tool on a contact's agent server. The contact's own switchboard still applies"},
			ot.callContactTool)
	}

	if e.Integrations != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "list_integrations",
			Description: "Connected upstreams and the tools each currently exposes (SPEC §6)"},
			ot.listIntegrationsTool)
	}

	if e.SetExposure != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "set_exposure",
			Description: "Republish which of an integration's tools are exposed to contacts (SPEC §6.5)"},
			ot.setExposureTool)
	}

	if e.AddContact != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "add_contact",
			Description: "Reach out to a peer: redeem their invite link, or request contact with a card " +
				"they gave you out of band (SPEC §9). Lands `pending_out` until they accept, or `active` " +
				"immediately if their invite auto-accepts."},
			ot.addContactTool)
	}

	if e.Audit != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "audit_query",
			Description: "Read the audit trail for the accounts you administer (SPEC §11.6)"},
			ot.auditQueryTool)
	}
}

// exportCardTool is the `export_card` tool.
func (ot ownerTools) exportCardTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	card, err := ot.e.Card(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	acct, err := ot.d.Store.GetAccountByID(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	// The card and what the owner reads it by, as the portal's card read answers them.
	facts, err := contacts.FactsOf(card, acct.Fingerprint)
	if err != nil {
		return nil, nil, err
	}
	r, err := jsonResult(facts)
	return r, nil, err
}

// identityCertificateTool is the `identity_certificate` tool.
func (ot ownerTools) identityCertificateTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	info, err := ot.e.Certificate(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{"certified": info.Certified}
	if info.Certified {
		chain := make([]string, 0, len(info.Chain))
		for _, c := range info.Chain {
			chain = append(chain, hdtpidentity.B64url(c))
		}
		out["root_fingerprint"], out["chain"] = info.RootFingerprint, chain
		if info.Served() {
			out["kid"], out["endpoint"] = info.Kid, info.Endpoint
			out["not_before"], out["not_after"] = info.NotBefore.UTC().Format(time.RFC3339), info.NotAfter.UTC().Format(time.RFC3339)
			out["renewal_due"] = info.RenewalDue
		}
		out["superseded"], out["former"] = info.Superseded, info.Former
		if info.PendingCSR != "" {
			out["pending_csr"] = info.PendingCSR
		}
	}
	r, err := jsonResult(out)
	return r, nil, err
}

// listPasskeysTool is the `list_passkeys` tool.
func (ot ownerTools) listPasskeysTool(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	list, err := ot.e.Passkeys(ctx)
	if err != nil {
		return nil, nil, err
	}
	r, err := jsonResult(list)
	return r, nil, err
}

// removePasskeyTool is the `remove_passkey` tool.
func (ot ownerTools) removePasskeyTool(ctx context.Context, req *mcp.CallToolRequest, a struct {
	ID string `json:"id" jsonschema:"the passkey id to remove"`
}) (*mcp.CallToolResult, any, error) {
	if a.ID == "" {
		r, err := jsonResult(map[string]string{"code": "bad_request"})
		return r, nil, err
	}
	// Removing the LAST passkey through an API would lock the owner
	// out of the portal with only the CLI left. The invariant is
	// enforced in auth.Service as one statement, so this surface and
	// the portal cannot race each other to zero.
	if err := ot.e.RemovePasskey(ctx, a.ID); err != nil {
		if errors.Is(err, auth.ErrLastPasskey) {
			ot.e.log("passkey_remove", "passkey:"+a.ID, "refused_last")
			r, jerr := jsonResult(map[string]string{
				"code": "bad_request",
				"detail": "that is the only passkey registered; " +
					"register another before removing it",
			})
			return r, nil, jerr
		}
		ot.e.log("passkey_remove", "passkey:"+a.ID, "error")
		return nil, nil, err
	}
	ot.e.log("passkey_remove", "passkey:"+a.ID, "ok")
	r, err := jsonResult(map[string]string{"status": "ok"})
	return r, nil, err
}

// callContactTool is the `call_contact` tool.
func (ot ownerTools) callContactTool(ctx context.Context, req *mcp.CallToolRequest, a struct {
	AccountID  string `json:"account_id" jsonschema:"the account to call from"`
	ContactFpr string `json:"contact_fpr" jsonschema:"the contact to call"`
	Tool       string `json:"tool" jsonschema:"the tool to invoke on their server"`
	// optional: a tool may legitimately take no arguments
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"arguments for that tool"`
}) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	if a.ContactFpr == "" || a.Tool == "" {
		r, err := jsonResult(map[string]string{"code": "bad_request"})
		return r, nil, err
	}
	// Only an ACTIVE contact can be called: a blocked or pending one
	// is not somebody this node reaches out to.
	c, err := ot.d.Store.GetContact(ctx, a.AccountID, a.ContactFpr)
	if err != nil || c.Status != "active" {
		ot.e.log("call_contact", "contact:"+a.ContactFpr, "unknown_contact")
		r, err := jsonResult(map[string]string{"code": "unknown_contact"})
		return r, nil, err
	}
	out, err := ot.e.CallContact(ctx, a.AccountID, a.ContactFpr, a.Tool, a.Arguments)
	if err != nil {
		ot.e.log("call_contact", "contact:"+a.ContactFpr+" tool:"+a.Tool, "failed")
		r, jerr := jsonResult(map[string]string{"code": "unavailable", "detail": err.Error()})
		return r, nil, jerr
	}
	ot.e.log("call_contact", "contact:"+a.ContactFpr+" tool:"+a.Tool, "ok")
	r, err := jsonResult(map[string]string{"result": out})
	return r, nil, err
}

// listIntegrationsTool is the `list_integrations` tool.
func (ot ownerTools) listIntegrationsTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	rows, err := ot.e.Integrations(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	r, jerr := jsonResult(rows)
	return r, nil, jerr
}

// setExposureTool is the `set_exposure` tool.
func (ot ownerTools) setExposureTool(ctx context.Context, req *mcp.CallToolRequest, a struct {
	AccountID     string   `json:"account_id" jsonschema:"the account the integration belongs to"`
	IntegrationID string   `json:"integration_id" jsonschema:"the integration to republish"`
	Tools         []string `json:"tools" jsonschema:"upstream tool names to expose; an empty list exposes nothing"`
}) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	if a.IntegrationID == "" {
		r, err := jsonResult(map[string]string{"code": "bad_request"})
		return r, nil, err
	}
	// Narrowing to nothing is legitimate — it is how an owner's
	// agent withdraws an integration — so an empty list is applied,
	// not treated as a missing argument.
	if err := ot.e.SetExposure(ctx, a.AccountID, a.IntegrationID, a.Tools); err != nil {
		ot.e.log("set_exposure", "integration:"+a.IntegrationID, "error")
		r, jerr := jsonResult(map[string]string{"code": "bad_request", "detail": err.Error()})
		return r, nil, jerr
	}
	ot.e.log("set_exposure", fmt.Sprintf("integration:%s tools:%d", a.IntegrationID, len(a.Tools)), "ok")
	r, jerr := jsonResult(map[string]any{"status": "ok", "exposed": len(a.Tools)})
	return r, nil, jerr
}

// addContactTool is the `add_contact` tool.
func (ot ownerTools) addContactTool(ctx context.Context, req *mcp.CallToolRequest, a struct {
	AccountID string `json:"account_id" jsonschema:"the account reaching out"`
	InviteURL string `json:"invite_url,omitempty" jsonschema:"their invite link (https://…/i/<token>)"`
	Card      string `json:"card,omitempty" jsonschema:"their vCard, if you have it instead of a link"`
	Note      string `json:"note,omitempty" jsonschema:"a short note for a card request; ignored when redeeming a link"`
	Grant     string `json:"grant,omitempty" jsonschema:"what THEY may do on YOUR node: basic|work|friend|family. Their invite decides what you may do on theirs; this is the other half, and granting nothing means they can never reply."`
}) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	// Exactly one: given both, which identity we are about to pin
	// would depend on argument precedence rather than on what the
	// owner meant.
	if (a.InviteURL == "") == (a.Card == "") {
		r, jerr := jsonResult(map[string]string{"code": "bad_request",
			"detail": "give either invite_url or card, not both"})
		return r, nil, jerr
	}
	res, err := ot.e.AddContact(ctx, a.AccountID, a.InviteURL, a.Card, a.Note, a.Grant)
	if err != nil {
		ot.e.log("add_contact", "account:"+a.AccountID, "error")
		r, jerr := jsonResult(map[string]string{"code": "bad_request", "detail": err.Error()})
		return r, nil, jerr
	}
	ot.e.log("add_contact", "peer:"+res.Fingerprint, res.Status)
	r, jerr := jsonResult(res)
	return r, nil, jerr
}

// auditQueryTool is the `audit_query` tool.
func (ot ownerTools) auditQueryTool(ctx context.Context, req *mcp.CallToolRequest, a struct {
	Actor string `json:"actor,omitempty" jsonschema:"optional: only rows written by this actor, by the id the trail shows for it (an owner or token id, a contact's fingerprint)"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum rows to return; default 100"`
}) (*mcp.CallToolResult, any, error) {
	limit := a.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	// Every other tool here gates on `allow`; this one did not, so
	// any token — including one scoped to a single account — read
	// the whole node's chain across every account. A row with no
	// account is node-level (`serve` start, settings) and is shown
	// only to an identity that administers the whole node.
	rows, err := ot.e.Audit(ctx, a.Actor, limit, func(accountID string) bool {
		if accountID == "" {
			// Node-level, or a row this node could not attribute.
			// Either way a NARROWED token must not see it: "no
			// account" and "an account you may not see" are
			// indistinguishable to this filter, and treating them
			// alike is how a scoping rule ends up permitting
			// everything — which is exactly what happened while
			// every row was written with an empty account.
			return ot.ident.AccountID == ""
		}
		return ot.allow(ctx, accountID)
	})
	if err != nil {
		return nil, nil, err
	}
	// The chain records what happened, not the bodies (§11): rows
	// already reference rather than copy, so they go out as stored.
	r, jerr := jsonResult(rows)
	return r, nil, jerr
}

// ErrNoCard is returned when a node cannot render a card for an account.
var ErrNoCard = fmt.Errorf("ownermcp: no card available")
