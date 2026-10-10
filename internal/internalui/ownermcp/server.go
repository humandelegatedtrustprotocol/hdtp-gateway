// Package ownermcp is the owner's MCP surface (SPEC §8.4): the tools and hdtp:// resources an
// owner's agent uses to run the node with a bearer token (internalui/auth.TokenService), mirroring
// what the portal does for a person. What changes is waited for with `wait_for_updates`
// (SPEC §8.5). Every authorization decision routes through policy (Cedar): a token narrowed to one
// account acts on that account alone, and every tool that names an account re-checks
// AllowOwnerManage.
//
// internal/cli (compose.go) builds one server per request with NewServerWithExtra, for the
// identity the request's token validated as, and mounts it at /owner/mcp outside the portal's
// session and CSRF layers; the token check there is the only gate in front of this package. The
// package does not authenticate: it is handed an auth.Identity and decides, per account, what
// that identity may touch.
//
// The tools are registered in three places: NewServerWithExtra (the core and the contact
// lifecycle), AddParityTools (the ones whose dependencies come in Extra; each is registered only
// when its dependency is non-nil), AddWatchTools (wait_for_updates, digest). The README lists
// them with their refusals.
package ownermcp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

const (
	// URIInbox is the resource of unread counts, one number per administered account.
	URIInbox = "hdtp://inbox"
	// URIRequests is the resource of contacts waiting for the owner's approval (pending_in), across
	// the administered accounts.
	URIRequests = "hdtp://requests"
	// URIPending is the resource of open agent-answered requests (SPEC §6.8), across the
	// administered accounts.
	URIPending = "hdtp://pending"
	// URIThreadPrefix is the per-thread resource SPEC §8.5 lists alongside the
	// three collection resources: one conversation, read without reading the
	// whole inbox.
	URIThreadPrefix = "hdtp://thread/"
)

// Deps is what the owner surface acts through. A nil Approved, Rejected, Removed, Invalidate,
// ServedPermissions, Audit or Send skips the effect it names and the tool still answers; a nil
// RefreshContact leaves refresh_contact unregistered; a nil Pending makes answer_request answer
// that dispatch is not enabled and keeps the pending count out of wait_for_updates and digest.
type Deps struct {
	// Store is the node's store. It is read for scope (memberships) and for every tool.
	Store store.Store
	// PublicURL is this node's public address, read live (it changes from Settings): where an
	// invite's link lands (`/i/<token>`). "" is no address, and create_invite then mints nothing.
	PublicURL func() string
	// Approved tells the peer their request was accepted (`contact_accepted`).
	// The portal's approve path calls the SAME function: approving on one surface
	// and not the other would leave the peer stranded depending on which button
	// the owner happened to press. Nil skips the call; the approval still stands.
	Approved func(ctx context.Context, accountID, contactFpr string, granted []string) error
	// Rejected tells the peer their request was declined (`contact_rejected`), and Removed tells
	// an active contact it was removed (their `remove_contact`): the same calls the portal makes.
	// Nil skips the call; the decision still stands and the result says they were not told.
	Rejected func(ctx context.Context, accountID, contactFpr string) error
	// Removed: see Rejected.
	Removed func(ctx context.Context, accountID, contactFpr string) error
	// ServedPermissions names every contact-tier permission this account's surface gates a tool
	// with beyond the core five — the portal's switchboard offers the same (contacts.Offered).
	ServedPermissions func(accountID string) []string
	// Invalidate drops a caller's composed MCP server after the switchboard
	// changed. Without it an approval writes the store and the CACHED per-caller
	// server keeps serving the old tier — so the owner's agent approves a contact
	// and that contact stays at guest tier until the node restarts (P14-05e).
	// The portal's contact pages have always had this; the owner MCP did not.
	Invalidate func(ctx context.Context, accountID, contactFpr string) error
	// Msg reads threads (and records a message when Send is nil).
	Msg *messaging.Service
	// Bus wakes wait_for_updates; nil leaves it to wait out its timeout.
	Bus *messaging.Bus
	// Contacts runs the contact lifecycle and mints invites. The lifecycle tools and create_invite
	// call it without a nil check.
	Contacts *contacts.Manager
	// Pending serves agent-answered dispatch (SPEC §6.8). Nil makes answer_request answer
	// {"error":"agent-answered dispatch is not enabled"}, and leaves the pending count out of
	// wait_for_updates and digest. list_pending and hdtp://pending read the store and do not
	// consult it.
	Pending *integrations.AgentAnswered
	// Send delivers a message to a contact AND records it. `internal/messaging`
	// has no path to the wire, so a tool wired straight to Msg.Record recorded
	// a row and sent nothing while telling the agent "delivered". nil keeps the
	// record-only behaviour for tests that do not compose a node.
	Send func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error)
	// RefreshContact re-fetches ONE contact's signed card now (node.RefreshContact), the
	// same function behind the button on the portal's contact page. There is no tool that
	// refreshes more than the contact it is given. nil hides the tool.
	RefreshContact func(ctx context.Context, accountID, contactFpr string) (outcome, why string, err error)
	// Audit records owner-agent actions that change security posture. The trust
	// flip is the one that matters most: it decides whether a contact's words
	// may INSTRUCT the owner's agent, and an unaudited flip is exactly the kind
	// of change an incident review needs to see. nil skips (tests).
	Audit func(action, resource, outcome string)
}

func (d Deps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// reconcile applies a switchboard change to any live per-caller server. A nil
// hook is tolerated so tests can build Deps without one, but production wires it.
func (d Deps) reconcile(ctx context.Context, accountID, contactFpr string) {
	if d.Invalidate == nil {
		return
	}
	_ = d.Invalidate(ctx, accountID, contactFpr)
}

// scope resolves what this identity may touch: the token's account narrow, else
// every account where the owner holds admin (SPEC §3.4).
func (d Deps) scope(ctx context.Context, ident auth.Identity) (policy.OwnerCtx, error) {
	ms, err := d.Store.ListMembershipsByOwner(ctx, ident.OwnerID)
	if err != nil {
		return policy.OwnerCtx{}, err
	}
	var accts []string
	for _, m := range ms {
		if m.Role != "admin" {
			continue
		}
		if ident.AccountID != "" && m.AccountID != ident.AccountID {
			continue // token narrowed to one account
		}
		accts = append(accts, m.AccountID)
	}
	return policy.OwnerCtx{OwnerID: ident.OwnerID, AdminAccounts: accts}, nil
}

// owner is the lifecycle both surfaces call (contacts.Owner), with this surface's hooks.
func (d Deps) owner() contacts.Owner {
	return contacts.Owner{Manager: d.Contacts, Invalidate: d.Invalidate,
		TellApproved: d.Approved, TellRejected: d.Rejected, TellRemoved: d.Removed}
}

// refused answers a refusal as a tool error carrying its code, the shape deny() uses.
func refused(err error) (*mcp.CallToolResult, error) {
	code := "internal"
	switch {
	case errors.Is(err, contacts.ErrUnknownContact):
		code = "unknown_contact"
	case errors.Is(err, contacts.ErrWrongState):
		code = "conflict"
	case errors.Is(err, contacts.ErrBadRequest):
		code = "bad_request"
	case errors.Is(err, contacts.ErrContactCap):
		code = "payment_required"
	}
	b, jerr := json.Marshal(map[string]string{"code": code, "detail": err.Error()})
	if jerr != nil {
		return nil, jerr
	}
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
}

func deny() (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"permission_denied"}`}},
	}, nil
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
}

/* --------------------------------- args ---------------------------------- */

// AccountArg is the argument of every tool that takes only an account.
type AccountArg struct {
	AccountID string `json:"account_id" jsonschema:"the account to act on"`
}

// AnswerArgs are answer_request's arguments: one pending request of one account, and the payload
// the node relays to the waiting caller.
type AnswerArgs struct {
	AccountID string `json:"account_id" jsonschema:"the account the request belongs to"`
	RequestID string `json:"request_id" jsonschema:"the pending request id"`
	Result    string `json:"result" jsonschema:"the answer payload relayed to the caller"`
}

// ReadThreadArgs are read_thread's arguments.
type ReadThreadArgs struct {
	AccountID string `json:"account_id"`
	ThreadID  string `json:"thread_id"`
}

// SendArgs are send_to_contact's arguments. MsgID is the idempotency key. ThreadID is empty to
// start a new thread; Topic is for that case only.
type SendArgs struct {
	AccountID  string `json:"account_id"`
	ContactFpr string `json:"contact_fpr"`
	ThreadID   string `json:"thread_id,omitempty"`
	MsgID      string `json:"msg_id"`
	Text       string `json:"text"`
	Topic      string `json:"topic,omitempty" jsonschema:"a new thread's topic, at most 256 bytes; refused for a thread that exists"`
}

// PermissionsArgs are set_permissions' arguments: the contact's whole new grant, not a delta.
// Preset is kept only while Permissions still equals that bundle.
type PermissionsArgs struct {
	AccountID   string   `json:"account_id"`
	ContactFpr  string   `json:"contact_fpr"`
	Permissions []string `json:"permissions"`
	Preset      string   `json:"preset,omitempty"`
}

// TrustArgs are set_trust_flag's arguments; Trust is messages_only or may_instruct.
type TrustArgs struct {
	AccountID  string `json:"account_id"`
	ContactFpr string `json:"contact_fpr"`
	Trust      string `json:"trust" jsonschema:"messages_only or may_instruct"`
}

// PetnameArgs renames a contact LOCALLY. The name a contact supplies is its own
// claim and several contacts may honestly share one; this is the owner's name for
// them, which no peer can reach or change. An empty Petname clears it and falls
// back to the contact's own name.
type PetnameArgs struct {
	AccountID  string `json:"account_id"`
	ContactFpr string `json:"contact_fpr"`
	Petname    string `json:"petname" jsonschema:"the owner's own name for this contact; empty clears it"`
}

// RefreshArgs names the one contact to refresh. There is no form of it that names none.
type RefreshArgs struct {
	AccountID  string `json:"account_id"`
	ContactFpr string `json:"contact_fpr" jsonschema:"the contact whose card to re-fetch"`
}

// ContactArgs names one contact of one account, for the lifecycle tools. Preset is read by
// approve_contact alone.
type ContactArgs struct {
	AccountID  string `json:"account_id"`
	ContactFpr string `json:"contact_fpr"`
	Preset     string `json:"preset,omitempty" jsonschema:"approve_contact only: the preset to grant; empty keeps the grant the request holds"`
}

// AddressArgs names a contact waiting at a new address, by its root (HDTP §5.3).
type AddressArgs struct {
	AccountID string `json:"account_id"`
	Root      string `json:"root" jsonschema:"the waiting contact's root fingerprint, as list_pending_addresses gives it"`
}

// InviteIDArgs names one invite of one account.
type InviteIDArgs struct {
	AccountID string `json:"account_id"`
	InviteID  string `json:"invite_id" jsonschema:"the invite to revoke, as list_invites names it"`
}

// InviteArgs are create_invite's arguments; they are contacts.InviteOptions.
type InviteArgs struct {
	AccountID  string   `json:"account_id"`
	Label      string   `json:"label,omitempty"`
	MaxUses    int64    `json:"max_uses,omitempty"`
	AutoAccept bool     `json:"auto_accept,omitempty"`
	Preset     string   `json:"preset,omitempty"`
	Perms      []string `json:"permissions,omitempty"`
}

// ownerTools is what the owner surface's tools and resources act with: the dependencies, the
// extras, the identity the token was validated as, and the Cedar decision for one account. Each
// tool is a method on it, registered by NewServerWithExtra, AddParityTools or AddWatchTools.
type ownerTools struct {
	d     Deps
	e     Extra
	ident auth.Identity
	allow func(ctx context.Context, accountID string) bool
}

// NewServerWithExtra composes the owner surface for one validated identity: the
// core tools, plus the SPEC §8.4/§8.6 tools whose dependencies live outside this
// package (the node's card, the outbound client, the passkey service, the audit
// chain) — each registered only when its dependency is supplied. The token was
// verified by the transport before this is called; Cedar decides everything else.
func NewServerWithExtra(d Deps, e Extra, ident auth.Identity) *mcp.Server {
	// Tools and resources, and neither a list-change notification nor resource subscriptions:
	// the surface is stateless (SPEC §8.5), so nothing would carry either, and a client told it
	// might would open `subscriptions/listen` for them.
	s := mcp.NewServer(&mcp.Implementation{Name: "hdtp-gateway-owner", Version: "1"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}, Resources: &mcp.ResourceCapabilities{}},
	})

	// SPEC §8.7: every action on this surface is audited. Individual tools
	// logged their own mutations and read-only calls logged nothing at all, so
	// an owner reviewing the trail could not see what a token had LOOKED at —
	// and a token that only reads is still a token that was used. One
	// middleware records every call, including refusals, which is also the only
	// way a tool added later cannot forget to.
	if e.Log != nil {
		s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				res, err := next(ctx, method, req)
				if method != "tools/call" {
					return res, err
				}
				name := "unknown"
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && p != nil {
					name = p.Name
				}
				outcome := "ok"
				switch {
				case err != nil:
					outcome = "error"
				default:
					if r, ok := res.(*mcp.CallToolResult); ok && r != nil && r.IsError {
						outcome = "refused"
					}
				}
				e.Log("owner_mcp_call", "tool:"+name, outcome)
				return res, err
			}
		})
	}

	allow := func(ctx context.Context, accountID string) bool {
		sc, err := d.scope(ctx, ident)
		if err != nil {
			return false
		}
		return policy.AllowOwnerManage(sc, accountID)
	}
	ot := ownerTools{d: d, e: e, ident: ident, allow: allow}

	mcp.AddTool(s, &mcp.Tool{Name: "list_accounts", Description: "Accounts this identity administers"},
		ot.listAccountsTool)

	mcp.AddTool(s, &mcp.Tool{Name: "get_inbox", Description: "Threads with unread counts. contact_status is the contact row's status, or removed when no row names the thread's fingerprint. A thread whose contact was removed stays, and its removed_contact holds the display_name and petname kept from the contact (a later request with no name does not erase them); null while any contact row, active, pending or blocked, names the thread's fingerprint"},
		ot.getInboxTool)

	mcp.AddTool(s, &mcp.Tool{Name: "read_thread", Description: "Messages in a thread, oldest first; reading marks the thread read through the newest"},
		ot.readThreadTool)

	mcp.AddTool(s, &mcp.Tool{Name: "send_to_contact", Description: "Send a message to a contact (labeled agent, SPEC §7.1)"},
		ot.sendToContactTool)

	mcp.AddTool(s, &mcp.Tool{Name: "list_contacts", Description: "Contacts with status and permissions"},
		ot.listContactsTool)

	// The contact lifecycle (SPEC §9.1), one tool per decision, each the portal's own through
	// contacts.Owner. Each answers the Decision — the status afterwards, and for the ones that
	// tell the peer, whether they heard — and is audited under the portal's action name.
	// Each tool is named by a literal at its call: the parity tests read the names from the syntax.
	lifecycle := func(tool *mcp.Tool, action string, do func(ctx context.Context, a ContactArgs) (contacts.Decision, error)) {
		mcp.AddTool(s, tool,
			func(ctx context.Context, req *mcp.CallToolRequest, a ContactArgs) (*mcp.CallToolResult, any, error) {
				if !allow(ctx, a.AccountID) {
					r, err := deny()
					return r, nil, err
				}
				resource := "account:" + a.AccountID + " contact:" + a.ContactFpr
				dec, err := do(ctx, a)
				if err != nil {
					d.audit(action, resource, "error")
					r, rerr := refused(err)
					return r, nil, rerr
				}
				d.audit(action, resource+" status:"+dec.Status, "ok")
				r, err := jsonResult(dec)
				return r, nil, err
			})
	}
	lifecycle(&mcp.Tool{Name: "approve_contact", Description: "Approve a waiting request (pending_in). A preset replaces the grant with that bundle; none keeps the grant the request holds (an invite's). The peer is told what they were granted; told=false says they could not be reached, and the approval stands"},
		"contact_approve", func(ctx context.Context, a ContactArgs) (contacts.Decision, error) {
			return d.owner().Approve(ctx, a.AccountID, a.ContactFpr, a.Preset)
		})
	lifecycle(&mcp.Tool{Name: "reject_contact", Description: "Decline a waiting request: it becomes blocked (a demotion, not a deletion), so that identity's next request never reaches you. They are told, so they do not wait for ever"},
		"contact_reject", func(ctx context.Context, a ContactArgs) (contacts.Decision, error) {
			return d.owner().Reject(ctx, a.AccountID, a.ContactFpr)
		})
	lifecycle(&mcp.Tool{Name: "block_contact", Description: "Block a contact, silently: they are not told, and see only what a stranger sees"},
		"contact_block", func(ctx context.Context, a ContactArgs) (contacts.Decision, error) {
			return d.owner().Block(ctx, a.AccountID, a.ContactFpr)
		})
	lifecycle(&mcp.Tool{Name: "unblock_contact", Description: "Undo a block, silently. A contact that was ever active returns as it was (status active); a rejected request or a declined approach was never a contact and is forgotten (status none), so they may ask again"},
		"contact_unblock", func(ctx context.Context, a ContactArgs) (contacts.Decision, error) {
			return d.owner().Unblock(ctx, a.AccountID, a.ContactFpr)
		})
	lifecycle(&mcp.Tool{Name: "remove_contact", Description: "Remove a contact in any state: an active one is told and its pin deleted whether or not it answers; a waiting request, your own pending request or a blocked identity goes silently"},
		"contact_remove", func(ctx context.Context, a ContactArgs) (contacts.Decision, error) {
			return d.owner().Remove(ctx, a.AccountID, a.ContactFpr)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "list_pending_addresses", Description: "Contacts waiting at a new address for your decision: the address they are pinned at, the one they now answer from, and why it was held"},
		ot.listPendingAddressesTool)
	address := func(tool *mcp.Tool, approve bool) {
		decision := "reject"
		if approve {
			decision = "approve"
		}
		mcp.AddTool(s, tool,
			func(ctx context.Context, req *mcp.CallToolRequest, a AddressArgs) (*mcp.CallToolResult, any, error) {
				if !allow(ctx, a.AccountID) {
					r, err := deny()
					return r, nil, err
				}
				p, err := d.owner().DecideAddress(ctx, a.AccountID, a.Root, approve)
				if err != nil {
					d.audit("contact_address_"+decision, "account:"+a.AccountID+" contact:"+a.Root, "error")
					r, rerr := refused(err)
					return r, nil, rerr
				}
				d.audit("contact_address_"+decision, "account:"+a.AccountID+" contact:"+a.Root+" endpoint:"+p.Endpoint, "ok")
				r, err := jsonResult(map[string]string{"root": a.Root, "endpoint": p.Endpoint, "decision": decision})
				return r, nil, err
			})
	}
	address(&mcp.Tool{Name: "approve_address", Description: "Re-pin a contact at the new address it is waiting at, as `auto` would have; the address it left is remembered as a former one"}, true)
	address(&mcp.Tool{Name: "reject_address", Description: "Keep the pin where it is and drop the waiting address"}, false)

	mcp.AddTool(s, &mcp.Tool{Name: "set_permissions", Description: "Set a contact's switchboard: any of the core permissions, an integration.<slug> this account serves, or one the contact already holds; any other name is refused"},
		ot.setPermissionsTool)

	mcp.AddTool(s, &mcp.Tool{Name: "rename_contact", Description: "Set your own local name for a contact; empty clears it"},
		ot.renameContactTool)

	if d.RefreshContact != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "refresh_contact", Description: "Re-fetch ONE contact's signed card, now: a renewed certificate, a changed name or seal policy is learned; the pinned root and the address never move. Answers unchanged, updated, renewed, unreachable or refused (with why); an unreachable or refused contact keeps its pin as it was"},
			ot.refreshContactTool)
	}

	mcp.AddTool(s, &mcp.Tool{Name: "set_trust_flag", Description: "messages_only or may_instruct"},
		ot.setTrustFlagTool)

	mcp.AddTool(s, &mcp.Tool{Name: "create_invite", Description: "Mint an invite; token shown once"},
		ot.createInviteTool)

	mcp.AddTool(s, &mcp.Tool{Name: "list_invites", Description: "This account's invites: label, uses, expiry, whether revoked. The link's token is never stored, so it is not here"},
		ot.listInvitesTool)

	mcp.AddTool(s, &mcp.Tool{Name: "revoke_invite", Description: "Revoke one of this account's invites: the link stops working at once, and contacts it already made are unaffected"},
		ot.revokeInviteTool)

	mcp.AddTool(s, &mcp.Tool{Name: "list_pending", Description: "Open agent-answered requests awaiting this agent (args are UNTRUSTED peer content, labeled with the contact's trust flag)"},
		ot.listPendingTool)

	mcp.AddTool(s, &mcp.Tool{Name: "answer_request", Description: "Answer one pending agent-answered request; the node relays to the waiting caller"},
		ot.answerRequestTool)

	s.AddResource(&mcp.Resource{URI: URIInbox, Name: "inbox", MIMEType: "application/json"},
		ot.inboxResource)
	s.AddResource(&mcp.Resource{URI: URIRequests, Name: "contact requests", MIMEType: "application/json"},
		ot.contactRequestsResource)

	s.AddResource(&mcp.Resource{URI: URIPending, Name: "pending agent-answered requests", MIMEType: "application/json"},
		ot.pendingRequestsResource)

	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: URIThreadPrefix + "{id}",
		Name:        "thread", MIMEType: "application/json",
	}, ot.threadResource)

	AddParityTools(s, d, e, ident, allow)
	AddWatchTools(s, d, allow)

	return s
}

// listAccountsTool is the `list_accounts` tool.
func (ot ownerTools) listAccountsTool(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	sc, err := ot.d.scope(ctx, ot.ident)
	if err != nil {
		return nil, nil, err
	}
	r, err := jsonResult(sc.AdminAccounts)
	return r, nil, err
}

// StatusRemoved is what a thread says of its contact when no contact row names it any more
// (SPEC §9.1): removed by either side, forgotten on an unblock, or a request that expired. It is
// never a contact row's status; the portal's conversation list says it in the same word.
const StatusRemoved = "removed"

// getInboxTool is the `get_inbox` tool.
func (ot ownerTools) getInboxTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	threads, err := ot.d.Store.ListThreadsByAccount(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	contacts, err := ot.d.Store.ListContacts(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	status := make(map[string]string, len(contacts))
	for _, c := range contacts {
		status[c.Fingerprint] = c.Status
	}
	type kept struct {
		DisplayName string `json:"display_name"`
		Petname     string `json:"petname"`
	}
	type row struct {
		ThreadID   string `json:"thread_id"`
		ContactFpr string `json:"contact_fpr"`
		Unread     int64  `json:"unread"`
		LastAt     int64  `json:"last_at"`
		// ContactStatus is the contact row's status (active, pending_in, pending_out, blocked),
		// or StatusRemoved when no row names ContactFpr: what BatonDeck's thread rows answer as
		// contact_status, in the same words.
		ContactStatus string `json:"contact_status"`
		// RemovedContact is null while a contact row names ContactFpr, whatever its status; once
		// the row is gone, the names the thread kept (an empty one never replaced a kept one).
		// BatonDeck's thread rows answer the same member.
		RemovedContact *kept `json:"removed_contact"`
	}
	out := make([]row, 0, len(threads))
	for _, th := range threads {
		n, _ := ot.d.Store.UnreadCount(ctx, a.AccountID, th.ID)
		r := row{ThreadID: th.ID, ContactFpr: th.ContactFpr, Unread: n, LastAt: th.LastAt}
		if st, held := status[th.ContactFpr]; held {
			r.ContactStatus = st
		} else {
			r.ContactStatus = StatusRemoved
			r.RemovedContact = &kept{DisplayName: stripName(th.KeptDisplayName), Petname: th.KeptPetname}
		}
		out = append(out, r)
	}
	r, err := jsonResult(out)
	return r, nil, err
}

// stripName is the one rule a name a contact chose passes before it renders (HDTP §3): every
// answer of this server that carries a contact's display name or a removed thread's kept one.
var stripName = identity.StripDisplayName

// readThreadTool is the `read_thread` tool.
func (ot ownerTools) readThreadTool(ctx context.Context, req *mcp.CallToolRequest, a ReadThreadArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	msgs, err := ot.d.Msg.Thread(ctx, a.AccountID, a.ThreadID)
	if err != nil {
		return nil, nil, err
	}
	type row struct {
		Direction string `json:"direction"`
		Sender    string `json:"sender"`
		Kind      string `json:"kind"`
		Body      string `json:"body"`
		Trust     string `json:"trust"`
		CreatedAt int64  `json:"created_at"`
	}
	out := make([]row, 0, len(msgs))
	for _, m := range msgs {
		trust := "messages_only"
		if c, err := ot.d.Store.GetContact(ctx, a.AccountID, m.ContactFpr); err == nil {
			trust = c.TrustFlag
		}
		// SPEC §7.6: every payload handed to the agent carries the trust label.
		out = append(out, row{Direction: m.Direction, Sender: m.Sender, Kind: m.Kind, Body: m.Body, Trust: trust, CreatedAt: m.CreatedAt})
	}
	// The agent reading is the owner reading, as BatonDeck's read_thread is: the thread is read
	// through the newest message this answer hands over (oldest first, so the last), and what
	// lands after it stays unread. The marker is local and never wire-visible (SPEC §7.6).
	if n := len(msgs); n > 0 {
		if _, err := ot.d.Store.MarkThreadReadThrough(ctx, a.AccountID, a.ThreadID, msgs[n-1].Seq); err != nil {
			return nil, nil, err
		}
	}
	r, err := jsonResult(out)
	return r, nil, err
}

// sendToContactTool is the `send_to_contact` tool.
func (ot ownerTools) sendToContactTool(ctx context.Context, req *mcp.CallToolRequest, a SendArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	// This surface IS the agent: the label is fixed here (SPEC §7.2).
	in := messaging.Input{
		MsgID: a.MsgID, ThreadID: a.ThreadID, Text: a.Text, Topic: a.Topic, Origin: messaging.OriginMCP,
	}
	send := ot.d.Send
	if send == nil {
		send = func(ctx context.Context, acct, c string, in messaging.Input) (messaging.Result, error) {
			return ot.d.Msg.Record(ctx, acct, c, messaging.DirOut, in)
		}
	}
	res, err := send(ctx, a.AccountID, a.ContactFpr, in)
	if err != nil {
		return nil, nil, err
	}
	r, err := jsonResult(res)
	return r, nil, err
}

// listContactsTool is the `list_contacts` tool.
func (ot ownerTools) listContactsTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	list, err := ot.d.Store.ListContacts(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	out := make([]contactView, 0, len(list))
	for _, c := range list {
		v := contactOf(c)
		// A request from an address that belongs, or lately belonged, to another contact names
		// that contact (HDTP §5.2), in the cloud's shape: {root, name}, the owner's name for them
		// first. Derived when read, by the rule the redemption applied.
		if c.Status == "pending_in" && ot.d.Contacts != nil {
			if claim, err := ot.d.Contacts.AddressClaim(ctx, a.AccountID, c.Endpoint, c.Fingerprint); err == nil && claim != "" {
				name := claim
				for _, h := range list {
					if h.Fingerprint == claim {
						name = cmp.Or(h.Petname, stripName(h.DisplayName), claim)
					}
				}
				v.AddressClaim = &addressClaim{Root: claim, Name: name}
			}
		}
		out = append(out, v)
	}
	r, err := jsonResult(out)
	return r, nil, err
}

// contactView is a contact as the owner MCP answers it (building rule 10: project, never spread):
// the cloud's names for what this node holds (batondeck api/v1/routes/shared.ts `Contact`), and
// the grant the contact made us. Not the row id, the account id, the pinned key, the card, the
// invite or the chain mark. The cloud's last_seen_at and acceptance_unheard_since are not here:
// this node keeps neither. address_claim is derived when read (HDTP §5.2).
type contactView struct {
	Fingerprint      string   `json:"fingerprint"`
	DisplayName      string   `json:"display_name"`
	Status           string   `json:"status"`
	Preset           string   `json:"preset"`
	Permissions      []string `json:"permissions"`
	TheirPermissions []string `json:"their_permissions"`
	TrustFlag        string   `json:"trust_flag"`
	Petname          string   `json:"petname"`
	CreatedAt        int64    `json:"created_at"`
	Endpoint         string   `json:"endpoint"`
	Leaf             string   `json:"leaf,omitempty"`
	RootCert         string   `json:"root_cert,omitempty"`
	// AddressClaim is, on a waiting request, the contact whose address it comes from (HDTP §5.2);
	// null otherwise, as the cloud answers it.
	AddressClaim *addressClaim `json:"address_claim"`
}

type addressClaim struct {
	Root string `json:"root"`
	Name string `json:"name"`
}

func contactOf(c store.Contact) contactView {
	v := contactView{Fingerprint: c.Fingerprint, DisplayName: stripName(c.DisplayName), Status: c.Status, Preset: c.Preset,
		Permissions: nonNil(c.Permissions), TheirPermissions: nonNil(c.TheirPermissions), TrustFlag: c.TrustFlag,
		Petname: c.Petname, CreatedAt: c.CreatedAt, Endpoint: c.Endpoint}
	if len(c.Leaf) > 0 {
		v.Leaf = hdtpidentity.B64url(c.Leaf)
	}
	if len(c.RootCert) > 0 {
		v.RootCert = hdtpidentity.B64url(c.RootCert)
	}
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// listPendingAddressesTool is the `list_pending_addresses` tool.
//
// A pinned contact now answering at a new address, held for the owner under `ask` (HDTP §5.3,
// SPEC §9.1): the portal's Requests tab and the CLI's `account address` make the same decision
// through contacts.Owner.DecideAddress, audited under the same names.
func (ot ownerTools) listPendingAddressesTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	list, err := ot.d.owner().PendingAddresses(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	r, err := jsonResult(list)
	return r, nil, err
}

// setPermissionsTool is the `set_permissions` tool.
func (ot ownerTools) setPermissionsTool(ctx context.Context, req *mcp.CallToolRequest, a PermissionsArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	c, err := ot.d.Store.GetContact(ctx, a.AccountID, a.ContactFpr)
	if err != nil {
		r, rerr := refused(fmt.Errorf("%w: no such contact", contacts.ErrUnknownContact))
		return r, nil, rerr
	}
	var served []string
	if ot.d.ServedPermissions != nil {
		served = ot.d.ServedPermissions(a.AccountID)
	}
	// The portal's switchboard, and the portal's allow-list. A name outside it is refused
	// rather than dropped: "ok" for a grant that was thrown away is how an agent came to
	// believe it had granted an integration nobody could call.
	offered := contacts.Offered(served, c.Permissions)
	for _, p := range a.Permissions {
		if !slices.Contains(offered, p) {
			r, rerr := refused(fmt.Errorf("%w: %q is not a permission this account offers", contacts.ErrBadRequest, p))
			return r, nil, rerr
		}
	}
	// Same rule the portal follows: a preset names a bundle, so it only
	// rides along while the grant still is that bundle. An agent setting
	// a bespoke list does not get to label it "family".
	preset := a.Preset
	if !contacts.LoadPresets(ctx, ot.d.Store).Holds(preset, a.Permissions) {
		preset = ""
	}
	if err := ot.d.Store.UpdateContactPermissions(ctx, a.AccountID, a.ContactFpr, a.Permissions, preset); err != nil {
		return nil, nil, err
	}
	ot.d.reconcile(ctx, a.AccountID, a.ContactFpr)
	r, err := jsonResult("ok")
	return r, nil, err
}

// renameContactTool is the `rename_contact` tool.
func (ot ownerTools) renameContactTool(ctx context.Context, req *mcp.CallToolRequest, a PetnameArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	name := strings.TrimSpace(a.Petname)
	if len([]rune(name)) > contacts.MaxDisplayName {
		return nil, nil, fmt.Errorf("petname over %d characters", contacts.MaxDisplayName)
	}
	if err := ot.d.Store.SetContactPetname(ctx, a.AccountID, a.ContactFpr, name); err != nil {
		return nil, nil, err
	}
	r, err := jsonResult("ok")
	return r, nil, err
}

// refreshContactTool is the `refresh_contact` tool.
func (ot ownerTools) refreshContactTool(ctx context.Context, req *mcp.CallToolRequest, a RefreshArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	outcome, why, err := ot.d.RefreshContact(ctx, a.AccountID, a.ContactFpr)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]string{"outcome": outcome}
	if why != "" {
		out["why"] = why
	}
	r, err := jsonResult(out)
	return r, nil, err
}

// setTrustFlagTool is the `set_trust_flag` tool.
func (ot ownerTools) setTrustFlagTool(ctx context.Context, req *mcp.CallToolRequest, a TrustArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	if a.Trust != "messages_only" && a.Trust != "may_instruct" {
		return nil, nil, fmt.Errorf("bad_request: trust must be messages_only|may_instruct")
	}
	if err := ot.d.Store.UpdateContactTrust(ctx, a.AccountID, a.ContactFpr, a.Trust); err != nil {
		ot.d.audit("trust_update", "account:"+a.AccountID+" contact:"+a.ContactFpr+" trust:"+a.Trust, "error")
		return nil, nil, err
	}
	ot.d.audit("trust_update", "account:"+a.AccountID+" contact:"+a.ContactFpr+" trust:"+a.Trust, "ok")
	r, err := jsonResult("ok")
	return r, nil, err
}

// createInviteTool is the `create_invite` tool.
func (ot ownerTools) createInviteTool(ctx context.Context, req *mcp.CallToolRequest, a InviteArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	// The link lands at this node's public address; with none there is nowhere for it to land,
	// and nothing is minted (the cloud refuses the same way when an identity has no address).
	base := ""
	if ot.d.PublicURL != nil {
		base = strings.TrimRight(ot.d.PublicURL(), "/")
	}
	if base == "" {
		b, err := json.Marshal(map[string]string{"code": "unavailable", "detail": "this node has no public address yet, so an invite has nowhere to land: set public_url"})
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
	}
	token, inv, err := ot.d.Contacts.CreateInvite(ctx, a.AccountID, contacts.InviteOptions{
		Label: a.Label, MaxUses: a.MaxUses, AutoAccept: a.AutoAccept,
		Preset: a.Preset, Permissions: a.Perms,
	})
	if err != nil {
		return nil, nil, err
	}
	// The cloud's answer (createInvite: id, url, expires_at). The token is in the link and nowhere
	// else: the link is what a person sends.
	r, err := jsonResult(map[string]any{"id": inv.ID, "url": base + "/i/" + token, "expires_at": inv.ExpiresAt})
	return r, nil, err
}

// listInvitesTool is the `list_invites` tool.
func (ot ownerTools) listInvitesTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	list, err := ot.d.Store.ListInvites(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	type row struct {
		ID          string   `json:"invite_id"`
		Label       string   `json:"label"`
		Uses        int64    `json:"uses"`
		MaxUses     int64    `json:"max_uses"`
		AutoAccept  bool     `json:"auto_accept"`
		Preset      string   `json:"preset,omitempty"`
		Permissions []string `json:"permissions"`
		ExpiresAt   int64    `json:"expires_at"`
		RevokedAt   int64    `json:"revoked_at,omitempty"`
	}
	out := make([]row, 0, len(list))
	for _, inv := range list {
		out = append(out, row{ID: inv.ID, Label: inv.Label, Uses: inv.Uses, MaxUses: inv.MaxUses, AutoAccept: inv.AutoAccept,
			Preset: inv.Preset, Permissions: inv.Permissions, ExpiresAt: inv.ExpiresAt, RevokedAt: inv.RevokedAt})
	}
	r, err := jsonResult(out)
	return r, nil, err
}

// revokeInviteTool is the `revoke_invite` tool.
func (ot ownerTools) revokeInviteTool(ctx context.Context, req *mcp.CallToolRequest, a InviteIDArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	// Scoped by the account: an invite id alone is not an authority.
	if err := ot.d.Store.RevokeInvite(ctx, a.AccountID, a.InviteID, time.Now().Unix()); err != nil {
		ot.d.audit("invite_revoke", "account:"+a.AccountID+" invite:"+a.InviteID, "error")
		// Only "no such live invite" is not_found. A store that failed has not said the
		// invite is absent, and telling the agent so would be a claim nobody measured.
		if !errors.Is(err, store.ErrNotFound) {
			r, rerr := refused(err)
			return r, nil, rerr
		}
		b, _ := json.Marshal(map[string]string{"code": "not_found", "detail": "no live invite with that id on this account"})
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
	}
	ot.d.audit("invite_revoke", "account:"+a.AccountID+" invite:"+a.InviteID, "ok")
	r, err := jsonResult(map[string]string{"status": "revoked"})
	return r, nil, err
}

// listPendingTool is the `list_pending` tool.
func (ot ownerTools) listPendingTool(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	rows, err := ot.d.Store.ListOpenPendingRequests(ctx, a.AccountID, time.Now().Unix())
	if err != nil {
		return nil, nil, err
	}
	r, err := jsonResult(rows)
	return r, nil, err
}

// answerRequestTool is the `answer_request` tool.
func (ot ownerTools) answerRequestTool(ctx context.Context, req *mcp.CallToolRequest, a AnswerArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	if ot.d.Pending == nil {
		r, err := jsonResult(map[string]any{"error": "agent-answered dispatch is not enabled"})
		return r, nil, err
	}
	relayed, err := ot.d.Pending.Answer(ctx, a.AccountID, a.RequestID, a.Result)
	if err != nil {
		return &mcp.CallToolResult{IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil, nil
	}
	r, err := jsonResult(map[string]any{"relayed": relayed})
	return r, nil, err
}

// inboxResource reads the `inbox` resource.
//
// Resources: summaries, read on demand (SPEC §8.5).
func (ot ownerTools) inboxResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	sc, err := ot.d.scope(ctx, ot.ident)
	if err != nil {
		return nil, err
	}
	summary := map[string]int64{}
	for _, acct := range sc.AdminAccounts {
		threads, err := ot.d.Store.ListThreadsByAccount(ctx, acct)
		if err != nil {
			continue
		}
		var n int64
		for _, th := range threads {
			u, _ := ot.d.Store.UnreadCount(ctx, acct, th.ID)
			n += u
		}
		summary[acct] = n
	}
	b, _ := json.Marshal(summary)
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: URIInbox, MIMEType: "application/json", Text: string(b)}}}, nil
}

// contactRequestsResource reads the `contact requests` resource.
func (ot ownerTools) contactRequestsResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	sc, err := ot.d.scope(ctx, ot.ident)
	if err != nil {
		return nil, err
	}
	var pending []store.Contact
	for _, acct := range sc.AdminAccounts {
		list, err := ot.d.Store.ListContacts(ctx, acct)
		if err != nil {
			continue
		}
		for _, c := range list {
			if c.Status == "pending_in" {
				pending = append(pending, c)
			}
		}
	}
	b, _ := json.Marshal(pending)
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: URIRequests, MIMEType: "application/json", Text: string(b)}}}, nil
}

// pendingRequestsResource reads the `pending agent-answered requests` resource.
func (ot ownerTools) pendingRequestsResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	sc, err := ot.d.scope(ctx, ot.ident)
	if err != nil {
		return nil, err
	}
	var rows []store.PendingRequest
	for _, acct := range sc.AdminAccounts {
		list, err := ot.d.Store.ListOpenPendingRequests(ctx, acct, time.Now().Unix())
		if err != nil {
			continue
		}
		rows = append(rows, list...)
	}
	b, _ := json.Marshal(rows)
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: URIPending, MIMEType: "application/json", Text: string(b)}}}, nil
}

// threadResource reads the `thread` resource.
//
// hdtp://thread/<id> (SPEC §8.5): one conversation. A template, because the id
// is not known until a thread exists.
func (ot ownerTools) threadResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	id := strings.TrimPrefix(req.Params.URI, URIThreadPrefix)
	if id == "" || id == req.Params.URI {
		return nil, fmt.Errorf("ownermcp: %s is not a thread URI", req.Params.URI)
	}
	sc, err := ot.d.scope(ctx, ot.ident)
	if err != nil {
		return nil, err
	}
	// A thread belongs to exactly one account, and this identity may only
	// read the accounts it administers — the same rule every tool applies.
	for _, acct := range sc.AdminAccounts {
		th, err := ot.d.Store.GetThread(ctx, acct, id)
		if err != nil {
			continue
		}
		msgs, err := ot.d.Store.ListMessagesByThread(ctx, acct, id)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(map[string]any{"thread": th, "messages": msgs})
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
			{URI: req.Params.URI, MIMEType: "application/json", Text: string(b)}}}, nil
	}
	return nil, fmt.Errorf("ownermcp: no such thread")
}
