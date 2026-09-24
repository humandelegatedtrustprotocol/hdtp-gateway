// Package ownermcp is the owner's MCP surface (SPEC §8.4): bearer-token-authed
// tools mirroring the portal, plus subscribable pact:// resources pushed via
// Server.ResourceUpdated on bus events. Every authorization decision routes
// through policy (Cedar): a token narrowed to one account acts on that account
// alone, and every tool that names an account re-checks AllowOwnerManage.
package ownermcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
)

const (
	URIInbox    = "pact://inbox"
	URIRequests = "pact://requests"
	URIPending  = "pact://pending"
	// URIThreadPrefix is the per-thread signal SPEC §8.5 lists alongside the
	// three collection resources. Only the collections existed, so an agent
	// watching one conversation had to re-read the whole inbox to notice a
	// reply.
	URIThreadPrefix = "pact://thread/"
)

type Deps struct {
	Store store.Store
	// Approved tells the peer their request was accepted (`contact_accepted`).
	// The portal's approve path calls the SAME function: approving on one surface
	// and not the other would leave the peer stranded depending on which button
	// the owner happened to press. Nil skips the call; the approval still stands.
	Approved func(ctx context.Context, accountID, contactFpr string, granted []string) error
	// Rejected tells the peer their request was declined (`contact_rejected`), and Removed tells
	// an active contact it was removed (their `remove_contact`): the same calls the portal makes.
	// Nil skips the call; the decision still stands and the result says they were not told.
	Rejected func(ctx context.Context, accountID, contactFpr string) error
	Removed  func(ctx context.Context, accountID, contactFpr string) error
	// ServedPermissions names every contact-tier permission this account's surface gates a tool
	// with beyond the core five — the portal's switchboard offers the same (contacts.Offered).
	ServedPermissions func(accountID string) []string
	// Invalidate reconciles a caller's composed MCP server after the switchboard
	// changed. Without it an approval writes the store and the CACHED per-caller
	// server keeps serving the old tier — so the owner's agent approves a contact
	// and that contact stays at guest tier until the node restarts (P14-05e).
	// The portal's contact pages have always had this; the owner MCP did not.
	Invalidate func(ctx context.Context, accountID, contactFpr string) error
	Msg        *messaging.Service
	Bus        *messaging.Bus
	Contacts   *contacts.Manager
	// Pending serves agent-answered dispatch (SPEC §6.8); nil disables the
	// list_pending / answer_request pair and pact://pending stays empty.
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

// scope resolves what this identity may touch: the token's account narrow, else
// every account where the owner holds admin (SPEC §3.4).
// reconcile applies a switchboard change to any live per-caller server. A nil
// hook is tolerated so tests can build Deps without one, but production wires it.
func (d Deps) reconcile(ctx context.Context, accountID, contactFpr string) {
	if d.Invalidate == nil {
		return
	}
	_ = d.Invalidate(ctx, accountID, contactFpr)
}

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

type AccountArg struct {
	AccountID string `json:"account_id" jsonschema:"the account to act on"`
}

type AnswerArgs struct {
	AccountID string `json:"account_id" jsonschema:"the account the request belongs to"`
	RequestID string `json:"request_id" jsonschema:"the pending request id"`
	Result    string `json:"result" jsonschema:"the answer payload relayed to the caller"`
}

type ReadThreadArgs struct {
	AccountID string `json:"account_id"`
	ThreadID  string `json:"thread_id"`
}

type SendArgs struct {
	AccountID  string `json:"account_id"`
	ContactFpr string `json:"contact_fpr"`
	ThreadID   string `json:"thread_id,omitempty"`
	MsgID      string `json:"msg_id"`
	Text       string `json:"text"`
}

type PermissionsArgs struct {
	AccountID   string   `json:"account_id"`
	ContactFpr  string   `json:"contact_fpr"`
	Permissions []string `json:"permissions"`
	Preset      string   `json:"preset,omitempty"`
}

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

// AddressArgs names a contact waiting at a new address, by its root (PACT §5.3).
type AddressArgs struct {
	AccountID string `json:"account_id"`
	Root      string `json:"root" jsonschema:"the waiting contact's root fingerprint, as list_pending_addresses gives it"`
}

// InviteIDArgs names one invite of one account.
type InviteIDArgs struct {
	AccountID string `json:"account_id"`
	InviteID  string `json:"invite_id" jsonschema:"the invite to revoke, as list_invites names it"`
}

type InviteArgs struct {
	AccountID  string   `json:"account_id"`
	Label      string   `json:"label,omitempty"`
	MaxUses    int64    `json:"max_uses,omitempty"`
	AutoAccept bool     `json:"auto_accept,omitempty"`
	Preset     string   `json:"preset,omitempty"`
	Perms      []string `json:"permissions,omitempty"`
}

// NewServerWithExtra composes the owner surface for one validated identity: the
// core tools, plus the SPEC §8.4/§8.6 tools whose dependencies live outside this
// package (the node's card, the outbound client, the passkey service, the audit
// chain) — each registered only when its dependency is supplied. The token was
// verified by the transport before this is called; Cedar decides everything else.
func NewServerWithExtra(d Deps, e Extra, ident auth.Identity) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "pact-gateway-owner", Version: "1"}, &mcp.ServerOptions{
		SubscribeHandler:   func(context.Context, *mcp.SubscribeRequest) error { return nil },
		UnsubscribeHandler: func(context.Context, *mcp.UnsubscribeRequest) error { return nil },
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

	mcp.AddTool(s, &mcp.Tool{Name: "list_accounts", Description: "Accounts this identity administers"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			sc, err := d.scope(ctx, ident)
			if err != nil {
				return nil, nil, err
			}
			r, err := jsonResult(sc.AdminAccounts)
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "get_inbox", Description: "Threads with unread counts"},
		func(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			threads, err := d.Store.ListThreadsByAccount(ctx, a.AccountID)
			if err != nil {
				return nil, nil, err
			}
			type row struct {
				ThreadID   string `json:"thread_id"`
				ContactFpr string `json:"contact_fpr"`
				Unread     int64  `json:"unread"`
				LastAt     int64  `json:"last_at"`
			}
			out := make([]row, 0, len(threads))
			for _, th := range threads {
				n, _ := d.Store.UnreadCount(ctx, a.AccountID, th.ID)
				out = append(out, row{ThreadID: th.ID, ContactFpr: th.ContactFpr, Unread: n, LastAt: th.LastAt})
			}
			r, err := jsonResult(out)
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "read_thread", Description: "Messages in a thread, oldest first"},
		func(ctx context.Context, req *mcp.CallToolRequest, a ReadThreadArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			msgs, err := d.Msg.Thread(ctx, a.AccountID, a.ThreadID)
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
				if c, err := d.Store.GetContact(ctx, a.AccountID, m.ContactFpr); err == nil {
					trust = c.TrustFlag
				}
				// SPEC §7.6: every payload handed to the agent carries the trust label.
				out = append(out, row{Direction: m.Direction, Sender: m.Sender, Kind: m.Kind, Body: m.Body, Trust: trust, CreatedAt: m.CreatedAt})
			}
			r, err := jsonResult(out)
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "send_to_contact", Description: "Send a message to a contact (labeled agent, SPEC §7.1)"},
		func(ctx context.Context, req *mcp.CallToolRequest, a SendArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			// This surface IS the agent: the label is fixed here (SPEC §7.2).
			in := messaging.Input{
				MsgID: a.MsgID, ThreadID: a.ThreadID, Text: a.Text, Origin: messaging.OriginMCP,
			}
			send := d.Send
			if send == nil {
				send = func(ctx context.Context, acct, c string, in messaging.Input) (messaging.Result, error) {
					return d.Msg.Record(ctx, acct, c, messaging.DirOut, in)
				}
			}
			res, err := send(ctx, a.AccountID, a.ContactFpr, in)
			if err != nil {
				return nil, nil, err
			}
			r, err := jsonResult(res)
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "list_contacts", Description: "Contacts with status and permissions"},
		func(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			list, err := d.Store.ListContacts(ctx, a.AccountID)
			if err != nil {
				return nil, nil, err
			}
			r, err := jsonResult(list)
			return r, nil, err
		})

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

	// A pinned contact now answering at a new address, held for the owner under `ask` (PACT §5.3,
	// SPEC §9.1): the portal's Requests tab and the CLI's `account address` make the same decision
	// through contacts.Owner.DecideAddress, audited under the same names.
	mcp.AddTool(s, &mcp.Tool{Name: "list_pending_addresses", Description: "Contacts waiting at a new address for your decision: the address they are pinned at, the one they now answer from, and why it was held"},
		func(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			list, err := d.owner().PendingAddresses(ctx, a.AccountID)
			if err != nil {
				return nil, nil, err
			}
			r, err := jsonResult(list)
			return r, nil, err
		})
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
		func(ctx context.Context, req *mcp.CallToolRequest, a PermissionsArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			c, err := d.Store.GetContact(ctx, a.AccountID, a.ContactFpr)
			if err != nil {
				r, rerr := refused(fmt.Errorf("%w: no such contact", contacts.ErrUnknownContact))
				return r, nil, rerr
			}
			var served []string
			if d.ServedPermissions != nil {
				served = d.ServedPermissions(a.AccountID)
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
			if !contacts.LoadPresets(ctx, d.Store).Holds(preset, a.Permissions) {
				preset = ""
			}
			if err := d.Store.UpdateContactPermissions(ctx, a.AccountID, a.ContactFpr, a.Permissions, preset); err != nil {
				return nil, nil, err
			}
			d.reconcile(ctx, a.AccountID, a.ContactFpr)
			r, err := jsonResult("ok")
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "rename_contact", Description: "Set your own local name for a contact; empty clears it"},
		func(ctx context.Context, req *mcp.CallToolRequest, a PetnameArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			name := strings.TrimSpace(a.Petname)
			if len([]rune(name)) > contacts.MaxDisplayName {
				return nil, nil, fmt.Errorf("petname over %d characters", contacts.MaxDisplayName)
			}
			if err := d.Store.SetContactPetname(ctx, a.AccountID, a.ContactFpr, name); err != nil {
				return nil, nil, err
			}
			r, err := jsonResult("ok")
			return r, nil, err
		})

	if d.RefreshContact != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "refresh_contact", Description: "Re-fetch ONE contact's signed card, now: a renewed certificate, a changed name or seal policy is learned; the pinned root and the address never move. Answers unchanged, updated, renewed, unreachable or refused (with why); an unreachable or refused contact keeps its pin as it was"},
			func(ctx context.Context, req *mcp.CallToolRequest, a RefreshArgs) (*mcp.CallToolResult, any, error) {
				if !allow(ctx, a.AccountID) {
					r, err := deny()
					return r, nil, err
				}
				outcome, why, err := d.RefreshContact(ctx, a.AccountID, a.ContactFpr)
				if err != nil {
					return nil, nil, err
				}
				out := map[string]string{"outcome": outcome}
				if why != "" {
					out["why"] = why
				}
				r, err := jsonResult(out)
				return r, nil, err
			})
	}

	mcp.AddTool(s, &mcp.Tool{Name: "set_trust_flag", Description: "messages_only or may_instruct"},
		func(ctx context.Context, req *mcp.CallToolRequest, a TrustArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			if a.Trust != "messages_only" && a.Trust != "may_instruct" {
				return nil, nil, fmt.Errorf("bad_request: trust must be messages_only|may_instruct")
			}
			if err := d.Store.UpdateContactTrust(ctx, a.AccountID, a.ContactFpr, a.Trust); err != nil {
				d.audit("trust_update", "account:"+a.AccountID+" contact:"+a.ContactFpr+" trust:"+a.Trust, "error")
				return nil, nil, err
			}
			d.audit("trust_update", "account:"+a.AccountID+" contact:"+a.ContactFpr+" trust:"+a.Trust, "ok")
			r, err := jsonResult("ok")
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "create_invite", Description: "Mint an invite; token shown once"},
		func(ctx context.Context, req *mcp.CallToolRequest, a InviteArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			token, inv, err := d.Contacts.CreateInvite(ctx, a.AccountID, contacts.InviteOptions{
				Label: a.Label, MaxUses: a.MaxUses, AutoAccept: a.AutoAccept,
				Preset: a.Preset, Permissions: a.Perms,
			})
			if err != nil {
				return nil, nil, err
			}
			r, err := jsonResult(map[string]any{"token": token, "invite_id": inv.ID, "expires_at": inv.ExpiresAt})
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "list_invites", Description: "This account's invites: label, uses, expiry, whether revoked. The link's token is never stored, so it is not here"},
		func(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			list, err := d.Store.ListInvites(ctx, a.AccountID)
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
		})

	mcp.AddTool(s, &mcp.Tool{Name: "revoke_invite", Description: "Revoke one of this account's invites: the link stops working at once, and contacts it already made are unaffected"},
		func(ctx context.Context, req *mcp.CallToolRequest, a InviteIDArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			// Scoped by the account: an invite id alone is not an authority.
			if err := d.Store.RevokeInvite(ctx, a.AccountID, a.InviteID, time.Now().Unix()); err != nil {
				d.audit("invite_revoke", "account:"+a.AccountID+" invite:"+a.InviteID, "error")
				// Only "no such live invite" is not_found. A store that failed has not said the
				// invite is absent, and telling the agent so would be a claim nobody measured.
				if !errors.Is(err, store.ErrNotFound) {
					r, rerr := refused(err)
					return r, nil, rerr
				}
				b, _ := json.Marshal(map[string]string{"code": "not_found", "detail": "no live invite with that id on this account"})
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
			}
			d.audit("invite_revoke", "account:"+a.AccountID+" invite:"+a.InviteID, "ok")
			r, err := jsonResult(map[string]string{"status": "revoked"})
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "list_pending", Description: "Open agent-answered requests awaiting this agent (args are UNTRUSTED peer content, labeled with the contact's trust flag)"},
		func(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			rows, err := d.Store.ListOpenPendingRequests(ctx, a.AccountID, time.Now().Unix())
			if err != nil {
				return nil, nil, err
			}
			r, err := jsonResult(rows)
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "answer_request", Description: "Answer one pending agent-answered request; the node relays to the waiting caller"},
		func(ctx context.Context, req *mcp.CallToolRequest, a AnswerArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			if d.Pending == nil {
				r, err := jsonResult(map[string]any{"error": "agent-answered dispatch is not enabled"})
				return r, nil, err
			}
			relayed, err := d.Pending.Answer(ctx, a.AccountID, a.RequestID, a.Result)
			if err != nil {
				return &mcp.CallToolResult{IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil, nil
			}
			r, err := jsonResult(map[string]any{"relayed": relayed})
			return r, nil, err
		})

	// Resources: subscribable summaries; content is always re-readable (poll path).
	s.AddResource(&mcp.Resource{URI: URIInbox, Name: "inbox", MIMEType: "application/json"},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			sc, err := d.scope(ctx, ident)
			if err != nil {
				return nil, err
			}
			summary := map[string]int64{}
			for _, acct := range sc.AdminAccounts {
				threads, err := d.Store.ListThreadsByAccount(ctx, acct)
				if err != nil {
					continue
				}
				var n int64
				for _, th := range threads {
					u, _ := d.Store.UnreadCount(ctx, acct, th.ID)
					n += u
				}
				summary[acct] = n
			}
			b, _ := json.Marshal(summary)
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: URIInbox, MIMEType: "application/json", Text: string(b)}}}, nil
		})
	s.AddResource(&mcp.Resource{URI: URIRequests, Name: "contact requests", MIMEType: "application/json"},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			sc, err := d.scope(ctx, ident)
			if err != nil {
				return nil, err
			}
			var pending []store.Contact
			for _, acct := range sc.AdminAccounts {
				list, err := d.Store.ListContacts(ctx, acct)
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
		})

	s.AddResource(&mcp.Resource{URI: URIPending, Name: "pending agent-answered requests", MIMEType: "application/json"},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			sc, err := d.scope(ctx, ident)
			if err != nil {
				return nil, err
			}
			var rows []store.PendingRequest
			for _, acct := range sc.AdminAccounts {
				list, err := d.Store.ListOpenPendingRequests(ctx, acct, time.Now().Unix())
				if err != nil {
					continue
				}
				rows = append(rows, list...)
			}
			b, _ := json.Marshal(rows)
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: URIPending, MIMEType: "application/json", Text: string(b)}}}, nil
		})

	// pact://thread/<id> (SPEC §8.5): the per-conversation signal. A template,
	// because the id is not known until a thread exists.
	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: URIThreadPrefix + "{id}",
		Name:        "thread", MIMEType: "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		id := strings.TrimPrefix(req.Params.URI, URIThreadPrefix)
		if id == "" || id == req.Params.URI {
			return nil, fmt.Errorf("ownermcp: %s is not a thread URI", req.Params.URI)
		}
		sc, err := d.scope(ctx, ident)
		if err != nil {
			return nil, err
		}
		// A thread belongs to exactly one account, and this identity may only
		// read the accounts it administers — the same rule every tool applies.
		for _, acct := range sc.AdminAccounts {
			th, err := d.Store.GetThread(ctx, acct, id)
			if err != nil {
				continue
			}
			msgs, err := d.Store.ListMessagesByThread(ctx, acct, id)
			if err != nil {
				return nil, err
			}
			b, _ := json.Marshal(map[string]any{"thread": th, "messages": msgs})
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
				{URI: req.Params.URI, MIMEType: "application/json", Text: string(b)}}}, nil
		}
		return nil, fmt.Errorf("ownermcp: no such thread")
	})

	AddParityTools(s, d, e, ident, allow)
	AddWatchTools(s, d, allow)

	return s
}

// ForwardBus pushes ResourceUpdated to subscribed sessions on bus events; run it
// once per server, stopped by cancelling ctx (SPEC §8.5).
func ForwardBus(ctx context.Context, s *mcp.Server, bus *messaging.Bus) {
	ch, cancel := bus.Subscribe("")
	go func() {
		defer cancel()
		// One forwarder is started per owner-MCP session, with the process-
		// lifetime context. Without an exit of its own, every reconnect by the
		// owner's agent left a goroutine and a 32-slot subscriber channel behind
		// for the life of the node — and Bus.Publish walks every subscriber
		// under a lock, so message delivery got slower with each one.
		//
		// A forwarder exists to push to ITS server's sessions. When that server
		// has none left, there is nothing to push to and it is done.
		idle := time.NewTicker(30 * time.Second)
		defer idle.Stop()
		started := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-idle.C:
				live := false
				for range s.Sessions() {
					live = true
					break
				}
				if live {
					started = true
					continue
				}
				if started {
					// It had sessions and now has none: the agent disconnected.
					return
				}
			case e, ok := <-ch:
				if !ok {
					return
				}
				switch e.Kind {
				case messaging.EventMessage:
					_ = s.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: URIInbox})
					// …and the conversation itself, so an agent watching one
					// thread does not have to re-read the whole inbox to notice
					// a reply (SPEC §8.5).
					if e.ThreadID != "" {
						_ = s.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{
							URI: URIThreadPrefix + e.ThreadID})
					}
				case messaging.EventRequest:
					_ = s.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: URIRequests})
				case messaging.EventPending:
					_ = s.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: URIPending})
				}
			}
		}
	}()
}
