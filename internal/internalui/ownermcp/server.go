// Package ownermcp is the owner's MCP surface (SPEC §8.4): bearer-token-authed
// tools mirroring the portal, plus subscribable pact:// resources pushed via
// Server.ResourceUpdated on bus events. Every authorization decision routes
// through policy (Cedar): a token narrowed to one account acts on that account
// alone, and every tool that names an account re-checks AllowOwnerManage.
package ownermcp

import (
	"context"
	"encoding/json"
	"fmt"
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
	// SyncContacts pulls every contact's signed card now (node.SyncContacts);
	// nil hides the tool.
	SyncContacts func(ctx context.Context) (checked, changed int)
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

type ApproveArgs struct {
	AccountID  string `json:"account_id"`
	ContactFpr string `json:"contact_fpr"`
	Preset     string `json:"preset,omitempty"`
}

type InviteArgs struct {
	AccountID  string   `json:"account_id"`
	Label      string   `json:"label,omitempty"`
	MaxUses    int64    `json:"max_uses,omitempty"`
	AutoAccept bool     `json:"auto_accept,omitempty"`
	Preset     string   `json:"preset,omitempty"`
	Perms      []string `json:"permissions,omitempty"`
}

// NewServer composes the owner surface for one validated identity. The token was
// verified by the transport before this is called; Cedar decides everything else.
// NewServer builds the owner surface for one bearer identity.
func NewServer(d Deps, ident auth.Identity) *mcp.Server {
	return NewServerWithExtra(d, Extra{}, ident)
}

// NewServerWithExtra is NewServer plus the SPEC §8.4/§8.6 tools whose
// dependencies live outside this package (the node's card, the outbound client,
// the passkey service, the audit chain).
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

	mcp.AddTool(s, &mcp.Tool{Name: "approve_contact", Description: "Approve a pending_in request"},
		func(ctx context.Context, req *mcp.CallToolRequest, a ApproveArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			c, err := d.Store.GetContact(ctx, a.AccountID, a.ContactFpr)
			if err != nil || c.Status != "pending_in" {
				return nil, nil, fmt.Errorf("unknown_contact: no pending request")
			}
			if err := d.Store.UpdateContactStatus(ctx, a.AccountID, a.ContactFpr, "active"); err != nil {
				return nil, nil, err
			}
			bundles := contacts.LoadPresets(ctx, d.Store)
			if a.Preset != "" {
				if perms, ok := bundles[a.Preset]; ok {
					_ = d.Store.UpdateContactPermissions(ctx, a.AccountID, a.ContactFpr, perms, a.Preset)
				}
			}
			d.reconcile(ctx, a.AccountID, a.ContactFpr)
			// Tell them, or they sit at pending_out with no way to learn.
			status := "approved"
			if d.Approved != nil {
				var granted []string
				if a.Preset != "" {
					granted = bundles[a.Preset]
				}
				if err := d.Approved(ctx, a.AccountID, a.ContactFpr, granted); err != nil {
					status = "approved; they could not be told yet (" + err.Error() + ")"
				}
			}
			r, err := jsonResult(status)
			return r, nil, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "set_permissions", Description: "Set a contact's switchboard"},
		func(ctx context.Context, req *mcp.CallToolRequest, a PermissionsArgs) (*mcp.CallToolResult, any, error) {
			if !allow(ctx, a.AccountID) {
				r, err := deny()
				return r, nil, err
			}
			var known []string
			for _, p := range a.Permissions {
				for _, k := range contacts.AllPermissions {
					if p == k {
						known = append(known, p)
					}
				}
			}
			// Same rule the portal follows: a preset names a bundle, so it only
			// rides along while the grant still is that bundle. An agent setting
			// a bespoke list does not get to label it "family".
			preset := a.Preset
			if !contacts.LoadPresets(ctx, d.Store).Holds(preset, known) {
				preset = ""
			}
			if err := d.Store.UpdateContactPermissions(ctx, a.AccountID, a.ContactFpr, known, preset); err != nil {
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

	if d.SyncContacts != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "sync_contacts", Description: "Re-fetch every contact's signed card now (endpoint/seal/gateway changes); the pinned key never moves"},
			func(ctx context.Context, req *mcp.CallToolRequest, a AccountArg) (*mcp.CallToolResult, any, error) {
				if !allow(ctx, a.AccountID) {
					r, err := deny()
					return r, nil, err
				}
				checked, changed := d.SyncContacts(ctx)
				r, err := jsonResult(map[string]int{"checked": checked, "updated": changed})
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
