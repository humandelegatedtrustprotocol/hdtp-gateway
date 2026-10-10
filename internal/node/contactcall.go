package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// ContactTool is what a contact's server offers this identity: the peer's own
// switchboard has already filtered the list, so every entry here is callable.
type ContactTool struct {
	// Name is the tool's name on the contact's server.
	Name string `json:"name"`
	// Description is the contact's description of it.
	Description string `json:"description,omitempty"`
	// InputSchema is the tool's JSON schema as the contact published it; for a list rebuilt from
	// the contact's grants it is the bare `{"type":"object"}`.
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// peerFor resolves an ACTIVE contact into the outbound peer and client for it.
// A blocked or pending contact is not somebody this node reaches out to.
func (n *Node) peerFor(ctx context.Context, accountID, contactFpr string) (*outbound.Client, outbound.Peer, error) {
	c, err := n.opts.Store.GetContact(ctx, accountID, contactFpr)
	if err != nil || c.Status != "active" {
		return nil, outbound.Peer{}, fmt.Errorf("unknown contact")
	}
	peer, err := n.PeerOf(accountID, c)
	if err != nil {
		return nil, outbound.Peer{}, err
	}
	client, err := n.OutboundClient(accountID)
	if err != nil {
		return nil, outbound.Peer{}, err
	}
	return client, peer, nil
}

// ListContactTools asks a contact's server what this identity may call there.
func (n *Node) ListContactTools(ctx context.Context, accountID, contactFpr string) ([]ContactTool, error) {
	client, peer, err := n.peerFor(ctx, accountID, contactFpr)
	if err != nil {
		return nil, err
	}
	// A sealed tools/list is answered for the identity in the envelope (HDTP §13.2), so it is
	// right even where TLS terminates before the peer and a plaintext list would be answered as
	// to a stranger. It is sealed to the key in the leaf held for them.
	var tools []*mcp.Tool
	if peer.Seal == "required" || peer.Seal == "optional" {
		tools, err = client.SealedListTools(ctx, peer, newCallID())
	} else {
		tools, err = client.ListTools(ctx, peer)
	}
	if err != nil {
		n.auditFor(accountID, "list_contact_tools", "contact:"+contactFpr, "failed")
		return nil, err
	}
	out := make([]ContactTool, 0, len(tools))
	for _, t := range tools {
		ct := ContactTool{Name: t.Name, Description: t.Description}
		if t.InputSchema != nil {
			if b, err := json.Marshal(t.InputSchema); err == nil {
				ct.InputSchema = b
			}
		}
		out = append(out, ct)
	}
	// Behind an edge that terminates TLS (a Cloudflare tunnel, say) no client
	// certificate reaches the peer, so a plain tools/list is answered as if we
	// were a stranger: the guest surface. That says nothing about what they let
	// US do. Their grants are on file — they told us at accept time and on every
	// switchboard change they pushed — so the surface is rebuilt from those.
	if looksGuest(out) {
		c, err := n.opts.Store.GetContact(ctx, accountID, contactFpr)
		if err == nil && c.Status == "active" {
			out = toolsFromGrants(c.TheirPermissions)
			n.auditFor(accountID, "list_contact_tools", "contact:"+contactFpr, "from_grants")
			return out, nil
		}
	}
	n.auditFor(accountID, "list_contact_tools", "contact:"+contactFpr, "ok")
	return out, nil
}

// looksGuest recognises the stranger's surface (HDTP §6.2): the two guest
// tools, with or without sealed_call, and none of the contact tier.
func looksGuest(tools []ContactTool) bool {
	guest, contact := false, false
	for _, t := range tools {
		switch t.Name {
		case core.ToolRedeemInvite, core.ToolRequestContact:
			guest = true
		case core.ToolGetCard, core.ToolSendMessage, core.ToolSendMedia, core.ToolGetStatus, core.ToolCheckAvailability, core.ToolBookSlot, core.ToolCancelBooking:
			contact = true
		}
	}
	return guest && !contact
}

// toolsFromGrants is the contact tier as the node itself would publish it for
// a caller holding these permissions — the same table as internal/public,
// minus integration tools, whose names only the peer's own list can supply.
func toolsFromGrants(perms []string) []ContactTool {
	has := map[string]bool{}
	for _, p := range perms {
		has[p] = true
	}
	obj := json.RawMessage(`{"type":"object"}`)
	out := []ContactTool{
		{Name: core.ToolGetCard, Description: "Fetch their current signed contact card", InputSchema: obj},
		{Name: core.ToolUpdateContact, Description: "Replace the card this contact holds for you: a new certificate, or a new address", InputSchema: obj},
		{Name: core.ToolRemoveContact, Description: "Remove yourself from their contacts", InputSchema: obj},
	}
	add := func(perm, name, desc string) {
		if has[perm] {
			out = append(out, ContactTool{Name: name, Description: desc, InputSchema: obj})
		}
	}
	add("message.text", core.ToolSendMessage, "Send a text message")
	add("message.media", core.ToolSendMedia, "Send a file or image")
	add("status.view", core.ToolGetStatus, "Read their availability status")
	add("calendar.availability", core.ToolCheckAvailability, "Ask for candidate meeting slots")
	add("calendar.book", core.ToolBookSlot, "Book one of the offered slots")
	add("calendar.book", core.ToolCancelBooking, "Cancel a booking you made")
	return out
}

// CallContact performs one call to a contact's server on the owner's behalf,
// through the ordinary outbound path — sealed or plain as the peer's card says.
// The peer applies its OWN switchboard either way: this cannot reach anything
// the contact has not granted us. The owner MCP's call_contact and the portal
// both go through here, so the two surfaces cannot disagree about what a call
// to a contact is.
func (n *Node) CallContact(ctx context.Context, accountID, contactFpr, tool string, args map[string]any) (string, error) {
	client, peer, err := n.peerFor(ctx, accountID, contactFpr)
	if err != nil {
		return "", err
	}
	if args == nil {
		args = map[string]any{}
	}
	msgID, _ := args["msg_id"].(string)
	if msgID == "" {
		msgID = newCallID()
	}
	res, err := client.Call(ctx, peer, tool, args, msgID)
	if err != nil {
		n.auditFor(accountID, "call_contact", "contact:"+contactFpr+" tool:"+tool, "failed")
		return "", err
	}
	n.auditFor(accountID, "call_contact", "contact:"+contactFpr+" tool:"+tool, outcomeOf(res))
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func outcomeOf(res *mcp.CallToolResult) string {
	if res != nil && res.IsError {
		return "refused"
	}
	return "ok"
}

// newCallID mints the idempotency key for a call the owner did not name.
func newCallID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "call-" + hex.EncodeToString(b)
}

// auditFor records an event attributed to the account it happened in. The
// trail's account column scopes a narrowed token's reads (SPEC §11.6) and the
// portal's audit page; a row about one person's contact, written with no
// account, is readable by every owner on the node.
func (n *Node) auditFor(accountID, action, resource, outcome string) {
	if accountID != "" {
		resource = "account:" + accountID + " " + resource
	}
	n.opts.audit(action, resource, outcome)
}
