package ownermcp

// The owner's agent asks its owner (SPEC §8.4, "owner asks"): `ask_owner` puts an A2UI surface on a
// thread for the owner to answer with a tap, `notify_owner` one with nothing to answer, and
// `withdraw_ask`, `get_ask` and `list_asks` follow them. Each is the asks service's own operation
// (internal/services/asks), the one the portal's card and its Needs you page answer through; this
// door only translates.
//
// ask_owner and notify_owner publish the catalog's JSON Schema as their surface argument's schema,
// its components' schemas under the tool schema's own $defs (asks.Defs), and do not let the SDK
// validate against it: asks.Parse does, so a refusal is coded (bad_request, too_large) like every
// other refusal of this surface rather than the SDK's free text.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/asks"
)

// PutArgs are ask_owner's and notify_owner's arguments: the message on the thread the surface is
// about, and the surface.
type PutArgs struct {
	AccountID    string          `json:"account_id"`
	ThreadID     string          `json:"thread_id"`
	ForMessageID string          `json:"for_message_id"`
	Surface      json.RawMessage `json:"surface"`
}

// AskIDArgs names one ask or notice of one account.
type AskIDArgs struct {
	AccountID string `json:"account_id"`
	AskID     string `json:"ask_id" jsonschema:"the ask, as ask_owner or list_asks names it"`
}

// ListAsksArgs are list_asks' arguments.
type ListAsksArgs struct {
	AccountID string `json:"account_id"`
	Status    string `json:"status,omitempty" jsonschema:"open for the asks waiting on the owner; omit for every ask and notice"`
	ThreadID  string `json:"thread_id,omitempty" jsonschema:"one thread's asks and notices, newest first"`
	Contact   string `json:"contact_fpr,omitempty" jsonschema:"one contact's asks and notices, newest first"`
}

// PutSchema is ask_owner's (kind ask) or notify_owner's (kind notice) input schema: the surface is
// the catalog's own schema for that kind, and the catalog's definitions it refers to are the tool
// schema's $defs, so every $ref is local to the one document, and $schema names the draft it is
// written in (2020-12: prefixItems, contains with maxContains).
func PutSchema(kind string) *jsonschema.Schema {
	str := func(about string) *jsonschema.Schema {
		return &jsonschema.Schema{Type: "string", MinLength: jsonschema.Ptr(1), Description: about}
	}
	return &jsonschema.Schema{
		Schema: Draft,
		Type:   "object",
		Properties: map[string]*jsonschema.Schema{
			"account_id":     str("the account to act on"),
			"thread_id":      str("the thread the surface goes on, as get_inbox names it"),
			"for_message_id": str("the message in the thread it is about, as read_thread names it; asking twice about one message is one " + kind),
			"surface":        asks.SurfaceSchema(kind),
		},
		Defs:                 asks.Defs(kind),
		Required:             []string{"account_id", "thread_id", "for_message_id", "surface"},
		AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
	}
}

// Draft is the JSON Schema dialect ask_owner's and notify_owner's input schemas are written in.
const Draft = "https://json-schema.org/draft/2020-12/schema"

// askAbout and noticeAbout are the two tools' descriptions, their numbers read from the catalog.
var (
	askAbout = fmt.Sprintf("Ask your owner something only they can decide, as a card on the thread and on their Needs you page: "+
		"an A2UI %s surface in the node's catalog (A2UI's basic components plus the node's KeyValue; the schema of surface) "+
		"listing the root Column first and its first child, a one-line TLDR Text (at most %d bytes), second; then what "+
		"they need to know (Text, KeyValue); then up to %d ready replies, each a Button whose action.event is "+
		"{\"name\":\"reply\",\"context\":{\"reply\":\"<the text>\"}} so one tap sends it; and a TextField last "+
		"for writing their own, with the Button that sends it. An input binds its value to a {path} in the data model "+
		"and a Button's action.event.context reads those paths: pressing it is the answer (a ChoicePicker or a "+
		"DateTimeInput read this way too). A ready reply or what they write is sent to the contact as the owner's "+
		"message (labelled human) and answers the ask; a date, or a button that reads nothing, answers without "+
		"sending. Any other message the owner sends on the thread answers it too. One open ask per thread (conflict while "+
		"one is open); asking again about the same message answers the same ask. It expires after %s. Read the answer "+
		"with get_ask: answer_text is one line (`Ana chose: \"Confirm Wed 15:00\"`); wait_for_updates lists it as it "+
		"moves. At most %d bytes and %d components (too_large, bad_request).",
		asks.Version, asks.MaxTLDRBytes, asks.MaxOptions, asks.Lifetime, asks.MaxSurfaceBytes, asks.MaxComponents)
	noticeAbout = fmt.Sprintf("Tell your owner something done for them, as a card on the thread: an A2UI %s surface "+
		"like ask_owner's with nothing to answer (Text and KeyValue only, no data model), a TLDR Text first. It does not "+
		"expire, and it does not stop the thread holding an open ask; telling twice about one message is one notice.", asks.Version)
)

// AddAskTools registers the asks tools when the node serves asks (Extra.Asks).
func AddAskTools(s *mcp.Server, d Deps, e Extra, ident auth.Identity, allow func(ctx context.Context, accountID string) bool) {
	if e.Asks == nil {
		return
	}
	ot := ownerTools{d: d, e: e, ident: ident, allow: allow}
	s.AddTool(&mcp.Tool{Name: "ask_owner", Description: askAbout, InputSchema: PutSchema(asks.KindAsk),
		Annotations: public.Hints(false, false, true, false)},
		ot.putTool(e.Asks.Ask))
	s.AddTool(&mcp.Tool{Name: "notify_owner", Description: noticeAbout, InputSchema: PutSchema(asks.KindNotice),
		Annotations: public.Hints(false, false, true, false)},
		ot.putTool(e.Asks.Notify))
	mcp.AddTool(s, &mcp.Tool{Name: "withdraw_ask",
		Description: "Withdraw an open ask the owner no longer needs to answer: its card stops offering an answer and the thread may hold the next. conflict once it is answered, expired or withdrawn",
		Annotations: public.Hints(false, true, false, false)},
		ot.withdrawAskTool)
	mcp.AddTool(s, &mcp.Tool{Name: "get_ask",
		Description: "One ask or notice: its status (open, answered, expired, withdrawn; a notice is posted), its TLDR, its surface, and answer_text, the one line the owner's answer became",
		Annotations: public.Hints(true, false, true, false)},
		ot.getAskTool)
	mcp.AddTool(s, &mcp.Tool{Name: "list_asks",
		Description: fmt.Sprintf("This account's asks and notices, newest first, at most %d: each with its status and answer_text. status open lists the asks waiting on the owner; thread_id one thread's and contact_fpr one contact's, newest first too; not_found for a thread or contact the account does not have", asks.ListLimit),
		Annotations: public.Hints(true, false, true, false)},
		ot.listAsksTool)
}

// putTool is ask_owner's or notify_owner's handler over put (asks.Service.Ask or Notify).
func (ot ownerTools) putTool(put func(ctx context.Context, accountID, threadID, forMsgID string, surface []byte) (asks.View, error)) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a PutArgs
		if err := json.Unmarshal(req.Params.Arguments, &a); err != nil {
			return refused(refusal.BadRequest("the arguments are an object of account_id, thread_id, for_message_id and surface", nil))
		}
		if !ot.allow(ctx, a.AccountID) {
			return deny()
		}
		v, err := put(ctx, a.AccountID, a.ThreadID, a.ForMessageID, a.Surface)
		if err != nil {
			return refused(err)
		}
		return jsonResult(v)
	}
}

// withdrawAskTool is the `withdraw_ask` tool.
func (ot ownerTools) withdrawAskTool(ctx context.Context, req *mcp.CallToolRequest, a AskIDArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	v, err := ot.e.Asks.Withdraw(ctx, a.AccountID, a.AskID)
	if err != nil {
		return fail(err)
	}
	r, err := jsonResult(v)
	return r, nil, err
}

// getAskTool is the `get_ask` tool.
func (ot ownerTools) getAskTool(ctx context.Context, req *mcp.CallToolRequest, a AskIDArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	v, err := ot.e.Asks.Get(ctx, a.AccountID, a.AskID)
	if err != nil {
		return fail(err)
	}
	r, err := jsonResult(v)
	return r, nil, err
}

// listAsksTool is the `list_asks` tool.
func (ot ownerTools) listAsksTool(ctx context.Context, req *mcp.CallToolRequest, a ListAsksArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	if a.Status != "" && a.Status != asks.StatusOpen {
		return fail(refusal.BadRequest("status is open, or omitted for every ask and notice", nil))
	}
	l, err := ot.e.Asks.List(ctx, a.AccountID, asks.Filter{Open: a.Status == asks.StatusOpen, Thread: a.ThreadID, Contact: a.Contact})
	if err != nil {
		return fail(err)
	}
	r, err := jsonResult(map[string]any{"asks": l})
	return r, nil, err
}
