package ownermcp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// keysOf is the sorted member names of one JSON object.
func keysOf(t *testing.T, text string) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("not one JSON object: %s", text)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// #234. send_to_contact answered messaging.Result as it was, in Go's field names (ThreadID,
// Status) and with no message id, where every other owner tool answers snake_case; the error of a
// message recorded and not delivered carried the same two names. Both answers name exactly status,
// message_id and thread_id now (the message_id the msg_id the message was recorded under), the
// description names the answer by those keys, and nothing in tools/list says ThreadID.
func TestSendToContactAnswersStatusMessageIDAndThreadID(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "send_to_contact", map[string]any{
		"account_id": e.acctA, "contact_fpr": "sha256:alina", "msg_id": "m1", "text": "hi"})
	if got := keysOf(t, text); isErr || !reflect.DeepEqual(got, []string{"message_id", "status", "thread_id"}) {
		t.Fatalf("a recorded send answered %s (IsError %v), want exactly status, message_id and thread_id", text, isErr)
	}
	var sent struct {
		Status    string `json:"status"`
		MessageID string `json:"message_id"`
		ThreadID  string `json:"thread_id"`
	}
	if err := json.Unmarshal([]byte(text), &sent); err != nil || sent.ThreadID == "" || sent.Status == "" || sent.MessageID != "m1" {
		t.Fatalf("a recorded send answered %s", text)
	}
	if msgs, err := e.deps.Msg.Thread(ctx, e.acctA, sent.ThreadID); err != nil || len(msgs) != 1 {
		t.Fatalf("the thread_id answered holds %d messages (%v), want the one sent", len(msgs), err)
	}

	d := e.deps
	d.Send = func(context.Context, string, string, messaging.Input) (messaging.Result, error) {
		return messaging.Result{ThreadID: "t1", Status: messaging.StatusPending},
			refusal.Undelivered("unreachable", errors.New("dial"))
	}
	srv := NewServerWithExtra(d, Extra{Log: func(string, string, string) {}}, auth.Identity{OwnerID: e.owner})
	text, isErr = callParityResult(t, ctx, srv, "send_to_contact", map[string]any{
		"account_id": e.acctA, "contact_fpr": "sha256:c", "msg_id": "m2", "text": "hi"})
	if got := keysOf(t, text); !isErr || !reflect.DeepEqual(got, []string{"code", "detail", "message_id", "status", "thread_id"}) ||
		!strings.Contains(text, `"thread_id":"t1"`) || !strings.Contains(text, `"message_id":"m2"`) {
		t.Fatalf("a recorded, undelivered send answered %s (IsError %v), want code, detail, status, message_id and thread_id", text, isErr)
	}

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		if tl.Name != "send_to_contact" {
			continue
		}
		raw, err := json.Marshal(tl)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "ThreadID") || !strings.Contains(tl.Description, "Answers {status, message_id, thread_id}") {
			t.Errorf("send_to_contact's listing names the answer by the old keys, or not by thread_id: %s", raw)
		}
		return
	}
	t.Fatal("tools/list has no send_to_contact")
}

// #223. The resource hdtp://thread/<id> is a second door to read_thread and answered the store's
// rows ({thread, messages}, each message in Go's field names and without message_id). It answers
// read_thread's projection now, the same text, and like every resource read it marks nothing: the
// thread is as unread after it as before, and read_thread is what reads it.
func TestTheThreadResourceAnswersWhatReadThreadAnswers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	const threadID = "tshapes"
	for _, id := range []string{"m1", "m2"} {
		if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn,
			messaging.Input{Origin: messaging.OriginPeer, MsgID: id, ThreadID: threadID, Text: "text of " + id, Sender: messaging.SenderAgent}); err != nil {
			t.Fatal(err)
		}
	}
	rr, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: URIThreadPrefix + threadID})
	if err != nil {
		t.Fatal(err)
	}
	resource := rr.Contents[0].Text
	if n, _ := e.st.UnreadCount(ctx, e.acctA, threadID); n != 2 {
		t.Fatalf("after the resource was read the thread has %d unread, want 2: a resource read marks nothing", n)
	}
	tool, isErr := callJSON(t, cs, "read_thread", map[string]any{"account_id": e.acctA, "thread_id": threadID})
	if isErr || resource != tool {
		t.Fatalf("the resource answered\n%s\nand read_thread\n%s", resource, tool)
	}
	var msgs []map[string]any
	if err := json.Unmarshal([]byte(resource), &msgs); err != nil || len(msgs) != 2 || msgs[0]["message_id"] != "m1" || msgs[1]["message_id"] != "m2" {
		t.Fatalf("the resource's messages: %s", resource)
	}
	if n, _ := e.st.UnreadCount(ctx, e.acctA, threadID); n != 0 {
		t.Fatalf("read_thread left %d unread, want 0", n)
	}
}

// #225. list_invites answered a bare array, each invite under invite_id with revoked_at left out
// while live, and the portal's GET /api/invites the same invites in Go's field names. Both answer
// contacts.InviteRows now; here, list_invites answers {invites: [...]} as the cloud's does, each row
// exactly the projection's, revoked_at null until the invite is revoked.
func TestListInvitesAnswersTheInviteRow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	_, inv, err := e.deps.Contacts.CreateInvite(ctx, e.acctA, contacts.InviteOptions{Label: "party", Preset: "basic"})
	if err != nil {
		t.Fatal(err)
	}
	list := func() string {
		t.Helper()
		text, isErr := callJSON(t, cs, "list_invites", map[string]any{"account_id": e.acctA})
		if isErr || !reflect.DeepEqual(keysOf(t, text), []string{"invites"}) {
			t.Fatalf("list_invites: %s", text)
		}
		stored, err := e.st.ListInvites(ctx, e.acctA)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(map[string]any{"invites": contacts.InviteRows(stored)})
		if err != nil {
			t.Fatal(err)
		}
		if text != string(want) {
			t.Fatalf("list_invites answered\n%s\nwant the invite rows\n%s", text, want)
		}
		return text
	}
	if text := list(); !strings.Contains(text, `"id":"`+inv.ID+`"`) || !strings.Contains(text, `"revoked_at":null`) {
		t.Fatalf("a live invite: %s", text)
	}
	if text, isErr := callJSON(t, cs, "revoke_invite", map[string]any{"account_id": e.acctA, "invite_id": inv.ID}); isErr {
		t.Fatalf("revoke_invite: %s", text)
	}
	if text := list(); strings.Contains(text, `"revoked_at":null`) {
		t.Fatalf("a revoked invite: %s", text)
	}
}

// Building rule 1's divergence for invites, named where a test holds it. The node's invite row is
// the cloud's /v1 Invite (batondeck gateway/src/api/v1/routes/shared.ts) without `url`, because this
// node keeps only the token's hash and has no link after the mint (SPEC §11), and with
// `permissions`, because an invite here can carry a grant of its own. create_invite answers what the
// cloud's createInvite answers (gateway/src/api/v1/routes/invites.ts). The cloud's keys are read from
// its source: a change on either side that the other does not make turns this red.
func TestTheInviteRowIsTheCloudsLessItsLinkAndWithItsGrant(t *testing.T) {
	shared := string(testid.SiblingFile(t, "batondeck", "gateway/src/api/v1/routes/shared.ts", "the node's invite row is unchecked against the cloud's"))
	routes := string(testid.SiblingFile(t, "batondeck", "gateway/src/api/v1/routes/invites.ts", "create_invite's answer is unchecked against the cloud's"))

	body := regexp.MustCompile(`(?s)export const Invite = z\.object\(\{\n(.*?)\n\}\)`).FindStringSubmatch(shared)
	if body == nil {
		t.Fatal("shared.ts declares no `export const Invite = z.object({ … })`")
	}
	var cloudRow []string
	for _, m := range regexp.MustCompile(`(?m)^  (\w+): z\.`).FindAllStringSubmatch(body[1], -1) {
		cloudRow = append(cloudRow, m[1])
	}
	var nodeRow []string
	rt := reflect.TypeOf(contacts.InviteRow{})
	for i := range rt.NumField() {
		nodeRow = append(nodeRow, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	want := slices.DeleteFunc(slices.Clone(cloudRow), func(k string) bool { return k == "url" })
	want = append(want, "permissions")
	sort.Strings(want)
	sort.Strings(nodeRow)
	if !slices.Contains(cloudRow, "url") || !reflect.DeepEqual(nodeRow, want) {
		t.Errorf("the node's invite row is %v; the cloud's is %v, and the named divergence (no url, permissions added) makes it %v",
			nodeRow, cloudRow, want)
	}

	create := regexp.MustCompile(`(?s)operationId: 'createInvite'.*?response: z\.object\(\{([^}]*)\}\)`).FindStringSubmatch(routes)
	if create == nil {
		t.Fatal("invites.ts declares no createInvite response")
	}
	var cloudCreate []string
	for _, m := range regexp.MustCompile(`(\w+): z\.`).FindAllStringSubmatch(create[1], -1) {
		cloudCreate = append(cloudCreate, m[1])
	}
	sort.Strings(cloudCreate)
	e := newEnv(t)
	e.deps.PublicURL = func() string { return "https://alina.example" }
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "create_invite", map[string]any{"account_id": e.acctA, "label": "party"})
	if got := keysOf(t, text); isErr || len(cloudCreate) == 0 || !reflect.DeepEqual(got, cloudCreate) {
		t.Errorf("create_invite answered %s (keys %v); the cloud's createInvite answers %v", text, got, cloudCreate)
	}
	if !strings.Contains(text, `"url":"https://alina.example/i/`) {
		t.Errorf("create_invite's link is not at this node's address: %s", text)
	}
}

// Building rule 1 for a send: send_to_contact answers what the cloud's sendMessage answers
// (batondeck gateway/src/api/v1/routes/conversations.ts, which the cloud's owner MCP's send
// publishes as its outputSchema), key for key. The cloud's keys are read from its source, so a
// key either side adds or drops that the other does not turns this red.
func TestSendToContactAnswersWhatTheCloudsSendMessageAnswers(t *testing.T) {
	routes := string(testid.SiblingFile(t, "batondeck", "gateway/src/api/v1/routes/conversations.ts", "send_to_contact's answer is unchecked against the cloud's"))
	send := regexp.MustCompile(`(?s)operationId: 'sendMessage'.*?response: z\.object\(\{([^}]*)\}\)`).FindStringSubmatch(routes)
	if send == nil {
		t.Fatal("conversations.ts declares no sendMessage response")
	}
	var cloud []string
	for _, m := range regexp.MustCompile(`(\w+): z\.`).FindAllStringSubmatch(send[1], -1) {
		cloud = append(cloud, m[1])
	}
	sort.Strings(cloud)
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "send_to_contact", map[string]any{
		"account_id": e.acctA, "contact_fpr": "sha256:alina", "msg_id": "m1", "text": "hi"})
	if got := keysOf(t, text); isErr || len(cloud) == 0 || !reflect.DeepEqual(got, cloud) {
		t.Errorf("send_to_contact answered %s (keys %v); the cloud's sendMessage answers %v", text, got, cloud)
	}
}
