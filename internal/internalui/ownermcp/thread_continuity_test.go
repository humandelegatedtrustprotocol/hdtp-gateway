package ownermcp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// resultThreadKey is the member send_to_contact answers the thread's id under, read from the
// answer's own encoding rather than written here.
func resultThreadKey(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(messaging.Result{ThreadID: "the-thread"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		if v == "the-thread" {
			return k
		}
	}
	t.Fatalf("messaging.Result encodes no thread id: %s", raw)
	return ""
}

// #232: every send_to_contact an agent made opened a new thread on both nodes, because a send
// without thread_id starts one (HDTP §7) and nothing the tool said told its caller so, nor what to
// pass to continue: the description was "Send a message to a contact" and thread_id had no
// description at all. What a client reads in tools/list is the whole contract it gets.
func TestSendToContactTellsItsCallerHowAThreadIsContinued(t *testing.T) {
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	key := resultThreadKey(t)
	for _, tl := range res.Tools {
		if tl.Name != "send_to_contact" {
			continue
		}
		for _, want := range []string{"without thread_id starts a new thread", "get_inbox", key} {
			if !strings.Contains(tl.Description, want) {
				t.Errorf("send_to_contact's description does not say %q: %q", want, tl.Description)
			}
		}
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		d := schema.Properties["thread_id"].Description
		for _, want := range []string{"continue", "none starts a new thread", key} {
			if !strings.Contains(d, want) {
				t.Errorf("thread_id's description does not say %q: %q", want, d)
			}
		}
		return
	}
	t.Fatal("tools/list has no send_to_contact")
}

var newThreadID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// What the description says, held at the door: a send without thread_id starts a new thread each
// time, under an id this node assigns (32 lower-case hex digits, SPEC §7); one naming the thread
// the first answered continues it; one naming another contact's thread is refused bad_request and
// records nothing (HDTP §7: a thread belongs to the contact that first used it).
func TestSendToContactContinuesTheThreadItNamesAndRefusesAnotherContacts(t *testing.T) {
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	ctx := context.Background()
	key := resultThreadKey(t)
	send := func(msgID, thread string) (string, map[string]string, bool) {
		t.Helper()
		args := map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:alina", "msg_id": msgID, "text": msgID}
		if thread != "" {
			args["thread_id"] = thread
		}
		text, isErr := callJSON(t, cs, "send_to_contact", args)
		var m map[string]string
		_ = json.Unmarshal([]byte(text), &m)
		return text, m, isErr
	}

	text, first, isErr := send("m1", "")
	if isErr || !newThreadID.MatchString(first[key]) {
		t.Fatalf("the first send: %s", text)
	}
	text, second, isErr := send("m2", "")
	if isErr || !newThreadID.MatchString(second[key]) || second[key] == first[key] {
		t.Fatalf("a second send without thread_id did not start a thread of its own: %s, the first was %s", text, first[key])
	}
	text, third, isErr := send("m3", first[key])
	if isErr || third[key] != first[key] {
		t.Fatalf("a send naming the first thread: %s, want %s", text, first[key])
	}
	if msgs, err := e.deps.Msg.Thread(ctx, e.acctA, first[key]); err != nil || len(msgs) != 2 {
		t.Fatalf("the first thread holds %d messages (%v), want 2", len(msgs), err)
	}

	const other = "tbharat"
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:bharat", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "b1", ThreadID: other, Text: "hi", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	if text, _, isErr := send("m4", other); !isErr || !strings.Contains(text, "bad_request") {
		t.Fatalf("a send to alina naming bharat's thread: %s (error %v), want bad_request", text, isErr)
	}
	if _, err := e.st.GetMessageByMsgID(ctx, e.acctA, "sha256:alina", string(messaging.DirOut), "m4"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refused send was recorded: %v", err)
	}
	if msgs, err := e.deps.Msg.Thread(ctx, e.acctA, other); err != nil || len(msgs) != 1 {
		t.Fatalf("bharat's thread holds %d messages (%v), want 1", len(msgs), err)
	}
	threads, err := e.st.ListThreadsByAccount(ctx, e.acctA)
	if err != nil || len(threads) != 3 {
		t.Fatalf("the account holds %d threads (%v), want 3: two of alina's and bharat's", len(threads), err)
	}
}
