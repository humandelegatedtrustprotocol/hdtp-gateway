package webhooks

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// A filter takes exactly the names the node emits, and a name the cloud sends that the node does
// not is refused: offering it would store a subscription that never fires (the cloud's "offers and
// accepts exactly the events that are sent, and refuses a reserved one").
func TestAFilterTakesExactlyTheEventsTheNodeSends(t *testing.T) {
	sent := Subscribable()
	want := []string{"message.received", "message.delivered", "message.failed", "media.received",
		"request.pending", "request.answered", "call.made"}
	if !slices.Equal(sent, want) {
		t.Fatalf("Subscribable() = %v, want %v", sent, want)
	}
	// The control: every name that is sent is a filter an owner may choose.
	if got := CheckEvents(sent); got != "" {
		t.Fatalf("CheckEvents refuses %q, which is sent", got)
	}
	// Names the cloud sends and the node does not (BatonDeck's gateway/src/events/registry.ts), and
	// the cloud's reserved ones.
	for _, name := range []string{"contact.requested", "contact.accepted", "booking.created", "integration.attention",
		"identity.renewed", "contact.address_pending", "workspace.owner_joined", "usage.threshold", "message.recieved", ""} {
		if got := CheckEvents([]string{"message.received", name}); got != name {
			t.Errorf("CheckEvents takes %q", name)
		}
	}
}

// Every name the table holds is one a real change row is delivered as, so no name is offered that
// nothing emits (Building rule 5). The message rows are written by the messaging service itself;
// the others are the rows their publishers write (internal/node/send.go setStatus,
// internal/integrations/agentanswered.go, internal/node/node.go's AuditAs), as messaging.EventOf
// reads them back.
func TestEveryChangeRowTheNodeWritesIsDeliveredAsItsNameOrNotAtAll(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alice", DisplayName: "Alice", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	const alina = "sha256:alina"
	clock := time.Unix(1_800_000_000, 0)
	bus := messaging.NewBus(st)
	msg := &messaging.Service{Store: st, Bus: bus, Now: func() time.Time { return clock }}
	media := &messaging.MediaService{Store: st, Blobs: messaging.BlobDir{Root: filepath.Join(dir, "blobs")}, Now: func() time.Time { return clock }}
	in, err := msg.Record(ctx, a.ID, alina, messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, MsgID: "m-in", Text: "hi", Sender: messaging.SenderAgent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := msg.Record(ctx, a.ID, alina, messaging.DirOut, messaging.Input{Origin: messaging.OriginPortal, MsgID: "m-out", ThreadID: in.ThreadID, Text: "yo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := media.ReceiveInline(ctx, msg, a.ID, alina, messaging.Input{Origin: messaging.OriginPeer, MsgID: "m-file", ThreadID: in.ThreadID, Sender: messaging.SenderAgent}, "a.txt", "text/plain", []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	for _, e := range []messaging.Event{
		{Kind: messaging.EventDelivery, AccountID: a.ID, ContactFpr: alina, ThreadID: in.ThreadID, Status: messaging.StatusDelivered, MsgID: "m-out"},
		{Kind: messaging.EventDelivery, AccountID: a.ID, ContactFpr: alina, ThreadID: in.ThreadID, Status: messaging.StatusFailed, MsgID: "m-out"},
		{Kind: messaging.EventPending, AccountID: a.ID, ContactFpr: alina, Ref: "pr-1"},
		{Kind: messaging.EventAnswered, AccountID: a.ID, Ref: "pr-1"},
		{Kind: messaging.EventRelayed, AccountID: a.ID, Ref: "pr-1"},
		{Kind: messaging.EventCall, AccountID: a.ID, ContactFpr: alina, Ref: core.ToolBookSlot},
		{Kind: messaging.EventCall, AccountID: a.ID, ContactFpr: alina},       // a contact's address moved
		{Kind: messaging.EventRequest, AccountID: a.ID, ContactFpr: alina},    // a request, or an address awaiting the owner
		{Kind: messaging.EventAttention, AccountID: a.ID},                     // names no integration
		{Kind: messaging.EventInvalidate, AccountID: a.ID, ContactFpr: alina}, // housekeeping
	} {
		bus.Publish(e)
	}
	rows, err := st.ChangesAfter(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Deleting the thread takes its rows with it and writes one that names no message.
	if _, err := msg.DeleteThread(ctx, a.ID, in.ThreadID); err != nil {
		t.Fatal(err)
	}
	gone, err := st.ChangesAfter(ctx, rows[len(rows)-1].ID, 100)
	if err != nil || len(gone) != 1 {
		t.Fatalf("the deleted thread wrote %+v %v, want one row", gone, err)
	}
	rows = append(rows, gone...)
	type sent struct {
		Type string
		Data map[string]any
	}
	var got []sent
	for _, c := range rows {
		env, ok := EnvelopeOf(c, a.ID)
		if !ok {
			continue
		}
		if env.ID != "evt_"+strconv.FormatInt(c.ID, 10) || env.CreatedAt != c.At*1000 || env.Identity != a.ID {
			t.Fatalf("the envelope of row %d: %+v", c.ID, env)
		}
		got = append(got, sent{env.Type, env.Data})
	}
	thread := in.ThreadID
	want := []sent{
		{"message.received", map[string]any{"thread_id": thread, "message_id": "m-in", "from": alina}},
		{"media.received", map[string]any{"thread_id": thread, "message_id": "m-file", "from": alina}},
		{"message.delivered", map[string]any{"thread_id": thread, "message_id": "m-out"}},
		{"message.failed", map[string]any{"thread_id": thread, "message_id": "m-out"}},
		{"request.pending", map[string]any{"request_id": "pr-1", "fingerprint": alina}},
		{"request.answered", map[string]any{"request_id": "pr-1"}},
		{"call.made", map[string]any{"fingerprint": alina, "capability": core.ToolBookSlot}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("delivered as\n%+v\nwant\n%+v", got, want)
	}
	// Every name the node offers was delivered once here: the table holds no name without an
	// emitter.
	var names []string
	for _, s := range got {
		names = append(names, s.Type)
	}
	sort.Strings(names)
	offered := Subscribable()
	sort.Strings(offered)
	if !slices.Equal(names, offered) {
		t.Fatalf("delivered %v, offered %v", names, offered)
	}
}

// The rule the cloud states for its envelope, asserted over the bytes that go out: ids and
// metadata, never content, in the cloud's key order (the cloud's "carries ids and metadata, and
// never content").
func TestTheBodyCarriesIdsAndMetadataAndNeverContent(t *testing.T) {
	body, err := EnvelopeBody(EventEnvelope{ID: "evt_1", Type: "message.received", CreatedAt: 1_800_000_000_000, Identity: "alice",
		Data: map[string]any{"thread_id": "th1", "message_id": "m1", "from": "sha256:abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"id":"evt_1","type":"message.received","created_at":1800000000000,"identity":"alice","data":{"from":"sha256:abc","message_id":"m1","thread_id":"th1"}}`; body != want {
		t.Fatalf("body\n%s\nwant\n%s", body, want)
	}
	for _, forbidden := range []string{"body", "text", "media", "card", "spki", "pkcs8", "key"} {
		if strings.Contains(body, `"`+forbidden+`"`) {
			t.Errorf("the body carries %q", forbidden)
		}
	}
	// No identity, no key; no data, an empty object.
	bare, _ := EnvelopeBody(EventEnvelope{ID: "evt_2", Type: "call.made", CreatedAt: 1})
	if bare != `{"id":"evt_2","type":"call.made","created_at":1,"data":{}}` {
		t.Fatalf("bare body %s", bare)
	}
}
