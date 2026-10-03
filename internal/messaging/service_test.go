package messaging

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

func newSvc(t *testing.T) (*Service, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1756000000, 0)
	return &Service{Store: st, Now: func() time.Time { return clock }}, a.ID
}

const alina = "sha256:alina"

func TestDuplicateMsgIDAcknowledgedNotReexecuted(t *testing.T) {
	svc, acct := newSvc(t)
	ctx := context.Background()
	r1, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m1", Text: "hello", Sender: SenderAgent})
	if err != nil {
		t.Fatal(err)
	}
	// same msg_id, even with DIFFERENT content: original response, no new row
	r2, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m1", Text: "DIFFERENT", Sender: SenderAgent})
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatalf("replay changed the response: %+v vs %+v", r1, r2)
	}
	msgs, _ := svc.Thread(ctx, acct, r1.ThreadID)
	if len(msgs) != 1 || msgs[0].Body != "hello" {
		t.Fatalf("replay wrote a row or mutated content: %+v", msgs)
	}
}

func TestThreadIDSharedAcrossDirections(t *testing.T) {
	svc, acct := newSvc(t)
	ctx := context.Background()
	in, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m1", Text: "hi", Topic: "coffee", Sender: SenderAgent})
	if err != nil {
		t.Fatal(err)
	}
	// our reply travels on THEIR thread id
	out, err := svc.Record(ctx, acct, alina, DirOut, Input{Origin: OriginPeer, MsgID: "m2", ThreadID: in.ThreadID, Text: "hello!", Sender: SenderHuman})
	if err != nil {
		t.Fatal(err)
	}
	if out.ThreadID != in.ThreadID {
		t.Fatalf("thread id not shared: %s vs %s", out.ThreadID, in.ThreadID)
	}
	msgs, _ := svc.Thread(ctx, acct, in.ThreadID)
	if len(msgs) != 2 || msgs[0].Direction != "in" || msgs[1].Direction != "out" || msgs[1].Sender != "human" {
		t.Fatalf("thread contents wrong: %+v", msgs)
	}
}

func TestPeerSuppliedThreadIDAdoptedOnFirstSight(t *testing.T) {
	svc, acct := newSvc(t)
	ctx := context.Background()
	r, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m1", ThreadID: "their-thread-42", Text: "x", Sender: SenderAgent})
	if err != nil || r.ThreadID != "their-thread-42" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestThreadNeverCrossesContacts(t *testing.T) {
	svc, acct := newSvc(t)
	ctx := context.Background()
	r, _ := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m1", Text: "x", Sender: SenderAgent})
	_, err := svc.Record(ctx, acct, "sha256:other", DirIn, Input{Origin: OriginPeer, MsgID: "m2", ThreadID: r.ThreadID, Text: "y", Sender: SenderAgent})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("cross-contact thread accepted: %v", err)
	}
}

func TestTextCap(t *testing.T) {
	svc, acct := newSvc(t)
	big := strings.Repeat("a", 16*1024+1)
	_, err := svc.Record(context.Background(), acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m1", Text: big, Sender: SenderAgent})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("16 KiB cap not enforced: %v", err)
	}
	// exactly at the cap is fine
	ok := strings.Repeat("a", 16*1024)
	if _, err := svc.Record(context.Background(), acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m2", Text: ok, Sender: SenderAgent}); err != nil {
		t.Fatal(err)
	}
}

func TestSenderLabelValidated(t *testing.T) {
	svc, acct := newSvc(t)
	_, err := svc.Record(context.Background(), acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m1", Text: "x", Sender: "robot"})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bogus sender accepted: %v", err)
	}
	if _, err := svc.Record(context.Background(), acct, alina, DirIn, Input{Origin: OriginPeer, Text: "x", Sender: SenderAgent}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("missing msg_id accepted: %v", err)
	}
}

// AC (P12-04): idempotency is per-SENDER. A msg_id a contact used for a message
// they sent us must not swallow a message WE send them.
//
// The uniqueness constraint and the idempotency lookup were both direction-blind,
// so an outbound message whose msg_id matched any inbound one from the same
// contact was never written — and `record` returned the inbound row's status,
// which is "delivered". The owner saw their message sitting in the thread marked
// delivered; it had never been written, let alone sent.
//
// The peer chooses their own msg_id, so this is reachable on purpose: a contact
// who sends a message with the id our composer is about to mint gets our next
// reply silently dropped.
func TestAnInboundMsgIDDoesNotSwallowAnOutboundMessage(t *testing.T) {
	svc, acct := newSvc(t)
	ctx := context.Background()

	in, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "ui-abc123", Text: "from them", Sender: SenderHuman})
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.Record(ctx, acct, alina, DirOut,
		Input{Origin: OriginPeer, MsgID: "ui-abc123", ThreadID: in.ThreadID, Text: "from us", Sender: SenderHuman})
	if err != nil {
		t.Fatalf("an outbound message reusing an inbound msg_id was refused: %v", err)
	}
	if out.Status == "delivered" {
		t.Fatalf("an outbound message was reported %q before anything was sent — "+
			"that is the inbound row's status being handed back", out.Status)
	}

	msgs, err := svc.Thread(ctx, acct, in.ThreadID)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, m := range msgs {
		dirs = append(dirs, m.Direction+":"+m.Body)
	}
	if len(msgs) != 2 {
		t.Fatalf("thread holds %d messages, want 2 (one each way): %v", len(msgs), dirs)
	}
}

// HDTP §6.2's honesty rule is about who composed a message, and the only thing
// that knows is the surface it arrived on. It used to be a constant each call
// site picked for itself, so a new surface — or an argument wired through by
// mistake — could label an agent's message as a person's, and nothing would
// catch it. The label is now derived here, and a caller's claim is ignored.
func TestTheSurfaceDecidesTheSenderLabel(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		origin Origin
		claim  Sender
		want   Sender
	}{
		{"portal is a person typing", OriginPortal, "", SenderHuman},
		{"portal claiming agent is still a person", OriginPortal, SenderAgent, SenderHuman},
		{"mcp is an agent acting", OriginMCP, "", SenderAgent},
		{"mcp claiming human is still an agent", OriginMCP, SenderHuman, SenderAgent},
		{"a peer labels its own side", OriginPeer, SenderHuman, SenderHuman},
		{"and its agent side too", OriginPeer, SenderAgent, SenderAgent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, acct := newSvc(t)
			dir := DirOut
			if tc.origin == OriginPeer {
				dir = DirIn
			}
			if _, err := svc.Record(ctx, acct, "sha256:peer", dir,
				Input{MsgID: "m1", Text: "hi", Origin: tc.origin, Sender: tc.claim}); err != nil {
				t.Fatal(err)
			}
			m, err := svc.Store.GetMessageByMsgID(ctx, acct, "sha256:peer", string(dir), "m1")
			if err != nil {
				t.Fatal(err)
			}
			if Sender(m.Sender) != tc.want {
				t.Fatalf("labelled %q, want %q", m.Sender, tc.want)
			}
		})
	}

	// A surface that says nothing is refused rather than guessed at.
	svc, acct := newSvc(t)
	if _, err := svc.Record(ctx, acct, "sha256:peer", DirOut, Input{MsgID: "m9", Text: "hi"}); err == nil {
		t.Fatal("a message with no origin was recorded; its label would be a guess")
	}
	// A peer that claims nonsense is refused; absent is agent, decided upstream.
	if _, err := svc.Record(ctx, acct, "sha256:peer", DirIn,
		Input{MsgID: "m8", Text: "hi", Origin: OriginPeer, Sender: "the_president"}); err == nil {
		t.Fatal("a peer's invented sender label was accepted")
	}
}

// A retry re-sends a row this node already recorded, and the label on that row
// is a fact — the message was composed on a surface, once. Deriving it again
// from an origin the sweeper does not have relabelled every retried human
// message as `agent`, and the peer stored that permanently: the exact inversion
// of HDTP §6.2 the origin change was written to prevent.
func TestAStoredMessageKeepsTheLabelItWasComposedWith(t *testing.T) {
	if got := (Input{Origin: OriginStored, Sender: SenderHuman}).Label(); got != SenderHuman {
		t.Fatalf("a retried human message went out as %q", got)
	}
	if got := (Input{Origin: OriginStored, Sender: SenderAgent}).Label(); got != SenderAgent {
		t.Fatalf("a retried agent message went out as %q", got)
	}
	// The bug in one line: without an origin, the wire label is derived from a
	// surface the sweeper is not, and the zero value reads as agent.
	if got := (Input{Sender: SenderHuman}).Label(); got == SenderHuman {
		t.Fatal("an Input with no origin now claims a label; the guard that catches a missing origin is gone")
	}
	// Recording a stored message again would duplicate the row being retried.
	svc, acct := newSvc(t)
	if _, err := svc.Record(context.Background(), acct, alina, DirOut,
		Input{Origin: OriginStored, MsgID: "s1", Text: "hi", Sender: SenderHuman}); err == nil {
		t.Fatal("a stored message was recorded a second time")
	}
}
