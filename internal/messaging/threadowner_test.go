package messaging

import (
	"context"
	"errors"
	"testing"
)

const carlos = "sha256:carlos"

// Thread ids are SHARED and caller-supplied (HDTP §7): a peer sends the id it
// knows, and we adopt it on first sight. That is also the obvious way to be
// impersonated without forging anything -- Carlos cannot sign as Alina, but if he
// could name HER thread, his message would be stored under it and the owner would
// read it inside Alina's conversation. Attribution would be correct in the row and
// wrong on the screen, which is the only place it is read.
//
// The message is refused outright rather than re-homed into a thread of Carlos's
// own: silently moving it would make a hostile thread id a way to create threads
// in someone else's name and leave no signal that anything was attempted.
func TestAThreadCannotBeAdoptedByASecondContact(t *testing.T) {
	svc, acct := newSvc(t)
	ctx := context.Background()

	first, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "a1", Text: "hello", Sender: SenderHuman})
	if err != nil {
		t.Fatal(err)
	}
	if first.ThreadID == "" {
		t.Fatal("no thread was created for the first message")
	}

	_, err = svc.Record(ctx, acct, carlos, DirIn, Input{Origin: OriginPeer,
		MsgID: "c1", ThreadID: first.ThreadID, Text: "transfer approved", Sender: SenderHuman,
	})
	if err == nil {
		t.Fatal("a second contact adopted another contact's thread; their message " +
			"would render inside that conversation")
	}
	if !errors.Is(err, ErrBadRequest) {
		t.Errorf("refused, but not as a bad request: %v", err)
	}

	// And nothing of his was written into it.
	rows, err := svc.Store.ListMessagesByThread(ctx, acct, first.ThreadID)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range rows {
		if m.ContactFpr != alina {
			t.Errorf("thread %s holds a message attributed to %s", first.ThreadID, m.ContactFpr)
		}
	}
	if len(rows) != 1 {
		t.Errorf("thread holds %d messages, want just the original", len(rows))
	}
}

// The same id offered by the SAME contact is the normal case and must still work,
// or the check above would have made threads unusable rather than safe.
func TestTheOwningContactKeepsUsingItsThread(t *testing.T) {
	svc, acct := newSvc(t)
	ctx := context.Background()

	first, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer, MsgID: "a1", Text: "hello", Sender: SenderHuman})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Record(ctx, acct, alina, DirIn, Input{Origin: OriginPeer,
		MsgID: "a2", ThreadID: first.ThreadID, Text: "still me", Sender: SenderHuman,
	})
	if err != nil {
		t.Fatalf("a contact could not continue its own thread: %v", err)
	}
	if second.ThreadID != first.ThreadID {
		t.Errorf("continuation landed in thread %s, want %s", second.ThreadID, first.ThreadID)
	}
}
