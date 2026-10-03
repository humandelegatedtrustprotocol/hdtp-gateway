package conformance

import (
	"context"
	"fmt"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// messages is the suite for messages: the msg_id namespace per direction and a far-future expiry.
func messages(t *testing.T, newStore Factory) {
	// msg_id is the SENDER's idempotency key, so the two directions are separate
	// namespaces. Both engines must accept the same msg_id once each way, look
	// each up independently, and confine a status update to the outbound row.
	// This lives in the shared suite because the constraint is enforced by the
	// schema, and the two engines express it in different DDL — Postgres swaps a
	// named constraint, SQLite rebuilds the table.
	t.Run("MsgIDIsScopedToDirection", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "dir", DisplayName: "Dir", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		for i, dir := range []string{"in", "out"} {
			if err := s.InsertMessage(ctx, store.Message{
				ID: fmt.Sprintf("d%d", i), AccountID: a.ID, ContactFpr: "sha256:p",
				MsgID: "shared", ThreadID: "t1", Direction: dir, Sender: "human",
				Kind: "text", Body: dir, Status: "delivered", CreatedAt: 100,
			}); err != nil {
				t.Fatalf("a %s message could not reuse a msg_id the other direction holds: %v", dir, err)
			}
		}
		for _, dir := range []string{"in", "out"} {
			m, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", dir, "shared")
			if err != nil {
				t.Fatalf("looking up the %s message by its key: %v", dir, err)
			}
			if m.Direction != dir || m.Body != dir {
				t.Fatalf("key (%s, shared) returned the %s row", dir, m.Direction)
			}
		}
		// A delivery outcome belongs to the message we SENT. Without the
		// direction scope this rewrote whichever row matched first, so a peer's
		// message could be marked failed by our own send.
		if err := s.SetMessageStatus(ctx, a.ID, "sha256:p", "shared", "failed"); err != nil {
			t.Fatal(err)
		}
		in, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", "in", "shared")
		if err != nil {
			t.Fatal(err)
		}
		if in.Status != "delivered" {
			t.Fatalf("an outbound delivery outcome rewrote the INBOUND row: status %q", in.Status)
		}
		out, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", "out", "shared")
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != "failed" {
			t.Fatalf("the outbound row was not updated: status %q", out.Status)
		}
	})

	// `expires` is chosen by the SENDER (HDTP §7), so the column has to hold any
	// plausible epoch value. On Postgres it was INTEGER — 32-bit — where every
	// other epoch column is BIGINT: a far-future deadline made the INSERT fail
	// with "integer out of range" and the message was refused, and the column
	// stopped holding a timestamp at all in 2038.
	t.Run("MessageExpiryHoldsAFarFutureDeadline", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "exp", DisplayName: "Exp", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		const farFuture = int64(1) << 34 // year 2514, comfortably past 2038
		if err := s.InsertMessage(ctx, store.Message{
			ID: "e1", AccountID: a.ID, ContactFpr: "sha256:p", MsgID: "far",
			ThreadID: "t1", Direction: "out", Sender: "human", Kind: "text",
			Body: "hi", Status: "pending", CreatedAt: 100, ExpiresAt: farFuture,
		}); err != nil {
			t.Fatalf("a far-future expires was refused by the schema: %v", err)
		}
		m, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", "out", "far")
		if err != nil {
			t.Fatal(err)
		}
		if m.ExpiresAt != farFuture {
			t.Fatalf("expires_at round-tripped as %d, want %d", m.ExpiresAt, farFuture)
		}
	})

	// Read state (SPEC §7.6): the marker is threads.last_read_seq, and the unread count is read
	// from it, never stored. A conversation is every thread with one contact; the count stops at
	// its bound; marking is a high-water mark that a repeat or a stale mark cannot move, and it
	// reaches neither another contact's threads nor another identity's.
	t.Run("ReadMarkerCountsAndMarksAConversation", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "rd", DisplayName: "Rd", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "rd2", DisplayName: "Rd2", Algo: "p256"})
		const pat, quinn = "sha256:pat", "sha256:quinn"
		for _, th := range []store.Thread{
			{ID: "t1", AccountID: a.ID, ContactFpr: pat, CreatedAt: 100, LastAt: 100},
			{ID: "t2", AccountID: a.ID, ContactFpr: pat, CreatedAt: 100, LastAt: 100},
			{ID: "t3", AccountID: a.ID, ContactFpr: quinn, CreatedAt: 100, LastAt: 100},
			{ID: "t4", AccountID: b.ID, ContactFpr: pat, CreatedAt: 100, LastAt: 100},
		} {
			if err := s.InsertThread(ctx, th); err != nil {
				t.Fatal(err)
			}
		}
		n := 0
		put := func(acct, thread, fpr, dir string) {
			t.Helper()
			n++
			if err := s.InsertMessage(ctx, store.Message{
				ID: fmt.Sprintf("r%d", n), AccountID: acct, ContactFpr: fpr, MsgID: fmt.Sprintf("m%d", n),
				ThreadID: thread, Direction: dir, Sender: "human", Kind: "text", Body: "x", Status: "delivered", CreatedAt: 100,
			}); err != nil {
				t.Fatal(err)
			}
		}
		put(a.ID, "t1", pat, "in")
		put(a.ID, "t1", pat, "in")
		put(a.ID, "t2", pat, "in")
		put(a.ID, "t2", pat, "out") // ours: never unread
		put(a.ID, "t3", quinn, "in")
		put(b.ID, "t4", pat, "in")
		unread := func(acct, fpr string, upTo int) int64 {
			t.Helper()
			got, err := s.UnreadWithContactUpTo(ctx, acct, fpr, upTo)
			if err != nil {
				t.Fatal(err)
			}
			return got
		}
		if got := unread(a.ID, pat, 100); got != 3 {
			t.Fatalf("pat's conversation over two threads counted %d unread, want 3", got)
		}
		if got := unread(a.ID, pat, 2); got != 2 {
			t.Fatalf("a count bounded at 2 answered %d", got)
		}
		if got, _ := s.ListContactsWithUnread(ctx, a.ID); len(got) != 2 || got[0] != pat || got[1] != quinn {
			t.Fatalf("contacts with unread: %v, want [pat quinn]", got)
		}

		seqs := map[string][]int64{}
		for _, th := range []string{"t1", "t2", "t4"} {
			acct := a.ID
			if th == "t4" {
				acct = b.ID
			}
			rows, err := s.ListMessagesByThread(ctx, acct, th)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range rows {
				seqs[th] = append(seqs[th], m.Seq)
			}
		}
		newest := seqs["t2"][1] // the newest of pat's conversation, our own reply
		if ok, _ := s.ConversationHasMessage(ctx, a.ID, pat, newest); !ok {
			t.Fatal("a message of pat's conversation is not one")
		}
		if ok, _ := s.ConversationHasMessage(ctx, a.ID, pat, seqs["t4"][0]); ok {
			t.Fatal("another identity's message counted as one of this conversation")
		}
		if ok, _ := s.ConversationHasMessage(ctx, a.ID, quinn, newest); ok {
			t.Fatal("pat's message counted as one of quinn's conversation")
		}

		// Through the first message only: what came after stays unread.
		if moved, err := s.MarkConversationReadThrough(ctx, a.ID, pat, seqs["t1"][0]); err != nil || moved != 2 {
			t.Fatalf("marking through the first message moved %d threads (%v), want 2", moved, err)
		}
		if got := unread(a.ID, pat, 100); got != 2 {
			t.Fatalf("after marking through the first message %d stay unread, want 2", got)
		}
		if moved, _ := s.MarkConversationReadThrough(ctx, a.ID, pat, newest); moved != 2 {
			t.Fatalf("marking through the newest moved %d threads, want 2", moved)
		}
		if got := unread(a.ID, pat, 100); got != 0 {
			t.Fatalf("a conversation read through its newest message has %d unread", got)
		}
		if moved, _ := s.MarkConversationReadThrough(ctx, a.ID, pat, newest); moved != 0 {
			t.Fatalf("marking again moved %d threads; a repeat must change nothing", moved)
		}
		if moved, _ := s.MarkConversationReadThrough(ctx, a.ID, pat, seqs["t1"][0]); moved != 0 {
			t.Fatalf("a stale mark moved %d threads; the marker is never lowered", moved)
		}
		if got := unread(a.ID, pat, 100); got != 0 {
			t.Fatalf("a stale mark brought back %d unread", got)
		}
		if got := unread(a.ID, quinn, 100); got != 1 {
			t.Fatalf("marking pat read touched quinn's conversation: %d unread, want 1", got)
		}
		if got := unread(b.ID, pat, 100); got != 1 {
			t.Fatalf("marking pat read on one identity touched another's: %d unread, want 1", got)
		}
		put(a.ID, "t1", pat, "in")
		if got := unread(a.ID, pat, 100); got != 1 {
			t.Fatalf("a message arriving after the mark counted %d unread, want 1", got)
		}

		// One thread: MarkThreadReadThrough moves that thread alone.
		t3, _ := s.ListMessagesByThread(ctx, a.ID, "t3")
		if moved, err := s.MarkThreadReadThrough(ctx, a.ID, "t3", t3[0].Seq); err != nil || moved != 1 {
			t.Fatalf("marking quinn's thread moved %d (%v), want 1", moved, err)
		}
		if moved, _ := s.MarkThreadReadThrough(ctx, a.ID, "t3", t3[0].Seq); moved != 0 {
			t.Fatalf("marking quinn's thread again moved %d", moved)
		}
		if got, _ := s.UnreadCount(ctx, a.ID, "t3"); got != 0 {
			t.Fatalf("quinn's thread read through its message has %d unread", got)
		}
		if got, _ := s.ListContactsWithUnread(ctx, a.ID); len(got) != 1 || got[0] != pat {
			t.Fatalf("contacts with unread after the marks: %v, want [pat]", got)
		}
	})
}
