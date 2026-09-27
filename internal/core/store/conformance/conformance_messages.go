package conformance

import (
	"context"
	"fmt"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
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

	// `expires` is chosen by the SENDER (PACT §7), so the column has to hold any
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
}
