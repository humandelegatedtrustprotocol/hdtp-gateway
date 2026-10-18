package messaging

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// A message's change row says which message it is, which way it went and what kind it is, so the
// webhooks (internal/services/webhooks) can tell a message received from one sent and a file from a
// text. Until the webhooks plan's W0 probe (docs/release/webhooks-2026-10-18.md) the rows of an
// inbound and an outbound message were the same row. A deleted thread names no message, so nothing
// reads its row as a message that arrived.
func TestAMessagesChangeRowNamesTheMessageItsDirectionAndItsKind(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "c.db"))
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
	svc := &Service{Store: st, Bus: NewBus(st), Now: func() time.Time { return clock }}
	media := &MediaService{Store: st, Blobs: BlobDir{Root: filepath.Join(dir, "blobs")}, Now: func() time.Time { return clock }}

	in, err := svc.Record(ctx, a.ID, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m-in", Text: "hi", Sender: SenderAgent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Record(ctx, a.ID, alina, DirOut, Input{Origin: OriginPortal, MsgID: "m-out", ThreadID: in.ThreadID, Text: "yo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := media.ReceiveInline(ctx, svc, a.ID, alina, Input{Origin: OriginPeer, MsgID: "m-file", ThreadID: in.ThreadID, Sender: SenderAgent}, "a.txt", "text/plain", []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	if _, err := media.SendInline(ctx, svc, a.ID, alina, Input{Origin: OriginPortal, MsgID: "m-file-out", ThreadID: in.ThreadID}, "b.txt", "text/plain", []byte("other")); err != nil {
		t.Fatal(err)
	}
	if _, err := media.ReceiveURL(ctx, svc, a.ID, alina, Input{Origin: OriginPeer, MsgID: "m-link", ThreadID: in.ThreadID, Sender: SenderAgent}, "c.pdf", "application/pdf", "https://files.example/c.pdf"); err != nil {
		t.Fatal(err)
	}
	// A replay records nothing and so says nothing.
	if _, err := svc.Record(ctx, a.ID, alina, DirIn, Input{Origin: OriginPeer, MsgID: "m-in", Text: "hi", Sender: SenderAgent}); err != nil {
		t.Fatal(err)
	}

	rows, err := st.ChangesAfter(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Deleting the thread takes its rows with it and writes one that names no message.
	if _, err := svc.DeleteThread(ctx, a.ID, in.ThreadID); err != nil {
		t.Fatal(err)
	}
	gone, err := st.ChangesAfter(ctx, rows[len(rows)-1].ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, gone...)
	type said struct{ msgID, direction, kind string }
	var got []said
	for _, c := range rows {
		if c.Kind != string(EventMessage) || c.AccountID != a.ID || c.ContactFpr != alina {
			t.Fatalf("a row that is not this account's message row: %+v", c)
		}
		got = append(got, said{c.MsgID, c.Direction, c.MsgKind})
	}
	want := []said{
		{"m-in", "in", "text"}, {"m-out", "out", "text"}, {"m-file", "in", "media"},
		{"m-file-out", "out", "media"}, {"m-link", "in", "media"},
		{"", "", ""}, // the deleted thread
	}
	if len(got) != len(want) {
		t.Fatalf("the change log holds %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d says %+v, want %+v (all: %v)", i, got[i], want[i], got)
		}
	}
	// What the log holds is what a reader of it is handed.
	if e := EventOf(rows[2]); e.MsgID != "m-file" || e.Direction != DirIn || e.MsgKind != "media" {
		t.Fatalf("EventOf dropped the message: %+v", e)
	}
}
