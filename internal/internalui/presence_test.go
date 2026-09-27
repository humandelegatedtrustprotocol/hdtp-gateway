package internalui

import (
	"context"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// Presence is shown only when the contact granted `status.view`. A dot for
// somebody who has not agreed to be seen would be inventing a signal we are not
// entitled to — the permission is theirs to give (PACT §6.2).
func TestPresenceIsHiddenUnlessTheyGrantedStatusView(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		granted []string
		want    string
	}{
		{"nothing granted", nil, ""},
		{"messaging only", []string{"message.text"}, ""},
		{"status.view granted", []string{"message.text", "status.view"}, "away"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := store.Contact{
				AccountID: acct.ID, Fingerprint: "sha256:p-" + tc.name,
				TheirPermissions: tc.granted,
			}
			got, _ := presenceOf(ctx, e.st, acct.ID, nil, c)
			if got != tc.want {
				t.Errorf("presence = %q, want %q", got, tc.want)
			}
		})
	}
}

// Granted, the colour is EVIDENCE: a message they sent, or one we delivered to
// them, proves they were reachable at that moment. Nothing is probed.
func TestPresenceIsGreenOnlyWithRecentConfirmedContact(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	const fpr = "sha256:peer"
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: fpr, Status: "active",
		DisplayName: "Peer", Card: "BEGIN:VCARD...",
	}); err != nil {
		t.Fatal(err)
	}
	c := store.Contact{AccountID: acct.ID, Fingerprint: fpr,
		TheirPermissions: []string{"status.view"}}

	// No exchange at all: granted, but nothing to go on.
	if got, _ := presenceOf(ctx, e.st, acct.ID, nil, c); got != "away" {
		t.Errorf("with no history presence = %q, want away", got)
	}

	th := store.Thread{ID: "t1", AccountID: acct.ID, ContactFpr: fpr,
		CreatedAt: time.Now().Unix(), LastAt: time.Now().Unix()}
	if err := e.st.InsertThread(ctx, th); err != nil {
		t.Fatal(err)
	}
	threads := []store.Thread{th}

	// An UNDELIVERED outbound proves nothing about them.
	mustMsg(t, e.st, store.Message{AccountID: acct.ID, ContactFpr: fpr, ThreadID: th.ID,
		MsgID: "m1", Direction: "out", Sender: "human", Kind: "text", Status: "pending", Body: "x",
		CreatedAt: time.Now().Unix()})
	if got, _ := presenceOf(ctx, e.st, acct.ID, threads, c); got != "away" {
		t.Errorf("an undelivered message made them look online: %q", got)
	}

	// One that landed does.
	mustMsg(t, e.st, store.Message{AccountID: acct.ID, ContactFpr: fpr, ThreadID: th.ID,
		MsgID: "m2", Direction: "out", Sender: "human", Kind: "text", Status: "delivered", Body: "y",
		CreatedAt: time.Now().Unix()})
	if got, _ := presenceOf(ctx, e.st, acct.ID, threads, c); got != "online" {
		t.Errorf("a delivered message did not count as contact: %q", got)
	}
}

func mustMsg(t *testing.T, st store.Store, m store.Message) {
	t.Helper()
	if err := st.InsertMessage(context.Background(), m); err != nil {
		t.Fatalf("insert message: %v", err)
	}
}
