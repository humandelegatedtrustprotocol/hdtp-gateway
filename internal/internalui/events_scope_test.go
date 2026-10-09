package internalui

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// GET /events with no account resolved (several accounts on the node, none named) subscribed to
// every account's events, so a signed-in owner read the stream of accounts they do not
// administer. The stream carries only the accounts the owner administers.
func TestEventsCarryOnlyTheAccountsTheOwnerAdministers(t *testing.T) {
	ctx := context.Background()
	var bus *messaging.Bus
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		bus = messaging.NewBus(st)
		MountInboxPages(mux, InboxDeps{Store: st, Bus: bus})
	})
	me, session := e.signIn(t, "Me")
	them, _ := e.signIn(t, "Them")
	mine, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Theirs", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, them, theirs.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(e.h)
	defer srv.Close()
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /events: %d", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, ": connected") {
		t.Fatalf("preamble: %q %v", line, err)
	}

	// Theirs first, then mine, on one bus: the stream delivers in order, so anything of theirs it
	// carried arrives before the event of mine that ends the read.
	bus.Publish(messaging.Event{Kind: messaging.EventMessage, AccountID: theirs.ID, ContactFpr: "sha256:theirs"})
	bus.Publish(messaging.Event{Kind: messaging.EventMessage, AccountID: mine.ID, ContactFpr: "sha256:mine"})
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("the owner's own event never arrived: %v", err)
		}
		if strings.Contains(line, theirs.ID) {
			t.Fatalf("owner %s received an event of account %s: %q", me, theirs.ID, line)
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, mine.ID) {
			return
		}
	}
}
