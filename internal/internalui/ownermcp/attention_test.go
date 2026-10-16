package ownermcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// An integration that lands in auth_error ends a wait once, and an integration that stays there
// does not end the next one. A real Manager against an upstream answering 401, its OnAuthError
// wired as serve.go wires it: the connect ends the wait parked on the cursor before it, with the
// integration in needs_attention; two health cycles that find the token still dead are not news, so
// a wait from the cursor that answer gave parks until its clock and still reports the integration.
// Each health cycle used to fire OnAuthError again, and its EventAttention ended every wait.
func TestAnIntegrationStillNeedingReauthorizationDoesNotEndAWait(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer upstream.Close()
	in, err := e.st.InsertIntegration(ctx, store.Integration{AccountID: e.acctA, Slug: "cal", Transport: "streamable-http", Endpoint: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	m := &integrations.Manager{Store: e.st, PingEvery: -1, OnAuthError: func(integrationID string) {
		if in, err := e.st.GetIntegrationByID(ctx, integrationID); err == nil {
			e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventAttention, AccountID: in.AccountID})
		}
	}}

	wait := func(since int64, timeout int) (waitResult, time.Duration) {
		t.Helper()
		began := time.Now()
		text, isErr := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA, "since": since, "timeout_sec": timeout})
		var r waitResult
		if isErr || json.Unmarshal([]byte(text), &r) != nil {
			t.Fatalf("wait_for_updates: %s", text)
		}
		return r, time.Since(began)
	}
	var start waitResult
	first, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA})
	if err := json.Unmarshal([]byte(first), &start); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect(ctx, in.ID); err == nil {
		t.Fatal("a connect to an upstream answering 401 succeeded")
	}
	woke, _ := wait(start.Cursor, 4)
	if woke.TimedOut || len(woke.NeedsAttention) != 1 || woke.NeedsAttention[0].Integration != "cal" {
		t.Fatalf("the control: an integration newly in auth_error did not end the wait: %+v", woke)
	}
	for range 2 {
		if err := m.HealthCheck(ctx, in.ID); err == nil {
			t.Fatal("a health check against an upstream answering 401 succeeded")
		}
	}
	if got, err := e.st.GetIntegrationByID(ctx, in.ID); err != nil || got.Status != "auth_error" {
		t.Fatalf("after two health cycles: %+v %v", got, err)
	}
	again, took := wait(woke.Cursor, 1)
	if !again.TimedOut || took < time.Second {
		t.Errorf("a wait over an integration still in auth_error answered after %s, timed_out %v: %+v", took, again.TimedOut, again)
	}
	if len(again.NeedsAttention) != 1 {
		t.Errorf("the parked wait does not report the integration still needing it: %+v", again)
	}
}
