package ownermcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
)

// create_invite answers the URL the owner hands out, on the node's public origin (SPEC §4: the
// landing is `/i/<token>` on the issuer's host) — the same link the landing page's QR encodes. An
// owner's agent handed only the token had no way to say where it is redeemed, and the cloud's
// conformance battery, aimed at a node through this door, fell back to guessing and found 404s.
func TestCreateInviteAnswersTheLinkToHandOut(t *testing.T) {
	e := newEnv(t)
	e.deps.PublicURL = func() string { return "https://alice.example:8443/" }
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, isErr := callJSON(t, cs, "create_invite", map[string]any{"account_id": e.acctA, "label": "x", "max_uses": 1})
	if isErr {
		t.Fatalf("create_invite refused: %s", text)
	}
	var got struct{ Token, URL string }
	if err := json.Unmarshal([]byte(text), &got); err != nil || got.Token == "" {
		t.Fatalf("create_invite answered %s", text)
	}
	if want := "https://alice.example:8443/i/" + got.Token; got.URL != want {
		t.Errorf("url is %q, want %q", got.URL, want)
	}

	// Without a public origin there is no link to give, and none is made up.
	e.deps.PublicURL = nil
	cs2, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	text, _ = callJSON(t, cs2, "create_invite", map[string]any{"account_id": e.acctA, "max_uses": 1})
	if strings.Contains(text, `"url"`) {
		t.Errorf("with no public origin the answer carries a url: %s", text)
	}
}
