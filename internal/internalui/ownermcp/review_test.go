package ownermcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
)

// QA of 2026-09-28, item 4 (building rule 10: project, never spread). list_contacts answered the
// store's rows whole - the row id, the account id, the pinned key, the card, the invite id, the
// chain mark. It answers named fields, the cloud's where the node holds them (pact-cloud
// api/v1/routes/shared.ts `Contact`), and nothing else.
func TestListContactsAnswersNamedFieldsOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:bob", SPKI: []byte("spki"), Status: "active",
		Permissions: []string{"message.text"}, DisplayName: "Bob", Card: "BEGIN:VCARD\nEND:VCARD", Endpoint: "https://bob.example/a/bob/mcp",
		Leaf: []byte("leaf"), RootCert: []byte("root"), InviteID: "inv-1", ChainSentKid: "sha256:kid"}); err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	out, isErr := callJSON(t, cs, "list_contacts", map[string]any{"account_id": e.acctA})
	if isErr {
		t.Fatalf("list_contacts: %s", out)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("list_contacts is a list of one: %v %s", err, out)
	}
	var keys []string
	for k := range rows[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "created_at display_name endpoint fingerprint leaf permissions petname preset root_cert status their_permissions trust_flag"
	if got := strings.Join(keys, " "); got != want {
		t.Fatalf("list_contacts answers %q, want exactly %q", got, want)
	}
}

// QA of 2026-09-28, item 5 (building rule 1). create_invite answered a token and no link, so an
// agent holding the owner surface could not hand anybody an invite. It answers the cloud's shape
// (pact-cloud createInvite: id, url, expires_at): the link at this node's public address. With no
// public address there is nowhere for the link to land, and nothing is minted.
func TestCreateInviteAnswersTheLink(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.deps.PublicURL = func() string { return "" }
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	if out, isErr := callJSON(t, cs, "create_invite", map[string]any{"account_id": e.acctA, "label": "x"}); !isErr || !strings.Contains(out, "public address") {
		t.Fatalf("an invite with no public address: %s", out)
	}
	if l, _ := e.st.ListInvites(ctx, e.acctA); len(l) != 0 {
		t.Fatal("an invite with nowhere to land was minted")
	}
	e.deps.PublicURL = func() string { return "https://node.example/" }
	cs, _ = connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	out, isErr := callJSON(t, cs, "create_invite", map[string]any{"account_id": e.acctA, "label": "x"})
	var got map[string]any
	if isErr || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("create_invite: %s", out)
	}
	url, _ := got["url"].(string)
	if !strings.HasPrefix(url, "https://node.example/i/") || len(url) <= len("https://node.example/i/") || got["id"] == nil || got["expires_at"] == nil || len(got) != 3 {
		t.Fatalf("create_invite answered %s", out)
	}
}
