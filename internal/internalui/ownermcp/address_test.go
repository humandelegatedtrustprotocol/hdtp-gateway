package ownermcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// movedLeaf is a leaf under a fresh root, naming endpoint: what a contact that moved presents.
func movedLeaf(t *testing.T, cn, endpoint string) (root string, leaf []byte) {
	t.Helper()
	at := time.Now().Add(-time.Hour)
	rootKey, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	host, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{CN: cn, RootCN: cn, RootKey: rootKey, HostPub: host.Public(),
		Endpoint: endpoint, NotBefore: at, NotAfter: at.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return hdtpidentity.Fingerprint(rootKey.Public().SPKI), leaf
}

// N-18: the owner's agent had no way to answer a contact parked at a new address under `ask`
// (HDTP §5.3) — only the CLI did. These are the names the cloud's owner MCP already serves, so its
// parity divergence closes: list_pending_addresses, approve_address, reject_address.
func TestTheOwnerAgentDecidesAContactAtANewAddress(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var audited, invalidated []string
	e.deps.Audit = func(action, resource, outcome string) { audited = append(audited, action+" "+resource+" "+outcome) }
	e.deps.Invalidate = func(_ context.Context, accountID, fpr string) error {
		invalidated = append(invalidated, accountID+"/"+fpr)
		return nil
	}

	const oldAt, newAt = "https://old.example/alina", "https://new.example/alina"
	park := func(t *testing.T, acct, cn string) string {
		t.Helper()
		root, oldLeaf := movedLeaf(t, cn, oldAt)
		if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: root, SPKI: []byte{1}, Status: "active",
			Endpoint: oldAt, Leaf: oldLeaf, DisplayName: cn}); err != nil {
			t.Fatal(err)
		}
		_, newLeaf := movedLeaf(t, cn, newAt)
		if err := e.st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: acct, Root: root, Endpoint: newAt, Leaf: newLeaf, Why: "ask", At: 1}); err != nil {
			t.Fatal(err)
		}
		return root
	}
	approved, rejected := park(t, e.acctA, "Alina"), park(t, e.acctA, "Bo")
	elsewhere := park(t, e.acctB, "Cy")

	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner, AccountID: e.acctA}, nil)

	text, isErr := callJSON(t, cs, "list_pending_addresses", map[string]any{"account_id": e.acctA})
	if isErr {
		t.Fatalf("list_pending_addresses: %s", text)
	}
	var list []contacts.AddressWaiting
	if err := json.Unmarshal([]byte(text), &list); err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d, want the account's 2: %s", len(list), text)
	}
	for _, w := range list {
		if w.Endpoint != newAt || w.Pinned != oldAt || w.Why != "ask" || w.Name == "" {
			t.Errorf("listed %+v", w)
		}
	}
	// The certificates stay in the store: the agent decides by root, and DER is nobody's reading.
	if strings.Contains(text, "Leaf") || strings.Contains(text, "RootCert") {
		t.Errorf("the listing carries certificate material: %s", text)
	}

	// The change feed counts them, so an agent woken by the signal finds what woke it.
	text, _ = callJSON(t, cs, "digest", map[string]any{"account_id": e.acctA})
	var dg struct {
		Addresses int64 `json:"pending_addresses"`
	}
	if err := json.Unmarshal([]byte(text), &dg); err != nil || dg.Addresses != 2 {
		t.Fatalf("digest counts %d contacts at a new address, want 2: %s", dg.Addresses, text)
	}

	if text, isErr := callJSON(t, cs, "approve_address", map[string]any{"account_id": e.acctA, "root": approved}); isErr {
		t.Fatalf("approve_address: %s", text)
	}
	if c, _ := e.st.GetContact(ctx, e.acctA, approved); c.Endpoint != newAt {
		t.Fatalf("approving did not move the pin: %s", c.Endpoint)
	}
	if fe, _ := e.st.ListFormerEndpoints(ctx, e.acctA); len(fe) != 1 || fe[0].Endpoint != oldAt {
		t.Fatalf("the address it left is not remembered: %+v", fe)
	}
	if text, isErr := callJSON(t, cs, "reject_address", map[string]any{"account_id": e.acctA, "root": rejected}); isErr {
		t.Fatalf("reject_address: %s", text)
	}
	if c, _ := e.st.GetContact(ctx, e.acctA, rejected); c.Endpoint != oldAt {
		t.Fatalf("rejecting moved the pin: %s", c.Endpoint)
	}
	if left, _ := e.st.ListPendingAddresses(ctx, e.acctA); len(left) != 0 {
		t.Fatalf("decided addresses still wait: %+v", left)
	}
	want := []string{
		"contact_address_approve account:" + e.acctA + " contact:" + approved + " endpoint:" + newAt + " ok",
		"contact_address_reject account:" + e.acctA + " contact:" + rejected + " endpoint:" + newAt + " ok",
	}
	for _, w := range want {
		if !strings.Contains(strings.Join(audited, "\n"), w) {
			t.Errorf("not audited as the CLI and the portal audit it: %q\n%v", w, audited)
		}
	}
	if len(invalidated) != 2 || invalidated[0] != e.acctA+"/"+approved || invalidated[1] != e.acctA+"/"+rejected {
		t.Errorf("composed surfaces dropped for %v, want both roots", invalidated)
	}

	// A root nobody waits for is refused by name; a token narrowed to one account cannot decide
	// another's, and the other account's contact stays waiting.
	if text, isErr := callJSON(t, cs, "approve_address", map[string]any{"account_id": e.acctA, "root": approved}); !isErr || !strings.Contains(text, "unknown_contact") {
		t.Fatalf("a second answer: %v %s", isErr, text)
	}
	if _, isErr := callJSON(t, cs, "approve_address", map[string]any{"account_id": e.acctB, "root": elsewhere}); !isErr {
		t.Fatal("a token narrowed to one account decided another account's address")
	}
	if left, _ := e.st.ListPendingAddresses(ctx, e.acctB); len(left) != 1 {
		t.Fatalf("the other account's address: %+v", left)
	}
}
