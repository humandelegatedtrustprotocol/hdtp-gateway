package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// The review of 2026-09-28 on the one signing-request service both doors call.

func reviewLeafEnv(t *testing.T) (*identity.Manager, store.Account) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
	a, err := idm.CreateAccount(context.Background(), "alina", "Alina Rao", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	return idm, a
}

// L1. The install is committed before the live node reloads the account. A node that then fails
// to reload answers "installed, with a warning" — one audit row, `partial`, naming it — and starts
// no campaign, which would announce the card the node still holds. It used to be an error: a 500
// for a leaf that was in fact installed.
func TestAnInstallWhoseNodeCannotReloadIsInstalledWithAWarning(t *testing.T) {
	idm, a := reviewLeafEnv(t)
	ctx := context.Background()
	var rows []string
	resumed := 0
	l := leafService{
		idm:         idm,
		audit:       func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" → "+outcome) },
		endpointFor: func(slug string) string { return "https://node.example/a/" + slug + "/mcp" },
		adopt:       func(context.Context, string) error { return errors.New("the node's store is closed") },
		resume:      func(context.Context, string, string) bool { resumed++; return true },
	}
	// An imported contact is owed the handshake, so this install would start a campaign.
	if err := idm.Store.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:friend", Status: "active", TrustFlag: "messages_only", HandshakeDueAt: 1}); err != nil {
		t.Fatal(err)
	}
	csr, err := l.Mint(ctx, a, identity.PurposeSignup, "", "")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := pactidentity.GenerateKey("ed25519")
	now := time.Now()
	root, _ := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Alina Rao", Key: key, NotBefore: now.Add(-time.Hour)})
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{RootCN: "Alina Rao", RootKey: key, RootSPKIs: [][]byte{key.Public.SPKI}, Now: now, ValidDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.Install(ctx, a, [][]byte{iss.DER, root}, "")
	if err != nil {
		t.Fatalf("an installed leaf was answered as a failure: %v", err)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Code != "not_loaded" || !strings.Contains(res.Warnings[0].Text, "restart the node") {
		t.Fatalf("the warning: %+v", res.Warnings)
	}
	if strings.Contains(res.Warnings[0].Text, "store is closed") {
		t.Fatal("the warning carries the error's text")
	}
	if info, _ := idm.Certificate(ctx, a.ID, now); !info.Served() {
		t.Fatal("the leaf is not installed")
	}
	if res.HandshakesDue != 1 || res.Campaign {
		t.Fatalf("a campaign was owed and must not start on a node that did not load the leaf: %+v", res.InstallResult)
	}
	installs := 0
	for _, r := range rows {
		if strings.HasPrefix(r, "account_leaf_install ") {
			installs++
			if !strings.HasSuffix(r, "warning:not_loaded → partial") {
				t.Fatalf("the install's row: %s", r)
			}
		}
	}
	if installs != 1 || resumed != 0 {
		t.Fatalf("one install row and no campaign: %d rows, %d campaigns\n%s", installs, resumed, strings.Join(rows, "\n"))
	}
}

// L8. A request that is not made is audited on either door (the admin socket and the portal both
// call Mint): `refused` for a request this node does not make, never silently.
func TestARefusedRequestIsAudited(t *testing.T) {
	idm, a := reviewLeafEnv(t)
	var rows []string
	l := leafService{
		idm:         idm,
		audit:       func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" → "+outcome) },
		endpointFor: func(slug string) string { return "https://node.example/a/" + slug + "/mcp" },
	}
	// A web wallet does not take a first leaf (signup): refused before anything is written.
	if _, err := l.Mint(context.Background(), a, identity.PurposeSignup, "", "https://wallet.example"); err == nil {
		t.Fatal("a signup to a web wallet was minted")
	}
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "account_csr account:"+a.ID) || !strings.HasSuffix(rows[0], "reason:purpose → refused") {
		t.Fatalf("the refused request's row: %q", rows)
	}
}
