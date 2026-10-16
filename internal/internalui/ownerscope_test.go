package internalui

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/ownermcp"
)

// membershipsFail is the store with the owner's memberships unreadable.
type membershipsFail struct{ store.Store }

func (membershipsFail) ListMembershipsByOwner(context.Context, string) ([]store.Membership, error) {
	return nil, errors.New("sqlite: disk I/O error")
}

// The portal and the owner MCP give one answer to "may this owner act on this account": both decide
// through policy.OwnerScope and policy.AllowOwnerManage. An admin may; an owner with no membership of
// the account may not; an owner whose memberships cannot be read may not (fail closed), on both doors.
// (The store holds one role, admin.)
func TestThePortalAndTheOwnerMCPDecideScopeAlike(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := st.CreateOwnerWithID(ctx, "", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "admin", DisplayName: "Admin", Algo: "p256"})
	other, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
	if err := st.AddMembership(ctx, o.ID, admin.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	portal := func(s store.Store, account string) bool {
		return ownerAdmins(signedIn(httptest.NewRequest("GET", "/", nil), o.ID), s, account)
	}
	ownerMCP := func(s store.Store, account string) bool {
		srv := ownermcp.NewServerWithExtra(ownermcp.Deps{Store: s}, ownermcp.Extra{}, auth.Identity{OwnerID: o.ID})
		ct, sv := mcp.NewInMemoryTransports()
		ss, err := srv.Connect(ctx, sv, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ss.Close()
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cs.Close()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_inbox", Arguments: map[string]any{"account_id": account}})
		if err != nil {
			t.Fatal(err)
		}
		text := ""
		if len(res.Content) > 0 {
			if tc, ok := res.Content[0].(*mcp.TextContent); ok {
				text = tc.Text
			}
		}
		if res.IsError && !strings.Contains(text, "permission_denied") {
			t.Fatalf("get_inbox of %s: %s, want an answer or permission_denied", account, text)
		}
		return !res.IsError
	}
	for _, c := range []struct {
		name    string
		st      store.Store
		account string
		may     bool
	}{
		{"an admin", st, admin.ID, true},
		{"no membership", st, other.ID, false},
		{"memberships unreadable", membershipsFail{st}, admin.ID, false},
	} {
		if p, m := portal(c.st, c.account), ownerMCP(c.st, c.account); p != c.may || m != c.may {
			t.Errorf("%s: the portal says %v, the owner MCP %v; want %v on both", c.name, p, m, c.may)
		}
	}
}
