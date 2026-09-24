package internalui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// failingRevoke is a store whose invite revocation fails as a store fails: not "no such invite".
type failingRevoke struct{ store.Store }

func (failingRevoke) RevokeInvite(context.Context, string, string, int64) error {
	return errors.New("database is locked")
}

// A failed revocation is not an absent invite: only ErrNotFound is a 404. The portal answered 404
// for any error, so a store fault told the owner the invite did not exist (review of #22, finding 3;
// the owner MCP's revoke_invite had the same shape and is held in ownermcp).
func TestRevokeInviteSaysNotFoundOnlyWhenItIsNot(t *testing.T) {
	_, st, _, acct := manageEnv(t)
	ctx := context.Background()
	inv, err := st.InsertInvite(ctx, store.Invite{AccountID: acct, TokenHash: []byte("h-rf"), ExpiresAt: 1 << 40, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	mount := func(s store.Store) *http.ServeMux {
		mux := http.NewServeMux()
		MountManagePages(mux, ManageDeps{Store: s, Contacts: &contacts.Manager{Store: st}, Audit: (&recAudit{}).fn,
			PublicURL: func() string { return "https://pact.example" }})
		return mux
	}
	if rr := postForm(t, mount(failingRevoke{st}), "/invites/"+inv.ID+"/revoke?account="+acct, url.Values{}); rr.Code != http.StatusInternalServerError {
		t.Fatalf("a store failure answered %d; it is not a missing invite", rr.Code)
	}
	if rr := postForm(t, mount(st), "/invites/no-such-invite/revoke?account="+acct, url.Values{}); rr.Code != http.StatusNotFound {
		t.Fatalf("a missing invite answered %d, want 404", rr.Code)
	}
	if rr := postForm(t, mount(st), "/invites/"+inv.ID+"/revoke?account="+acct, url.Values{}); rr.Code != http.StatusSeeOther {
		t.Fatalf("the control: a live invite answered %d, want 303", rr.Code)
	}
}
