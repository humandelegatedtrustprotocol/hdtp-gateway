package internalui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// approveEnv is the manage pages with the peer-notification hook recorded.
type toldApproval struct {
	fpr      string
	granted  []string
	deadline time.Duration // how long the call was allowed; 0 = no deadline at all
}

func approveEnv(t *testing.T, answer error) (*http.ServeMux, *store.SQLite, string, *[]toldApproval) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	var told []toldApproval
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{
		Store: st, Contacts: &contacts.Manager{Store: st}, Audit: func(string, string, string) {},
		Approved: func(ctx context.Context, _, fpr string, granted []string) error {
			rec := toldApproval{fpr: fpr, granted: granted}
			if dl, ok := ctx.Deadline(); ok {
				rec.deadline = time.Until(dl)
			}
			told = append(told, rec)
			return answer
		},
	})
	return mux, st, a.ID, &told
}

// N-06: the peer is told the grant the row holds. A request that came through an invite already
// holds the invite's grant; approving it without naming a preset kept that grant here and told the
// peer nothing — `permissions` absent — so their agent listed no tools it may call on us.
func TestApproveTellsThePeerTheGrantTheRowHolds(t *testing.T) {
	mux, st, acct, told := approveEnv(t, nil)
	ctx := context.Background()
	invited := []string{"message.text", "status.view"}
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: "sha256:inv", Status: "pending_in",
		Preset: "work", Permissions: invited, InviteID: "inv-1"}); err != nil {
		t.Fatal(err)
	}
	if rr := postForm(t, mux, "/requests/sha256:inv/approve?account="+acct, url.Values{"preset": {""}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	c, _ := st.GetContact(ctx, acct, "sha256:inv")
	if len(*told) != 1 || !slices.Equal((*told)[0].granted, c.Permissions) || len(c.Permissions) != len(invited) {
		t.Fatalf("the row grants %v and the peer was told %+v", c.Permissions, *told)
	}
}

// N-05: an approval the peer could not hear still stands, and the owner is told that — the
// handler computed the notice and threw it away, then redirected with nothing to show.
func TestApproveCarriesTheCouldNotBeToldNotice(t *testing.T) {
	mux, st, acct, _ := approveEnv(t, errors.New("dial tcp: connection refused"))
	ctx := context.Background()
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: "sha256:away", Status: "pending_in"}); err != nil {
		t.Fatal(err)
	}
	rr := postForm(t, mux, "/requests/sha256:away/approve?account="+acct, url.Values{"preset": {"basic"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("approve: %d", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if n := loc.Query().Get("notice"); !strings.Contains(n, "could not be told") || !strings.Contains(n, "connection refused") {
		t.Fatalf("redirect %q carries no could-not-be-told notice", loc)
	}
	if c, _ := st.GetContact(ctx, acct, "sha256:away"); c.Status != "active" {
		t.Fatalf("an unreachable peer undid the approval: %s", c.Status)
	}
}

// N-21: telling the peer is bounded like removal's courtesy call. It ran on the request's own
// context, so an unreachable peer held the owner's POST for the outbound client's thirty seconds.
func TestApproveTellsThePeerWithinABudget(t *testing.T) {
	mux, st, acct, told := approveEnv(t, nil)
	if _, err := st.InsertContact(context.Background(), store.Contact{AccountID: acct, Fingerprint: "sha256:b", Status: "pending_in"}); err != nil {
		t.Fatal(err)
	}
	postForm(t, mux, "/requests/sha256:b/approve?account="+acct, url.Values{"preset": {"basic"}})
	if len(*told) != 1 {
		t.Fatalf("told %d times", len(*told))
	}
	if d := (*told)[0].deadline; d <= 0 || d > 6*time.Second {
		t.Fatalf("the approval's call to the peer was allowed %v; want a bound of a few seconds", d)
	}
}

// N-01: blocked had no way out on any surface — the portal could reach blocked (reject) and
// leave it only by a silent delete. Block and unblock are the plan of record's D1, the rule the
// cloud follows: a contact the owner blocked comes back as it was; a request the owner rejected
// was never a contact and is forgotten, so its root may ask again.
func TestBlockAndUnblockOnTheContactPage(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "bu.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	acct := a.ID
	aud := &recAudit{}
	var invalidated []string
	inval := func(_ context.Context, _, fpr string) error { invalidated = append(invalidated, fpr); return nil }
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{Store: st, Audit: aud.fn, Invalidate: inval})
	MountManagePages(mux, ManageDeps{Store: st, Contacts: &contacts.Manager{Store: st}, Audit: aud.fn, Invalidate: inval})
	notice := func(t *testing.T, path string) (added, errMsg string) {
		t.Helper()
		rr := postForm(t, mux, path+"?account="+acct, url.Values{})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		loc, _ := url.Parse(rr.Header().Get("Location"))
		return loc.Query().Get("added"), loc.Query().Get("err")
	}

	t.Run("an active contact blocked, then unblocked, is the contact it was", func(t *testing.T) {
		if _, err := st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: "sha256:friend", Status: "pending_in"}); err != nil {
			t.Fatal(err)
		}
		postForm(t, mux, "/requests/sha256:friend/approve?account="+acct, url.Values{"preset": {"friend"}})
		before, _ := st.GetContact(ctx, acct, "sha256:friend")
		if _, e := notice(t, "/contacts/sha256:friend/block"); e != "" {
			t.Fatal(e)
		}
		if c, _ := st.GetContact(ctx, acct, "sha256:friend"); c.Status != "blocked" {
			t.Fatalf("block left %s", c.Status)
		}
		said, e := notice(t, "/contacts/sha256:friend/unblock")
		if e != "" || !strings.Contains(said, "contact again") {
			t.Fatalf("unblock said %q / %q", said, e)
		}
		after, err := st.GetContact(ctx, acct, "sha256:friend")
		if err != nil || after.Status != "active" || after.Preset != before.Preset || !slices.Equal(after.Permissions, before.Permissions) {
			t.Fatalf("unblocked %+v, was %+v", after, before)
		}
		if !aud.hasRow("contact_block", "contact:sha256:friend", "ok") || !aud.hasRow("contact_unblock", "contact:sha256:friend status:active", "ok") {
			t.Fatalf("not audited: %v", aud.rows)
		}
	})

	t.Run("a rejected request unblocked is forgotten, and may ask again", func(t *testing.T) {
		if _, err := st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: "sha256:asker", Status: "pending_in"}); err != nil {
			t.Fatal(err)
		}
		postForm(t, mux, "/requests/sha256:asker/reject?account="+acct, url.Values{})
		if c, _ := st.GetContact(ctx, acct, "sha256:asker"); c.Status != "blocked" {
			t.Fatalf("reject left %s", c.Status)
		}
		said, e := notice(t, "/contacts/sha256:asker/unblock")
		if e != "" || !strings.Contains(said, "forgotten") {
			t.Fatalf("unblock said %q / %q", said, e)
		}
		if _, err := st.GetContact(ctx, acct, "sha256:asker"); err == nil {
			t.Fatal("a rejected request came back from an unblock; it was never a contact")
		}
		if !slices.Contains(invalidated, "sha256:asker") {
			t.Error("the forgotten caller's composed surface was not dropped")
		}
	})

	t.Run("unblocking what is not blocked, or nobody, is refused and changes nothing", func(t *testing.T) {
		if _, e := notice(t, "/contacts/sha256:friend/unblock"); e == "" {
			t.Fatal("unblocking an active contact was accepted")
		}
		if _, e := notice(t, "/contacts/sha256:nobody/unblock"); e == "" {
			t.Fatal("unblocking a contact that does not exist was accepted")
		}
		if _, e := notice(t, "/contacts/sha256:nobody/block"); e == "" {
			t.Fatal("blocking a contact that does not exist was accepted")
		}
		if c, _ := st.GetContact(ctx, acct, "sha256:friend"); c.Status != "active" {
			t.Fatalf("a refused unblock changed the contact: %s", c.Status)
		}
	})
}

// P-13: rejecting a request tells the requester, so a node that asked is not left at pending_out
// for ever. The node never sent `contact_rejected`; the cloud already did.
func TestRejectTellsTheRequesterWithinABudget(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "rj.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	var told []string
	var allowed time.Duration
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{Store: st, Contacts: &contacts.Manager{Store: st}, Audit: func(string, string, string) {},
		Rejected: func(ctx context.Context, _, fpr string) error {
			told = append(told, fpr)
			if dl, ok := ctx.Deadline(); ok {
				allowed = time.Until(dl)
			}
			return errors.New("no route to host")
		}})
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:r", Status: "pending_in"}); err != nil {
		t.Fatal(err)
	}
	rr := postForm(t, mux, "/requests/sha256:r/reject?account="+a.ID, url.Values{})
	if len(told) != 1 || told[0] != "sha256:r" {
		t.Fatalf("the requester was told %v", told)
	}
	if allowed <= 0 || allowed > 6*time.Second {
		t.Fatalf("the call was allowed %v", allowed)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("notice"), "could not be told") {
		t.Fatalf("an unheard rejection was not reported to the owner: %s", loc)
	}
	if c, _ := st.GetContact(ctx, a.ID, "sha256:r"); c.Status != "blocked" {
		t.Fatalf("an unreachable requester undid the rejection: %s", c.Status)
	}
}
