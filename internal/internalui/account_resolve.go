package internalui

// Which identity is this page about?
//
// Every account-scoped portal page reads `?account=`, and the dashboard's own
// navigation carried none — so following a link from the dashboard landed on a
// page with an empty account: `/card` answered 404, `POST /invites/create`
// answered 400, and the list pages rendered blank because a query for account ""
// matches nothing. The portal could not be used by clicking.
//
// The account is resolved here instead of being carried in the URL. That is a
// deliberate choice, not just a fix: which identity the owner is looking at is
// not something a link should have to spell out, and an id in the URL is one more
// thing to leak into a screenshot, a bookmark or a shared link.
//
// This is NOT an authorization boundary. The portal is the owner's own surface
// (SPEC §8.3) and shows every account on its dashboard; resolution decides what a
// page is ABOUT, never what the owner may see.

import (
	"context"
	"net/http"
	"strings"

	"github.com/tech-sumit/pact-gateway/internal/contacts"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// accountMiddleware fills in the account a page acts on when the request names
// none and the answer is unambiguous.
//
// A request that names an account keeps it — resolution fills a gap and never
// overrides a choice. With several identities nothing is filled in at all:
// guessing would show one person's inbox under another's name, and a blank page
// is a better answer than a confidently wrong one.
func accountMiddleware(st store.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			next.ServeHTTP(w, r)
			return
		}
		// No session: resolve nothing and refuse nothing. This runs INSIDE the
		// session gate, so the only requests that reach it without an owner are
		// the ones §8.3 leaves open — the sign-in view and the ceremonies. They
		// are static code and need no identity. Scoping them would 404 the
		// sign-in page itself on any node with exactly one account, which is to
		// say: lock the owner out of the way back in.
		if OwnerFrom(r.Context()) == "" {
			next.ServeHTTP(w, r)
			return
		}
		if named := accountParam(r); named != "" {
			if !ownerAdmins(r, st, named) {
				http.NotFound(w, r) // not 403: whether that account exists is not this owner's business
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		// A form carries the account in its BODY, so nothing about which identity
		// you are looking at reaches the address bar. ParseForm is idempotent —
		// it returns early once r.PostForm is set — so the handler still reads its
		// own form normally.
		id := ""
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil {
				id = r.PostForm.Get("account")
			}
		}
		if id == "" {
			id = soleAccountID(r.Context(), st)
		}
		// Resolution FILLS A GAP; it never refuses. An owner who administers no
		// account simply gets none filled in — pages that need one then show
		// nothing, which is the truth — while pages that need none (owners,
		// settings, identity) keep working. Refusing here 404'd the whole portal
		// for an owner whose accounts were provisioned before they registered.
		//
		// The refusal that matters is the NAMED case above: asking for a
		// specific account you do not administer.
		if id == "" || !ownerAdmins(r, st, id) {
			next.ServeHTTP(w, r)
			return
		}
		// Rewrite a COPY. Mutating the request's URL in place would edit a value
		// the caller still owns, and r.URL is shared with whatever wrapped us.
		u := *r.URL
		q := u.Query()
		q.Set("account", id)
		u.RawQuery = q.Encode()
		r2 := r.Clone(r.Context())
		r2.URL = &u
		next.ServeHTTP(w, r2)
	})
}

// presetNames is the node's preset names in a stable order — the owner's
// edited bundles when any exist, the documented defaults otherwise.
func presetNames(ctx context.Context, st store.SettingStore) []string {
	return contacts.LoadPresets(ctx, st).Names()
}

// soleAccountID returns the account id when the node has exactly one, else "".
func soleAccountID(ctx context.Context, st store.AccountStore) string {
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 {
		return ""
	}
	return accounts[0].ID
}

// withChrome adds what the shared shell needs to a page's template data.
//
// Both values come from the request, so no page has to be given a new dependency
// to wear the chrome — which is what kept the header on the dashboard alone.
// SignedIn is false when nothing signed in: a loopback portal serves with no
// login (SPEC §8.3), and a sign-out button there would promise something it
// cannot do.

// ownerAdmins reports whether the request may act on this account.
//
// SPEC §3.3 makes owner→account a MEMBERSHIP, and the owner MCP enforces it on
// every tool via policy.AllowOwnerManage. The portal enforced nothing: it took
// `account` from the query string or the form body and handed it straight to the
// store, so the only thing standing between a signed-in owner and another owner's
// identity was that v1 happens to create exactly one owner (passkeys.go joins the
// existing owner rather than creating a second). That is a property of today's
// registration flow, not an access-control decision, and it is not what the
// memberships table is for.
//
// There is no loopback carve-out: §8.3 requires a session on every bind, so a
// request with no owner is never entitled to an account.
func ownerAdmins(r *http.Request, st store.OwnerStore, accountID string) bool {
	owner := OwnerFrom(r.Context())
	if owner == "" {
		// No session, no account. This used to return true for the §8.3
		// loopback portal, which served with no login; that carve-out is gone
		// (every bind needs a session), so an owner-less request here is either
		// the zero-passkey setup window — which has no business reading an
		// account — or a bug. Both fail closed.
		return false
	}
	ms, err := st.ListMembershipsByOwner(r.Context(), owner)
	if err != nil {
		return false // fail closed: an unreadable membership list is not a grant
	}
	for _, m := range ms {
		if m.AccountID == accountID && m.Role == "admin" {
			return true
		}
	}
	return false
}

// accountParam is the account a request names in its `account` query parameter, "" when it
// names none (accountMiddleware fills it in when the request named none and the answer is
// unambiguous).
func accountParam(r *http.Request) string { return r.URL.Query().Get("account") }

// withAccount attributes an audit row to the account the request is about.
//
// The trail's account column is what scopes a narrowed token's reads (SPEC
// §11.6) and the portal's own audit page. A row written without it is readable
// by every owner on the node, including the ones who administer none of the
// accounts it concerns — so the column has to be filled wherever the account is
// known, and on this surface it always is.
func withAccount(r *http.Request, resource string) string {
	account := accountParam(r)
	if account == "" || strings.HasPrefix(resource, "account:") {
		return resource
	}
	if resource == "" {
		return "account:" + account
	}
	return "account:" + account + " " + resource
}
