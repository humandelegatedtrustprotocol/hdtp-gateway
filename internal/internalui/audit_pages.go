package internalui

// Audit view (SPEC §11.6): owner-visible only, filterable, read-only.

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
)

// AuditDeps is what the audit page reads: the trail, and the lists its ids are named from.
type AuditDeps struct {
	Store store.Store
	// Tokens names the owner-MCP tokens a row mentions (`token:<id>`), revoked ones included:
	// revoking is a timestamp, and the rows the token wrote still name it. Nil leaves them unnamed.
	Tokens *auth.TokenService
	// Passkeys names the passkeys a row mentions (`passkey:<id>`) by their tag. Nil leaves them
	// unnamed.
	Passkeys func(ctx context.Context) ([]auth.PasskeyInfo, error)
}

// MountAuditPages registers the audit view.
func MountAuditPages(mux *http.ServeMux, d AuditDeps) {
	mux.HandleFunc("GET /api/audit", d.getAPIAudit)
}

// getAPIAudit serves `GET /api/audit`.
func (d AuditDeps) getAPIAudit(w http.ResponseWriter, r *http.Request) {
	st := d.Store
	// The session gate normally guarantees an owner before this runs; a
	// mount that somehow lacks one must fail closed rather than serve the
	// node-wide trail to nobody in particular.
	owner := OwnerFrom(r.Context())
	if owner == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"identity_required"}`))
		return
	}
	actor := r.URL.Query().Get("actor")
	// Bounded by default. The trail grows with every public call, including
	// from callers who never authenticate, and has no automatic retention:
	// a page that fetched all of it worked until the day it did not.
	limit := 500
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, 5000)
	}
	// The scope is decided HERE, from the session's owner — never by what
	// the client volunteers. The first version of this scoping honoured a
	// named ?account= and read the whole trail when the parameter was
	// simply omitted, so sending less yielded more: any signed-in owner
	// could fetch every account's contacts, bookings and message rows.
	account := accountParam(r)
	var scope []string
	if account != "" {
		// Named: only if this owner administers it. The account middleware
		// enforces the same rule, but this handler must not depend on how
		// it happens to be mounted.
		if !ownerAdmins(r, st, account) {
			http.NotFound(w, r) // not 403: whether it exists is not this owner's business
			return
		}
		scope = []string{account}
	} else {
		admins, err := administered(r.Context(), st, owner)
		if err != nil {
			http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
			return
		}
		for id := range admins {
			scope = append(scope, id)
		}
		sort.Strings(scope)
		if len(scope) == 0 {
			// An owner who administers nothing still sees the node's own
			// rows — the per-account query returns them alongside any
			// account, and no real id is one character, so "-" matches no
			// account-scoped row.
			scope = []string{"-"}
		}
	}
	// One query per administered account, newest first. Each also carries
	// the node's own unattributed rows, so rows are deduped by seq before
	// the merged set is cut back down to the limit.
	seen := map[int64]bool{}
	rows := []store.AuditRow{}
	for _, id := range scope {
		part, err := st.ListAuditEventsPage(r.Context(), store.AuditPage{
			Actor: actor, Account: id, Limit: limit,
		})
		if err != nil {
			http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
			return
		}
		for _, row := range part {
			if !seen[row.Seq] {
				seen[row.Seq] = true
				rows = append(rows, row)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Seq > rows[j].Seq })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	names, err := d.names(r.Context(), scope, rows)
	if err != nil {
		http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
		return
	}
	apiJSON(w, map[string]any{"rows": rows, "actor": actor, "account": account, "limit": limit, "names": names})
}

// auditNames is the directory the page names a row's ids from (web/src/audit_names.ts reads it; the
// cloud's audit answers the same shape). One map per kind of id, each keyed by the id as the rows
// write it. A map the node cannot answer is null, which the page says as "a key", never as
// "deleted key": null is "not known", an id absent from a map that was read is "no longer here".
type auditNames struct {
	// The node's owners: every one administers the node (SPEC §3.3), so the owners page lists them all.
	Owners map[string]string `json:"owners"`
	// The identities in the read's scope, by account id: only those this owner administers.
	Identities map[string]string `json:"identities"`
	// The contacts the rows mention, by fingerprint, named as the inbox names them (labelContacts:
	// the owner's petname first, a shared name told apart by its fingerprint). Only the scope's.
	Contacts map[string]string `json:"contacts"`
	// The owner-MCP tokens, revoked ones included, by id.
	Keys map[string]nameEntry `json:"keys"`
	// The passkeys, by id, named by their tag.
	Passkeys map[string]string `json:"passkeys"`
}

type nameEntry struct {
	Name    string `json:"name"`
	Revoked bool   `json:"revoked,omitempty"`
}

// fingerprintRe finds the contact fingerprints a row mentions, by their shape (PACT's `sha256:` and
// base64url), wherever the row carries one: its actor, its locator, its details.
var fingerprintRe = regexp.MustCompile(`sha256:[A-Za-z0-9_-]+`)

// names reads the directory for rows read under scope. Any list it cannot read fails the whole
// answer: a page that named some ids and quietly left others as ids would read as a trail whose
// people were removed.
func (d AuditDeps) names(ctx context.Context, scope []string, rows []store.AuditRow) (auditNames, error) {
	out := auditNames{
		Owners: map[string]string{}, Identities: map[string]string{}, Contacts: map[string]string{},
	}
	owners, err := d.Store.ListOwners(ctx)
	if err != nil {
		return out, err
	}
	for _, o := range owners {
		out.Owners[o.ID] = o.DisplayName
	}
	inScope := map[string]bool{}
	for _, id := range scope {
		inScope[id] = true
	}
	accounts, err := d.Store.ListAccounts(ctx)
	if err != nil {
		return out, err
	}
	for _, a := range accounts {
		if inScope[a.ID] {
			out.Identities[a.ID] = a.DisplayName
		}
	}
	// The fingerprints each account's rows mention; a node-level row (no account) names no contact of
	// anybody's.
	mentioned := map[string]map[string]bool{}
	for _, r := range rows {
		if !inScope[r.AccountID] {
			continue
		}
		for _, text := range []string{r.ActorID, r.Resource, r.Details} {
			for _, fpr := range fingerprintRe.FindAllString(text, -1) {
				if mentioned[r.AccountID] == nil {
					mentioned[r.AccountID] = map[string]bool{}
				}
				mentioned[r.AccountID][fpr] = true
			}
		}
	}
	for account, fprs := range mentioned {
		list, err := d.Store.ListContacts(ctx, account)
		if err != nil {
			return out, err
		}
		labels := labelContacts(list)
		for fpr := range fprs {
			if name, ok := labels[fpr]; ok {
				out.Contacts[fpr] = name
			}
		}
	}
	if d.Tokens != nil {
		tokens, err := d.Tokens.List(ctx)
		if err != nil {
			return out, err
		}
		out.Keys = make(map[string]nameEntry, len(tokens))
		for _, t := range tokens {
			out.Keys[t.ID] = nameEntry{Name: t.Label, Revoked: t.Revoked}
		}
	}
	if d.Passkeys != nil {
		keys, err := d.Passkeys(ctx)
		if err != nil {
			return out, err
		}
		out.Passkeys = make(map[string]string, len(keys))
		for _, k := range keys {
			out.Passkeys[k.ID] = k.Tag
		}
	}
	return out, nil
}
