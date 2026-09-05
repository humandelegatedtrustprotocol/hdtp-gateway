package internalui

// Audit view (SPEC §11.6): owner-visible only, filterable, read-only.

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

func MountAuditPages(mux *http.ServeMux, st store.Store) {
	mux.HandleFunc("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
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
		account := r.URL.Query().Get("account")
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
			ms, err := st.ListMembershipsByOwner(r.Context(), owner)
			if err != nil {
				http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
				return
			}
			for _, m := range ms {
				if m.Role == "admin" {
					scope = append(scope, m.AccountID)
				}
			}
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
		apiJSON(w, map[string]any{"rows": rows, "actor": actor, "account": account, "limit": limit})
	})
}
