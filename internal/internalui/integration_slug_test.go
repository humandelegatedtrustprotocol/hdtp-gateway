package internalui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// HDTP §8: one switch per integration, `integration.<slug>`, and one slug rule on both hosts:
// `[a-z0-9][a-z0-9-]{1,31}`, 2 to 32 characters (batondeck's isIntegrationSlug). The portal created
// an integration under any slug at all, so one the permission cannot spell could be added, exposed,
// and never granted to anybody; and an underscore spelled the tool name and the permission two
// ways. A slug outside the rule is refused at creation and nothing is written; the control, a
// slug at the rule's longest, gets through.
func TestAnIntegrationSlugIsTheOneItsPermissionAdmits(t *testing.T) {
	mux, st, _, acct := integrationsEnv(t)
	ctx := context.Background()
	for name, slug := range map[string]string{
		"an underscore":           "my_cal",
		"an uppercase letter":     "Cal",
		"a leading hyphen":        "-cal",
		"a dot":                   "cal.v2",
		"a space":                 "my cal",
		"a non-ASCII letter":      "café",
		"one character":           "a",
		"thirty-three characters": "a" + strings.Repeat("b", 32),
	} {
		rr := postForm(t, mux, "/integrations/create?account="+acct, url.Values{
			"slug": {slug}, "transport": {"streamable-http"}, "endpoint": {"https://cal.example/mcp"},
		})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s (%q): %d, want 400", name, slug, rr.Code)
		}
		if _, err := st.GetIntegration(ctx, acct, slug); err == nil {
			t.Errorf("%s (%q): the row was written", name, slug)
		}
	}
	control := "a" + strings.Repeat("-9", 15) + "z" // 32 characters
	if rr := postForm(t, mux, "/integrations/create?account="+acct, url.Values{
		"slug": {control}, "transport": {"streamable-http"}, "endpoint": {"https://cal.example/mcp"},
	}); rr.Code != http.StatusSeeOther {
		t.Fatalf("the control %q: %d", control, rr.Code)
	}
	if _, err := st.GetIntegration(ctx, acct, control); err != nil {
		t.Fatalf("the control wrote no row: %v", err)
	}
}
