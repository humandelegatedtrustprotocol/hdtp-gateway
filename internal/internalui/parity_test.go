package internalui

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// SPEC §8.4 says the portal and the owner MCP are the same authority in two
// shapes. They were not, and every gap looked the same from the outside: the
// capability worked, the agent could reach it, and a person could not.
//
//	add_contact       accepting an invite was agent-only  (E22)
//	send_to_contact   messaging had no way to START a conversation
//	contact removal   the store and manager had it, no route reached them
//	integration remove same
//
// So this maps one surface onto the other. It is a source lint because the
// question is "does an affordance EXIST", which no request-level test asks — each
// of those shipped with the endpoint tested and unreachable.
func TestEveryAgentCapabilityHasAPortalAffordance(t *testing.T) {
	root := repoRootUI(t)

	tools := ownerTools(t, root)
	routes := portalRoutes(t, root)

	// Each agent tool and where a person does the same thing. An entry of ""
	// means it is genuinely agent-only, and the reason is stated.
	expected := map[string]string{
		"add_contact":       "POST /contacts/add",
		"approve_contact":   "POST /requests/{fpr}/approve",
		"audit_query":       "GET /api/audit",
		"create_invite":     "POST /invites/create",
		"export_card":       "GET /api/card",
		"get_inbox":         "GET /api/conversations",
		"inbox":             "GET /api/conversations",
		"list_accounts":     "GET /api/session",
		"list_contacts":     "GET /api/contacts",
		"list_integrations": "GET /api/integrations",
		"list_passkeys":     "GET /api/owners",
		"read_thread":       "GET /api/conversations",
		"remove_passkey":    "POST /owners/passkeys/{id}/remove",
		"rename_contact":    "POST /contacts/{fpr}/petname",
		"send_to_contact":   "POST /messages/send",
		"set_exposure":      "POST /integrations/{id}/exposure",
		"set_permissions":   "POST /contacts/{fpr}/permissions",
		"set_trust_flag":    "POST /contacts/{fpr}/trust",

		// Agent-only, deliberately:
		"agent":          "", // the agent's own presence
		"ask_me":         "", // the agent asking its OWNER a question
		"answer_request": "", // an AGENT answers what a peer asked of it (§6.8)
		"list_pending":   "", // the queue that answer_request drains
		"call_contact":   "", // invoking a contact's tool: an agent action, not a page
		"sync_contacts":  "", // runs the 6-hour card-refresh sweep now; the node schedules it itself
	}

	var missing []string
	for _, tool := range tools {
		route, known := expected[tool]
		if !known {
			t.Errorf("owner MCP tool %q is new and this map does not say whether a "+
				"person can do it too. Add its portal route, or \"\" with the reason "+
				"it is agent-only.", tool)
			continue
		}
		if route == "" {
			continue
		}
		if !routes[route] {
			missing = append(missing, tool+" → "+route+" (no such route)")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("an agent can do this and a person cannot: %s", m)
	}
}

// ownerTools lists the tools registered on the owner MCP.
func ownerTools(t *testing.T, root string) []string {
	t.Helper()
	dir := filepath.Join(root, "internal", "internalui", "ownermcp")
	// Tools only. Resource templates also carry a Name, and a resource is not
	// something a person "does" — it is what a page already shows.
	re := regexp.MustCompile(`mcp\.Tool\{Name:\s*"([a-z_]+)"`)
	seen := map[string]bool{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) < 15 {
		t.Fatalf("only found %d owner tools; the lint is looking in the wrong place", len(out))
	}
	return out
}

// portalRoutes lists what the portal actually serves.
func portalRoutes(t *testing.T, root string) map[string]bool {
	t.Helper()
	dir := filepath.Join(root, "internal", "internalui")
	re := regexp.MustCompile(`HandleFunc\("((?:GET|POST) [^"]+)"`)
	out := map[string]bool{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
