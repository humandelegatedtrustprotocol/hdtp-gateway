package internalui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
		"add_contact":     "POST /contacts/add",
		"approve_contact": "POST /requests/{fpr}/approve",
		"audit_query":     "GET /api/audit",
		"create_invite":   "POST /invites/create",
		"export_card":     "GET /api/card",
		"get_inbox":       "GET /api/conversations",
		// Settings · identity renders the same certificate state for a person:
		// root, endpoint, notAfter and renewal_due, from the same reader.
		"identity_certificate": "GET /api/identity",
		"list_accounts":        "GET /api/session",
		"list_contacts":        "GET /api/contacts",
		"list_integrations":    "GET /api/integrations",
		"list_passkeys":        "GET /api/owners",
		"read_thread":          "GET /api/conversations",
		"delete_thread":        "POST /threads/{id}/delete",
		"remove_passkey":       "POST /owners/passkeys/{id}/remove",
		"refresh_contact":      "POST /contacts/{fpr}/refresh",
		"rename_contact":       "POST /contacts/{fpr}/petname",
		"send_to_contact":      "POST /messages/send",
		"set_exposure":         "POST /integrations/{id}/exposure",
		"set_permissions":      "POST /contacts/{fpr}/permissions",
		"set_trust_flag":       "POST /contacts/{fpr}/trust",
		"reject_contact":       "POST /requests/{fpr}/reject",
		"block_contact":        "POST /contacts/{fpr}/block",
		"unblock_contact":      "POST /contacts/{fpr}/unblock",
		"remove_contact":       "POST /contacts/{fpr}/remove",
		"list_invites":         "GET /api/invites",
		"revoke_invite":        "POST /invites/{id}/revoke",
		// A contact waiting at a new address (HDTP §5.3): the Requests tab lists and decides it.
		"list_pending_addresses": "GET /api/requests",
		"approve_address":        "POST /requests/addresses/{root}/approve",
		"reject_address":         "POST /requests/addresses/{root}/reject",

		// Agent-only, deliberately:
		"answer_request":   "", // an AGENT answers what a peer asked of it (§6.8)
		"list_pending":     "", // the queue that answer_request drains
		"call_contact":     "", // invoking a contact's tool: an agent action, not a page
		"wait_for_updates": "", // the agent's own long poll; a person's is the portal's live view (GET /events)
		"digest":           "", // what moved since a cursor, for an agent waking up; the dashboard is a person's
	}
	// And nothing here describes a tool that is gone: an entry nobody reads is a claim nobody checks.
	registered := map[string]bool{}
	for _, tool := range tools {
		registered[tool] = true
	}
	for tool := range expected {
		if !registered[tool] {
			t.Errorf("this map still describes %q, which the owner MCP does not register", tool)
		}
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

// The other direction, over the routes that decide who may reach this account — contacts,
// requests and invites (SPEC §8.4: the owner MCP's "contact management" and "invite management"
// mirror the portal). It did not exist, and the gap it would have named was real: a person could
// reject, remove and revoke, and an agent could do none of the three (review N-02).
func TestEveryContactAndInviteDecisionAPersonMakesAnAgentCanMake(t *testing.T) {
	root := repoRootUI(t)
	tools := map[string]bool{}
	for _, tool := range ownerTools(t, root) {
		tools[tool] = true
	}
	// Each person's route and the agent's tool for the same decision; "" says why none.
	expected := map[string]string{
		"POST /contacts/add":                      "add_contact",
		"POST /contacts/{fpr}/call":               "call_contact",
		"POST /contacts/{fpr}/remove":             "remove_contact",
		"POST /contacts/{fpr}/block":              "block_contact",
		"POST /contacts/{fpr}/unblock":            "unblock_contact",
		"POST /contacts/{fpr}/permissions":        "set_permissions",
		"POST /contacts/{fpr}/petname":            "rename_contact",
		"POST /contacts/{fpr}/refresh":            "refresh_contact",
		"POST /contacts/{fpr}/trust":              "set_trust_flag",
		"POST /requests/{fpr}/approve":            "approve_contact",
		"POST /requests/{fpr}/reject":             "reject_contact",
		"POST /requests/addresses/{root}/approve": "approve_address",
		"POST /requests/addresses/{root}/reject":  "reject_address",
		"POST /invites/create":                    "create_invite",
		"POST /invites/{id}/revoke":               "revoke_invite",
	}
	routes := portalRoutes(t, root)
	checked := 0
	for route := range routes {
		if !strings.HasPrefix(route, "POST /contacts/") && !strings.HasPrefix(route, "POST /requests/") && !strings.HasPrefix(route, "POST /invites/") {
			continue
		}
		checked++
		tool, known := expected[route]
		if !known {
			t.Errorf("portal route %q decides who may reach an account and this map does not say which owner-MCP tool does the same", route)
			continue
		}
		if !tools[tool] {
			t.Errorf("a person can do this and an agent cannot: %s → %s (no such tool)", route, tool)
		}
	}
	for route := range expected {
		if !routes[route] {
			t.Errorf("this map still describes %q, which the portal does not serve", route)
		}
	}
	if checked < len(expected) {
		t.Fatalf("checked %d routes, fewer than the %d this map names: the scan is looking in the wrong place", checked, len(expected))
	}
}

// SPEC §8.4's table is the owner MCP's tool list as a reader meets it, and it had drifted both
// ways: it named `set_trust_flag` twice, and never named six tools the node registers
// (`list_accounts`, `identity_certificate`, `wait_for_updates`, `digest`, `list_integrations`,
// `set_exposure`). So every backticked name in the table's cells is a registered tool, each is
// named once, and every registered tool is named.
func TestSpecNamesEveryOwnerToolOnce(t *testing.T) {
	root := repoRootUI(t)
	raw, err := os.ReadFile(filepath.Join(root, "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	named := specOwnerTools(t, string(raw))
	registered := map[string]bool{}
	for _, tool := range ownerTools(t, root) {
		registered[tool] = true
	}
	count := map[string]int{}
	for _, n := range named {
		count[n]++
	}
	names := make([]string, 0, len(count))
	for n := range count {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if c := count[n]; c > 1 {
			t.Errorf("SPEC §8.4 names %q %d times; the table names each tool once", n, c)
		}
		if !registered[n] {
			t.Errorf("SPEC §8.4 names %q, which the owner MCP does not register", n)
		}
	}
	for _, tool := range ownerTools(t, root) {
		if count[tool] == 0 {
			t.Errorf("the owner MCP registers %q and SPEC §8.4's table does not name it", tool)
		}
	}
}

// specOwnerTools reads the backticked names in the cells of SPEC §8.4's table (the second
// column), in order and with repeats.
func specOwnerTools(t *testing.T, spec string) []string {
	t.Helper()
	start := strings.Index(spec, "### 8.4 Owner MCP: tools")
	if start < 0 {
		t.Fatal("SPEC.md has no \"### 8.4 Owner MCP: tools\" heading")
	}
	section := spec[start+len("### 8.4"):]
	if end := strings.Index(section, "\n### "); end >= 0 {
		section = section[:end]
	}
	tick := regexp.MustCompile("`([^`]+)`")
	var out []string
	rows := 0
	for _, line := range strings.Split(section, "\n") {
		cells := strings.Split(line, "|")
		if !strings.HasPrefix(line, "|") || len(cells) < 4 || strings.HasPrefix(line, "|---") || strings.TrimSpace(cells[1]) == "Area" {
			continue
		}
		rows++
		for _, m := range tick.FindAllStringSubmatch(cells[2], -1) {
			out = append(out, m[1])
		}
	}
	if rows < 5 || len(out) < 20 {
		t.Fatalf("read %d tool names from %d rows of SPEC §8.4's table: the reader is looking in the wrong place", len(out), rows)
	}
	return out
}

// ownerTools lists the tools registered on the owner MCP.
//
// Read from the syntax tree: every `mcp.Tool{Name: "…"}` literal in the package. It was a pattern
// over the source text that wanted `Name:` on the same line as `mcp.Tool{`, and two tools are not
// written that way — `wait_for_updates` and `digest` — so this test had never been asked whether
// a person can do what they do.
func ownerTools(t *testing.T, root string) []string {
	t.Helper()
	dir := filepath.Join(root, "internal", "internalui", "ownermcp")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				// Tools only. A resource also carries a Name, and a resource is not something a
				// person "does" — it is what a page already shows.
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Tool" {
					return true
				}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Name" {
						continue
					}
					if val, ok := kv.Value.(*ast.BasicLit); ok {
						name, _ := strconv.Unquote(val.Value)
						seen[name] = true
					}
				}
				return true
			})
		}
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
