package integrationtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nodeLevelActions are the audit actions that legitimately belong to no
// account. They are facts about the NODE — a listener starting, someone signing
// in to the portal, a certificate being managed — and stay readable by every
// owner. Everything else concerns one identity's contacts, messages, bookings
// or integrations, and must name the account it happened in.
var nodeLevelActions = map[string]string{
	"portal_login":             "who signed in to this node; not about an account",
	"portal_request":           "an unauthenticated request to the node's own surface",
	"public_listener":          "the node's listener starting and stopping",
	"rate_limited":             "a budget tripped by a key or an IP, before any account is resolved",
	"ingress_leg":              "the paired ingress presenting the wrong identity",
	"owner_mcp":                "an owner-MCP request refused before a token named an owner",
	"acme_manage":              "certificate management for the node's names",
	"recipe_corpus":            "the embedded recipe corpus failing to load",
	"exposure_stale_guard":     "reached with an integration id alone",
	"integration_availability": "reached with an integration id alone",
	"set_exposure":             "refused before the integration is loaded",
	"contact_add":              "already names the account it adds to",
	"invite_create":            "already names the account it issues for",
	"media_fetch":              "already names the account it fetches for",
	"settings_storage":         "already names the account whose storage changed",
	"settings_seal":            "already names the account whose seal changed",
	"tools_list":               "already names the account whose surface was asked for",
	"portal_logout":            "an owner signing out of the node",
	"passkey_register":         "an owner's credential on the node, not on an account",
	"passkey_remove":           "an owner's credential on the node, not on an account",
	"lan_refused":              "a private-range source refused at the listener",
	"listener_full":            "connections the listener refused past its cap, before any account was resolved",
	"leaf_retirement_pass":     "the pass that destroys expired leaf keys could not list accounts; per-key rows name theirs",
	"settings_public_url":      "the node's own address",
	"settings_lan":             "the node's own listener policy",
	"token_revoke":             "revocation is by token id; the node holds the scope",
	"settings_save":            "the node's own settings; per-account storage is settings_storage",
	"settings_probe":           "a probe of the node's own configuration",
	"ingress_pair":             "pairing the node's own inbound adapter",
	"ingress_unpair":           "unpairing the node's own inbound adapter",
	"settings_unreadable":      "a node settings row the keyring cannot open",
	"account_create":           "a failed create names no account because none exists yet; the success path names the one it made, and the slug-misuse rule still guards it",
}

// wrappedAtWiring are files whose audit calls are given the account by the code
// that supplies their audit function, not at the call site. Listing them here
// is the price of a lint that reads one line at a time; each entry says where
// the account is actually attached.
var wrappedAtWiring = map[string]string{
	"internal/public/tools.go":   "node.go wires ToolDeps.Audit with the account prefixed",
	"internal/public/servers.go": "Pool.audit prefixes Pool.AccountID",
}

// Every row in the trail that is about somebody must say whose. The account
// column is what scopes a narrowed token's reads (SPEC §11.6) and the portal's
// audit page; a row written without it is readable by every owner on the node,
// including the ones who administer none of the accounts it concerns. This
// lint exists because that was true of nearly the whole trail and nothing
// caught it — the column was there, the filter used it, and almost nothing
// filled it in.
func TestEveryAuditRowNamesItsAccount(t *testing.T) {
	root := repoRoot(t)
	dirs := []string{"internal/node", "internal/public", "internal/integrations",
		"internal/internalui", "internal/cli", "internal/services", "internal/messaging", "internal/identity"}
	call := regexp.MustCompile(`\b(audit|Audit|auditFn|auditAs|AuditAs|auditFor)\(`)
	literal := regexp.MustCompile(`^"([a-z][a-z0-9_]*)"$`)
	slugAsAccount := regexp.MustCompile(`account:"\s*\+\s*[\w.]*\.Slug`)

	var checked int
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			if why, ok := wrappedAtWiring[filepath.ToSlash(rel)]; ok {
				t.Logf("skipping %s: %s", rel, why)
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			src := string(b)
			for _, span := range callSpans(src, call) {
				args := topLevelArgs(span.text)
				// auditAs names the actor kind first; auditFor names the account.
				want := 0
				if span.callee == "auditAs" || span.callee == "AuditAs" {
					want = 1
				}
				if span.callee == "auditFor" {
					continue // the account is the first argument by construction
				}
				if want >= len(args) {
					continue
				}
				m := literal.FindStringSubmatch(strings.TrimSpace(args[want]))
				if m == nil {
					continue // a forwarding shim, or a call whose action is a variable
				}
				checked++
				// The account column holds IDs. A slug formatted into the
				// account: prefix is a different string that happens to name
				// one — the sink recovers the column from the prefix verbatim,
				// so the row would be scoped to an account that does not exist
				// and hidden from every scoped read. This caught a real one:
				// the rotation success row wrote account:<slug>:<old>-><new>.
				if slugAsAccount.MatchString(span.text) ||
					(strings.Contains(span.text, "account:%s") && strings.Contains(span.text, ".Slug")) {
					t.Errorf("%s:%d formats a slug into the account: prefix; the column holds ids.", rel, span.line)
					continue
				}
				// "contains account" was too loose: an action with "account" in
				// its name or a slug formatted after the prefix satisfied
				// it while attributing nothing. The prefix (with its colon) or
				// an explicit id expression is what counts as attribution.
				if strings.Contains(span.text, "account:") ||
					strings.Contains(span.text, "AccountID") || strings.Contains(span.text, "accountID") ||
					strings.Contains(span.text, "withAccount(") || strings.Contains(span.text, "attributed(") {
					continue
				}
				if _, ok := nodeLevelActions[m[1]]; ok {
					continue
				}
				t.Errorf("%s:%d audits %q without naming an account. Add the account "+
					"to the resource, or add the action to nodeLevelActions with the "+
					"reason it belongs to no account.", rel, span.line, m[1])
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 50 {
		t.Fatalf("only %d audit calls found; this lint is checking nothing", checked)
	}
	t.Logf("checked %d audit call sites", checked)
}

type span struct {
	callee string
	text   string
	line   int
}

// topLevelArgs splits a call's argument text on commas that are not inside
// nested parentheses, brackets, braces or a string.
func topLevelArgs(s string) []string {
	var out []string
	depth, inStr, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && inStr:
			i++
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// callSpans returns each call's argument text, balanced across line breaks so a
// wrapped call is read whole rather than judged on its first line.
func callSpans(src string, call *regexp.Regexp) []span {
	var out []span
	for _, loc := range call.FindAllStringIndex(src, -1) {
		depth, end := 0, -1
		for i := loc[1] - 1; i < len(src); i++ {
			switch src[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			continue
		}
		out = append(out, span{
			callee: strings.TrimSuffix(src[loc[0]:loc[1]], "("),
			text:   src[loc[1]:end],
			line:   strings.Count(src[:loc[0]], "\n") + 1,
		})
	}
	return out
}

// The outcome column is a verdict and nothing else. It is what the portal
// colours, counts and filters by, so a fingerprint, a booking id, a count or a
// failure sentence in that column turns every row into its own category and
// hides real refusals. This lint catches the shapes that did it: a compound
// literal, a concatenation, a Sprintf. An outcome held in a variable cannot be
// judged here — TestAuditOutcomesAreSingleVerdicts in internal/public watches
// those at runtime.
func TestAuditOutcomesAreLiteralVerdicts(t *testing.T) {
	root := repoRoot(t)
	dirs := []string{"internal/node", "internal/public", "internal/integrations",
		"internal/internalui", "internal/cli", "internal/services", "internal/messaging", "internal/identity"}
	call := regexp.MustCompile(`\b(audit|Audit|auditFn|auditAs|AuditAs|auditFor)\(`)
	verdict := regexp.MustCompile(`^"[a-z][a-z0-9_]*"$`)

	var checked int
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, span := range callSpans(string(b), call) {
				args := topLevelArgs(span.text)
				if len(args) < 3 {
					continue // a two-argument shim or a partial application
				}
				last := strings.TrimSpace(args[len(args)-1])
				// An error's TEXT is never a verdict, and it got past this lint for as long as the
				// lint only looked at arguments with a quote in them: `err.Error()` has none, so it
				// read as "a variable" and was skipped. `account_unavailable` was written that way,
				// its outcome a sentence the portal can neither colour, count nor filter by.
				if strings.HasSuffix(last, ".Error()") {
					t.Errorf("%s:%d writes an error's text as the outcome (%s). The verdict goes in the "+
						"outcome — \"error\" — and what went wrong goes in the resource, redacted.",
						rel, span.line, last)
					continue
				}
				if !strings.Contains(last, `"`) || strings.Contains(last, "func(") {
					continue // a variable, or a callback (audit_query's permit function)
				}
				checked++
				if verdict.MatchString(last) {
					continue
				}
				t.Errorf("%s:%d writes a compound outcome %s. The verdict goes in the "+
					"outcome; everything that describes it goes in the resource.",
					rel, span.line, last)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 100 {
		t.Fatalf("only %d literal outcomes found; this lint is checking nothing", checked)
	}
	t.Logf("checked %d literal outcomes", checked)
}
