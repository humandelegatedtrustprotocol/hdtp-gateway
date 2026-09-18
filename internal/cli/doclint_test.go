package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Documentation that quotes a command the binary does not accept is worse than
// no documentation: a reader trusts it, types it, and gets a usage error. This
// walks every `pact-gateway …` invocation in the docs and the README and checks
// the subcommand exists and every flag it names is real.
//
// It cannot check that the command DOES what the prose says — only that it
// parses. That is still the difference between "documented" and "invented".
func TestDocsOnlyQuoteRealCommands(t *testing.T) {
	root := repoRootFromTest(t)
	files := docFiles(t, root)
	if len(files) < 5 {
		t.Fatalf("only found %d doc files — the lint is looking in the wrong place", len(files))
	}
	invocation := regexp.MustCompile(`pact-gateway ([a-z-]+(?: [a-z-]+)?)((?: +-{1,2}[a-z0-9-]+(?:[= ][^\s\\` + "`" + `]+)?)*)`)

	var problems []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, f)
		for _, inv := range invocations(string(b)) {
			m := invocation.FindStringSubmatch(inv.text)
			if m == nil {
				continue
			}
			words := strings.Fields(m[1])
			cmd, known := resolveCommand(words)
			if !known {
				// A shell line is an instruction: an unknown command there is a
				// broken instruction. An inline span is usually prose naming the
				// binary ("a `pact-gateway node`"), so it is only checked when it
				// does name a real command.
				if inv.shellLine {
					problems = append(problems, rel+": unknown command `pact-gateway "+m[1]+"`")
				}
				continue
			}
			accepted, ok := acceptedFlags(cmd)
			if !ok {
				continue // a command with no flag set of its own
			}
			for _, fl := range flagNames(m[2]) {
				if !accepted[fl] {
					problems = append(problems, rel+": `pact-gateway "+strings.Join(cmd, " ")+"` has no flag -"+fl)
				}
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("documentation quotes commands the binary does not accept:\n  %s", strings.Join(problems, "\n  "))
	}
}

// quoted is one `pact-gateway …` occurrence and where it came from.
type quoted struct {
	text      string
	shellLine bool // a line in a fenced block that a reader would paste
}

// invocations pulls every `pact-gateway …` out of a markdown document's CODE —
// fenced blocks and inline spans — and marks which ones are shell lines.
func invocations(doc string) []quoted {
	var out []quoted
	inFence := false
	envOrExec := regexp.MustCompile(`^(?:[A-Z_][A-Z0-9_]*=\S+ +|\$ +|docker compose exec +\S+ +|sudo +)*`)
	output := regexp.MustCompile(`^pact-gateway [a-z-]+:`)
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			stripped := trimmed[len(envOrExec.FindString(trimmed)):]
			// `pact-gateway serving: …` is the banner the binary PRINTS, not a
			// command a reader types. Output lines name a field, then a colon.
			if output.MatchString(stripped) {
				continue
			}
			if strings.HasPrefix(stripped, "pact-gateway ") {
				out = append(out, quoted{text: stripped, shellLine: true})
			}
			continue
		}
		for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(line, -1) {
			if strings.Contains(m[1], "pact-gateway ") {
				out = append(out, quoted{text: m[1]})
			}
		}
	}
	return out
}

// resolveCommand decides how many of the words are the command: `ingress serve`
// and `account create` are two-word commands, most are one.
func resolveCommand(words []string) ([]string, bool) {
	if len(words) == 0 {
		return nil, false
	}
	top := map[string]bool{
		"serve": true, "ingress": true, "migrate": true, "doctor": true, "healthcheck": true,
		"account": true, "passkey": true, "token": true, "audit": true, "backup": true, "version": true,
	}
	if !top[words[0]] {
		return nil, false
	}
	multi := map[string]bool{"ingress": true, "account": true, "passkey": true, "token": true, "audit": true, "backup": true}
	if multi[words[0]] {
		if len(words) < 2 {
			return words[:1], true
		}
		// The SUBCOMMAND has to be real too. Accepting any second word let
		// `pact-gateway passkey unlock-me-please` through the lint — a fake
		// recovery command in the README would have read as documented.
		if subs, ok := acceptedSubcommands(words[0]); ok && !subs[words[1]] {
			return nil, false
		}
		return words[:2], true
	}
	return words[:1], true
}

// acceptedSubcommands asks the command itself, the way acceptedFlags does: run
// it with NO subcommand and read the `<a|b|c>` out of the usage line it prints.
// Running it with a BOGUS subcommand would not do — several commands load the
// config before they reach the switch, so they fail with a config error instead
// of the usage. No subcommand at all short-circuits to usage, side-effect free.
func acceptedSubcommands(top string) (map[string]bool, bool) {
	var out, errb bytes.Buffer
	Run([]string{top}, "test", &out, &errb)
	m := regexp.MustCompile(`<([a-z-]+(?:\|[a-z-]+)+)>`).FindStringSubmatch(out.String() + errb.String())
	if m == nil {
		return nil, false
	}
	subs := map[string]bool{}
	for _, name := range strings.Split(m[1], "|") {
		subs[name] = true
	}
	return subs, true
}

// acceptedFlags asks the command itself, by running it with -h and reading the
// flag set it prints. No second list to drift out of date.
func acceptedFlags(cmd []string) (map[string]bool, bool) {
	var out, errb bytes.Buffer
	Run(append(append([]string{}, cmd...), "-h"), "test", &out, &errb)
	text := out.String() + errb.String()
	if !strings.Contains(text, "Usage of") {
		return nil, false
	}
	names := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+-([a-z0-9-]+)`).FindAllStringSubmatch(text, -1) {
		names[m[1]] = true
	}
	return names, len(names) > 0
}

// flagNames reads the flag TOKENS out of a command tail.
//
// It tokenizes rather than pattern-matching the whole string, because a flag's
// VALUE routinely contains something that looks like a flag: the first version
// scanned the tail with a regex and read `--out pact-backup.tar.gz` as naming a
// flag called `-backup`, which is a false report about correct documentation.
// Only a token that starts with a dash is a flag.
func flagNames(tail string) []string {
	var out []string
	for _, tok := range strings.Fields(tail) {
		if !strings.HasPrefix(tok, "-") {
			continue // a value
		}
		name := strings.TrimLeft(tok, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func docFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	// `..` and `../.github` are the repository root, one level above this
	// module: the umbrella README, SECURITY.md and the PR and issue templates
	// live there. They are contributor-facing documentation like any other, and
	// the commands a newcomer types first are the ones that must not be invented.
	for _, dir := range []string{"docs", "docs/demos", ".", "..", "../.github"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
				files = append(files, filepath.Join(root, dir, e.Name()))
			}
		}
	}
	return files
}

func repoRootFromTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}

// AC (P10-10f): SPEC §11.2's table list and §12.1's command table are checked
// against the code, so they cannot silently drift again.
//
// They had: §11.2 named `tunnel_state`, which has never existed, and omitted
// seven tables that do; §12.1 omitted `ingress`, `healthcheck`, `backup` and
// `version` and listed `setup`, `invite`, `card` and `contact`, which the
// dispatcher does not have. A prose table nobody checks is a prose table that
// describes an earlier draft.
func TestSpecTablesMatchTheCode(t *testing.T) {
	root := specRoot(t)

	// §7.2 states the messages uniqueness key in prose. The table-name check
	// below cannot see a column, so when P12-04 put `direction` into the key the
	// spec silently began describing the previous schema — the exact drift this
	// lint exists to prevent, one level down.
	t.Run("7.2's uniqueness key matches the migrations", func(t *testing.T) {
		files, err := filepath.Glob(filepath.Join(root, "migrations", "sqlite", "*.sql"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no migrations found: %v", err)
		}
		uniq := regexp.MustCompile(`(?i)UNIQUE \(account_id, contact_fpr,([a-z_, ]+)\)`)
		key := ""
		sort.Strings(files) // last migration to define it wins
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if m := uniq.FindStringSubmatch(string(b)); m != nil {
				key = strings.Join(strings.Fields(strings.ReplaceAll(m[1], ",", " ")), ", ")
			}
		}
		if key == "" {
			t.Fatal("no messages UNIQUE constraint found in the sqlite migrations")
		}
		// account_id -> account, contact_fpr -> contact, as §7.2 words it.
		want := "`unique(account, contact, " + key + ")`"
		b, err := os.ReadFile(filepath.Join(root, "SPEC.md"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("§7.2 does not state the constraint the migrations create: want %s", want)
		}
	})

	// The binary's own help disagreed with itself: the top-level usage block
	// said `account create|list` while the dispatcher accepted `rotate-key` and
	// even printed it in its own error string. The 12.1 check below reads the
	// dispatcher, so it saw a command the operator's help did not.
	t.Run("usage text names every subcommand the dispatcher accepts", func(t *testing.T) {
		b, err := os.ReadFile(filepath.Join(root, "internal", "cli", "cli.go"))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		// Each subcommand group states its own set in its usage error; that
		// string is next to the switch it describes, so it is the reliable one.
		use := regexp.MustCompile(`usage: pact-gateway ([a-z]+) <([a-z|-]+)>`)
		seen := map[string]map[string]bool{}
		for _, m := range use.FindAllStringSubmatch(src, -1) {
			if seen[m[1]] == nil {
				seen[m[1]] = map[string]bool{}
			}
			for _, sub := range strings.Split(m[2], "|") {
				seen[m[1]][sub] = true
			}
		}
		if len(seen) == 0 {
			t.Fatal("no subcommand usage strings found")
		}
		block := src[strings.Index(src, "commands:"):]
		block = block[:strings.Index(block, "`)")]
		for cmd, subs := range seen {
			line := ""
			for _, l := range strings.Split(block, "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), cmd+" ") {
					line = l
					break
				}
			}
			if line == "" {
				t.Errorf("the usage block does not mention %q at all", cmd)
				continue
			}
			for sub := range subs {
				if !strings.Contains(line, sub) {
					t.Errorf("usage block for %q omits the %q subcommand the dispatcher accepts", cmd, sub)
				}
			}
		}
	})

	t.Run("11.2 lists exactly the tables that exist", func(t *testing.T) {
		want := map[string]bool{}
		files, err := filepath.Glob(filepath.Join(root, "migrations", "sqlite", "*.sql"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no migrations found: %v", err)
		}
		create := regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)`)
		drop := regexp.MustCompile(`(?i)DROP TABLE (?:IF EXISTS )?([a-z_]+)`)
		rename := regexp.MustCompile(`(?i)ALTER TABLE ([a-z_]+) RENAME TO ([a-z_]+)`)
		// In migration order, and a DROP counts: the guard used to read CREATEs
		// alone, so a table a later migration retired was still demanded of
		// §11.2 forever. That made the section un-shrinkable — the only way to
		// pass was to keep documenting a table nothing has, which is the shape
		// of defect this guard exists to catch.
		//
		// Only the Up half is read. A Down re-creating what it rolls back is
		// correct goose and says nothing about the schema a node runs.
		sort.Strings(files)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			up := string(b)
			if i := strings.Index(up, "-- +goose Down"); i >= 0 {
				up = up[:i]
			}
			for _, m := range create.FindAllStringSubmatch(up, -1) {
				name := m[1]
				// A table rebuild (SQLite cannot alter a CHECK) creates a
				// temporary twin; it is not part of the schema.
				if strings.HasSuffix(name, "_new") || strings.HasSuffix(name, "_old") {
					continue
				}
				want[name] = true
			}
			for _, m := range drop.FindAllStringSubmatch(up, -1) {
				delete(want, m[1])
			}
			// A SQLite table rebuild is create-twin, drop, rename: the name the
			// schema ends with is never CREATEd under that name at all.
			for _, m := range rename.FindAllStringSubmatch(up, -1) {
				delete(want, m[1])
				want[m[2]] = true
			}
		}
		got, dups := specTableRows(t, root)
		if len(dups) > 0 {
			sort.Strings(dups)
			t.Errorf("§11.2 lists these twice: %s", strings.Join(dups, ", "))
		}
		for name := range want {
			if !got[name] {
				t.Errorf("§11.2 does not list %q, which exists", name)
			}
		}
		for name := range got {
			if !want[name] {
				t.Errorf("§11.2 lists %q, which no migration creates", name)
			}
		}
	})

	t.Run("12.1 lists exactly the commands the binary has", func(t *testing.T) {
		b, err := os.ReadFile(filepath.Join(root, "internal", "cli", "cli.go"))
		if err != nil {
			t.Fatal(err)
		}
		// The usage text the binary prints is the contract a reader sees, so it
		// is what the spec must agree with.
		usage := regexp.MustCompile(`(?s)commands:\n(.*?)\n` + "`" + `\)`).FindStringSubmatch(string(b))
		if usage == nil {
			t.Fatal("could not find the usage block in cli.go")
		}
		want := map[string]bool{}
		for _, line := range strings.Split(usage[1], "\n") {
			f := strings.Fields(line)
			if len(f) > 0 {
				want[f[0]] = true
			}
		}
		got := specCommandList(t, root)
		for name := range want {
			if !got[name] {
				t.Errorf("§12.1 does not list %q, which the binary prints in its usage", name)
			}
		}
		for name := range got {
			if !want[name] {
				t.Errorf("§12.1 lists %q, which the binary does not offer", name)
			}
		}
	})
}

// specTableRows reads the §11.2 table names, and reports any listed twice —
// which is exactly the mistake made while writing this lint, when §11.2 turned
// out to have one long table rather than the two blocks a quick diff suggested.
func specTableRows(t *testing.T, root string) (map[string]bool, []string) {
	t.Helper()
	sec := specSection(t, root, "### 11.2", "### 11.3")
	row := regexp.MustCompile("(?m)^\\|\\s*`([^`]+)`\\s*\\|")
	seen := map[string]int{}
	for _, m := range row.FindAllStringSubmatch(sec, -1) {
		seen[strings.TrimSpace(m[1])]++
	}
	out := map[string]bool{}
	var dups []string
	for name, n := range seen {
		out[name] = true
		if n > 1 {
			dups = append(dups, name)
		}
	}
	return out, dups
}

// specCommandList reads the §12.1 command names, taking the first word of each
// row so `passkey list|remove` counts as `passkey`.
func specCommandList(t *testing.T, root string) map[string]bool {
	t.Helper()
	sec := specSection(t, root, "### 12.1", "### 12.2")
	out := map[string]bool{}
	for name := range firstColumnNames(sec) {
		out[strings.Fields(strings.ReplaceAll(name, "|", " "))[0]] = true
	}
	return out
}

func firstColumnNames(section string) map[string]bool {
	row := regexp.MustCompile("(?m)^\\|\\s*`([^`]+)`\\s*\\|")
	out := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		out[strings.TrimSpace(m[1])] = true
	}
	return out
}

func specSection(t *testing.T, root, from, to string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("SPEC.md has no %s", from)
	}
	j := strings.Index(s[i:], to)
	if j < 0 {
		return s[i:]
	}
	return s[i : i+j]
}

// specRoot walks up to the module root.
func specRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("module root not found")
	return ""
}

// AC (P10-12d): PLAN.md build-goal item 6 — "manual-verification demo docs exist and are
// dated" — is mechanically checkable rather than a claim someone has to audit
// by eye.
//
// Every demo carries a `Last manual run:` marker. This does NOT require a date:
// these runs need a tailnet, a paid ngrok plan, a Cloudflare domain, a VPS and a
// real Google account, so no agent can produce one. What it requires is that the
// marker EXISTS, is in the shape a date goes into, and that an undated run is
// visible as undated instead of quietly reading as done.
func TestDemoDocsCarryAManualRunMarker(t *testing.T) {
	root := specRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "docs", "demos", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 5 {
		t.Fatalf("found %d demo docs; PLAN.md build-goal item 6 names five runs", len(files))
	}
	marker := regexp.MustCompile("`Last manual run: (—|[0-9]{4}-[0-9]{2}-[0-9]{2})`")
	var undated []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		m := marker.FindSubmatch(b)
		if m == nil {
			t.Errorf("%s has no `Last manual run: …` marker, so nobody can tell whether it was run",
				filepath.Base(f))
			continue
		}
		if string(m[1]) == "—" {
			undated = append(undated, filepath.Base(f))
		}
	}
	// Undated is the honest current state, not a failure: these runs are
	// owner-gated. The test records which, so the count cannot drift silently.
	sort.Strings(undated)
	t.Logf("demo docs still awaiting a live run: %v", undated)
}
