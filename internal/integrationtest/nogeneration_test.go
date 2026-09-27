package integrationtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// generationSuffix is a name that says which PACT generation it belongs to: a letter, then "20",
// then the end of the name or the next word of it (seal20, State20, seal20Opt, pact20_demo). There
// is one generation, so a name that carries one says nothing true — and it is how the `…20` names
// outlived the `v: 1` code they were once told apart from.
var generationSuffix = regexp.MustCompile(`[A-Za-z]20($|[A-Z_.])`)

// cipherName is the one kind of "20" that is not a generation: ChaCha20, a cipher's own name.
var cipherName = regexp.MustCompile(`(?i)chacha20`)

func generational(name string) bool {
	return generationSuffix.MatchString(cipherName.ReplaceAllString(name, ""))
}

// No Go identifier and no file name under internal/, harness/ or queries/ carries a generation
// suffix. Identifiers are read with go/parser, so a date, a string or a comment is never one; the
// migrations are append-only and are not scanned.
func TestNoNameCarriesAGenerationSuffix(t *testing.T) {
	root := repoRoot(t)
	var found []string
	scanned := 0
	for _, dir := range []string{"internal", "harness", "queries"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if d.IsDir() {
				if d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if generational(d.Name()) {
				found = append(found, rel+" (file name)")
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
			if perr != nil {
				t.Errorf("%s does not parse: %v", rel, perr)
				return nil
			}
			scanned++
			seen := map[string]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && !seen[id.Name] && generational(id.Name) {
					seen[id.Name] = true
					found = append(found, rel+": "+id.Name)
				}
				return true
			})
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	// A floor, derived from nothing that can go stale by growing: a scan that read nothing proves
	// nothing, and the tree has had hundreds of Go files since the first commit.
	if scanned < 100 {
		t.Fatalf("scanned %d Go files; the walk is not reading the tree", scanned)
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Fatalf("names carry a generation suffix; there is one generation, name the thing instead:\n  %s", strings.Join(found, "\n  "))
	}
}

// The pattern itself: what it must catch and what it must leave alone.
func TestTheGenerationPatternCatchesTheOldNamesAndSparesTheCipher(t *testing.T) {
	for _, name := range []string{"seal20", "State20", "seal20Opt", "BenchmarkState20OneAccount", "pact20_demo_test.go", "client20.go", "TestPact20ExitDemo", "Pact20StateRoundTrips"} {
		if !generational(name) {
			t.Errorf("%s: not caught", name)
		}
	}
	for _, name := range []string{"chacha20poly1305", "ChaCha20Poly1305", "XChaCha20", "chacha20", "2026", "Ed25519", "migration0020", "P256", "sha256"} {
		if generational(name) {
			t.Errorf("%s: caught, and it is not a generation", name)
		}
	}
}
