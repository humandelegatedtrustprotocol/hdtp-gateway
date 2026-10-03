package integrationtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// generationSuffix is a name that says which generation of the protocol it belongs to. Two forms
// have been written here: a letter, then "20", then the end of the name or the next word of it
// (seal20, State20, seal20Opt), and a word that is `V` and a number (TestV2PinnedContact, sealV1).
// There is one generation, so a name that carries one says nothing true — and it is how the `…20`
// names outlived the code they were once told apart from.
var generationSuffix = regexp.MustCompile(`[A-Za-z]20($|[A-Z_.])|(^|[a-z_])V[0-9]+($|[A-Z_.])`)

// cipherName is the one kind of "20" that is not a generation: ChaCha20, a cipher's own name.
var cipherName = regexp.MustCompile(`(?i)chacha20`)

func generational(name string) bool {
	return generationSuffix.MatchString(cipherName.ReplaceAllString(name, ""))
}

// generationFile is the form a FILE name takes and an identifier must not be held to: a word
// that is a lower-case `v` and a number (decide_v2.go). `v1` and `v2` are ordinary variables.
var generationFile = regexp.MustCompile(`(^|_)v[0-9]+[_.]`)

func generationalFile(name string) bool {
	return generational(name) || generationFile.MatchString(name)
}

// No Go identifier and no file name under internal/, harness/ or queries/ carries a generation
// suffix. Identifiers are read with go/parser, so a date, a string or a comment is never one.
// Red on 9f27f67, where it listed 75 names and files, from harness/peer/peer.go's BuildCard20 to a
// query file named for the generation; and red again on 1bbcbce for the `V2` form, with the eight
// TestV2… names of internal/public/decide_test.go.
func TestNoNameCarriesAGenerationSuffix(t *testing.T) {
	root := repoRoot(t)
	var found []string
	// Each root must be there and must be read: a floor per root, so a walk that silently read
	// only one of them cannot pass for all three. The floors are far below today's counts (397 Go
	// files under internal/, 47 under harness/, 12 query files) and only a broken walk misses them.
	floors := map[string]int{"internal": 100, "harness": 10, "queries": 2}
	for _, dir := range []string{"internal", "harness", "queries"} {
		files := 0
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
			if generationalFile(d.Name()) {
				found = append(found, rel+" (file name)")
			}
			if dir == "queries" {
				files++
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
			if perr != nil {
				t.Errorf("%s does not parse: %v", rel, perr)
				return nil
			}
			files++
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
		if err != nil {
			t.Fatalf("%s/ could not be walked: %v", dir, err)
		}
		if files < floors[dir] {
			t.Fatalf("read %d files under %s/, fewer than %d; the walk is not reading the tree", files, dir, floors[dir])
		}
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Fatalf("names carry a generation suffix; there is one generation, name the thing instead:\n  %s", strings.Join(found, "\n  "))
	}
}

// The pattern itself: what it must catch and what it must leave alone.
func TestTheGenerationPatternCatchesTheOldNamesAndSparesTheCipher(t *testing.T) {
	for _, name := range []string{
		"seal20", "State20", "seal20Opt", "BenchmarkState20OneAccount", "demo20_test.go", "client20.go", "TestNode20ExitDemo", "Node20StateRoundTrips",
		"TestV2PinnedContactBothForms", "sealV1", "V2Envelope", "openV2",
	} {
		if !generational(name) {
			t.Errorf("%s: not caught", name)
		}
	}
	for _, file := range []string{"decide_v2.go", "v1_test.go", "seal_v2_test.go", "client20.go"} {
		if !generationalFile(file) {
			t.Errorf("%s: a file name that was not caught", file)
		}
	}
	for _, name := range []string{"v1", "v2", "pgxv5"} {
		if generational(name) {
			t.Errorf("%s: caught, and it is an ordinary identifier", name)
		}
	}
	for _, name := range []string{
		"chacha20poly1305", "ChaCha20Poly1305", "XChaCha20", "chacha20", "2026", "Ed25519", "migration0020", "P256", "sha256",
		"IPv4", "IPv6Only", "VersionTLS12", "CSV2", "UUIDv4", "X25519",
	} {
		if generational(name) {
			t.Errorf("%s: caught, and it is not a generation", name)
		}
	}
}
