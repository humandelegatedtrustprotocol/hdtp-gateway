package images

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every upstream image is pinned by digest, and nothing built here pretends to be.
func TestPulledImagesArePinnedByDigest(t *testing.T) {
	for _, ref := range Pulled {
		if !strings.Contains(ref, "@sha256:") || len(ref[strings.Index(ref, "@sha256:")+8:]) != 64 {
			t.Errorf("%s is not pinned by a sha256 digest", ref)
		}
		if strings.Contains(ref, ":latest") {
			t.Errorf("%s names :latest", ref)
		}
	}
	for _, ref := range Local {
		if strings.Contains(ref, "@") {
			t.Errorf("%s is built here and has no registry digest to pin", ref)
		}
	}
}

// The lists are what the other guards read, so a constant missing from both escapes them.
func TestEveryImageConstantIsListed(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "images.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	listed := append(slices.Clone(Local), Pulled...)
	byName := map[string]string{
		"Node": Node, "Caldav": Caldav, "Shaper": Shaper, "Alpine": Alpine, "Socat": Socat,
		"Curl": Curl, "Pebble": Pebble, "CoreDNS": CoreDNS, "Radicale": Radicale, "Frps": Frps,
	}
	seen := 0
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		// Node is a var (its tag may be chosen per worktree); the rest are constants.
		if !ok || (g.Tok != token.CONST && g.Tok != token.VAR) {
			continue
		}
		for _, s := range g.Specs {
			for _, n := range s.(*ast.ValueSpec).Names {
				if n.Name == "ShaperDockerfile" || n.Name == "Local" || n.Name == "Pulled" {
					continue
				}
				seen++
				v, ok := byName[n.Name]
				if !ok {
					t.Errorf("images.%s is not in this test's name table; add it here and to Local or Pulled", n.Name)
					continue
				}
				if !slices.Contains(listed, v) {
					t.Errorf("images.%s (%s) is in neither Local nor Pulled", n.Name, v)
				}
			}
		}
	}
	if seen != len(byName) || len(listed) != len(byName) {
		t.Errorf("%d image constants, %d in the name table, %d listed: they must agree", seen, len(byName), len(listed))
	}
}

// No file but this package names an image. A second copy of a reference is how `alpine/socat`
// stayed untagged in two scenarios after the constant beside them was pinned.
func TestNoOtherFileNamesAnImage(t *testing.T) {
	var repos []string
	for _, ref := range Pulled {
		repos = append(repos, strings.SplitN(strings.SplitN(ref, "@", 2)[0], ":", 2)[0])
	}
	names := func(lit string) bool {
		if strings.HasSuffix(lit, ":latest") {
			return true
		}
		for _, ref := range Local {
			if strings.Contains(lit, ref) {
				return true
			}
		}
		for _, repo := range repos {
			if lit == repo || strings.HasPrefix(lit, repo+":") || strings.HasPrefix(lit, repo+"@") {
				return true
			}
		}
		return false
	}
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if filepath.Base(path) == "images" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING {
				if s, uerr := strconv.Unquote(b.Value); uerr == nil && names(s) {
					t.Errorf("%s names the image %q: use the constant in harness/images", path, s)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The Makefile builds the local images and runs Alpine for the guest kernel. Its references are
// held to the constants, and the shaper's recipe exists only in Go.
func TestTheMakefileAgreesWithTheConstants(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	mk := string(b)
	// The node image's tag is the Makefile's HARNESS_IMAGE, handed to the harness as
	// PACT_HARNESS_IMAGE; both default to the one tag images.go falls back to.
	const nodeDefault = "pact-gateway:harness"
	if os.Getenv("PACT_HARNESS_IMAGE") == "" && Node != nodeDefault {
		t.Errorf("with PACT_HARNESS_IMAGE unset the node image is %s, not %s", Node, nodeDefault)
	}
	for _, want := range []string{"HARNESS_IMAGE ?= " + nodeDefault + "\n", "export PACT_HARNESS_IMAGE := $(HARNESS_IMAGE)\n", "-t $(HARNESS_IMAGE) "} {
		if !strings.Contains(mk, want) {
			t.Errorf("the Makefile has no %q: the node image it builds is not the one the harness runs", strings.TrimSpace(want))
		}
	}
	for _, ref := range []string{Caldav} {
		if !strings.Contains(mk, "-t "+ref+" ") && !strings.Contains(mk, "-t "+ref+"\n") {
			t.Errorf("the Makefile does not build %s", ref)
		}
	}
	for _, m := range regexp.MustCompile(`alpine:[^\s'"]+`).FindAllString(mk, -1) {
		if m != Alpine {
			t.Errorf("the Makefile runs %s; the harness pins %s", m, Alpine)
		}
	}
	if strings.Contains(mk, "add --no-cache iproute2") {
		t.Error("the Makefile carries its own shaper recipe; images.ShaperDockerfile is the one copy")
	}
}
