package fabric

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// FreePort never hands out one port twice, and what it hands out can be bound.
func TestFreePortIsUniqueAndBindable(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		p, err := FreePort()
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("port %s handed out twice", p)
		}
		seen[p] = true
	}
	for p := range seen {
		l, err := net.Listen("tcp", ":"+p)
		if err != nil {
			t.Errorf("FreePort gave %s, which cannot be bound: %v", p, err)
			continue
		}
		_ = l.Close()
		break
	}
}

// A prefix is a DNS label (container names are addresses leaves name), carries the scenario's
// id, and differs between runs by its token.
func TestPrefixForIsALabelWithTheIDAndTheRunToken(t *testing.T) {
	p := PrefixFor("S13")
	if !regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(p) {
		t.Errorf("%q is not a DNS label", p)
	}
	if !strings.HasPrefix(p, "pacts13-") || !strings.HasSuffix(p, runToken) || len(runToken) != 4 {
		t.Errorf("%q does not carry the id and this run's token %q", p, runToken)
	}
}

// No harness source picks a host port by hand. They collided: 18680 and 18681 were two
// scenarios' ports, and so were 18691 and 18692. A port is fabric.FreePort's to give.
func TestNoScenarioPicksAHostPort(t *testing.T) {
	// Files that may name one, and why.
	allowed := map[string]string{
		// The Cloudflare rig is built by docs/demos/cloudflare-two-users.sh, which publishes the
		// owner ports; the test reaches what the script built.
		"scenario/cloudflare_live_test.go": "the demo script's ports",
		// The recorder asserts what argv a published port becomes; nothing is bound.
		"fabric/fabric_test.go": "a recorded argv",
	}
	hostPort := regexp.MustCompile(`^(127\.0\.0\.1:)?1[0-9]{4}(:[0-9]+)?$`)
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if _, ok := allowed[rel]; ok {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING {
				if s, uerr := strconv.Unquote(b.Value); uerr == nil && hostPort.MatchString(s) {
					t.Errorf("%s picks the host port %q: use fabric.FreePort", rel, s)
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
