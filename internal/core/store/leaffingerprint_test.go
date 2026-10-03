package store_test

// Every pin carries the fingerprint of its leaf's key (`leaf_fingerprint`), which PinCandidates finds
// a small form's pin by. There is no branch for a row without it: a row that holds a leaf and no
// fingerprint is a contact whose small-form calls find no pin. So every statement that writes `leaf`
// writes `leaf_fingerprint` with it, and that is held here.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every statement that writes `leaf` into contacts writes `leaf_fingerprint` beside it, in both
// dialects: an INSERT that lists `leaf` lists `leaf_fingerprint`, an UPDATE that sets one sets the
// other. The control: the statements are found (five writers in each dialect today).
func TestEveryStatementThatWritesALeafWritesItsFingerprint(t *testing.T) {
	header := regexp.MustCompile(`(?m)^-- name: ([A-Za-z]+) :[a-z]+\s*$`)
	insertLeaf := regexp.MustCompile(`(?is)INSERT INTO contacts\s*\(([^)]*)\)`)
	setLeaf := regexp.MustCompile(`(?is)UPDATE contacts SET (.*?)\bWHERE\b`)
	for _, dialect := range []string{"sqlite", "postgres"} {
		dir := filepath.Join("..", "..", "..", "queries", dialect)
		files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
		if err != nil {
			t.Fatal(err)
		}
		writers := 0
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			src := string(b)
			locs := header.FindAllStringSubmatchIndex(src, -1)
			for i, loc := range locs {
				end := len(src)
				if i+1 < len(locs) {
					end = locs[i+1][0]
				}
				name, body := src[loc[2]:loc[3]], src[loc[1]:end]
				var written []string
				if m := insertLeaf.FindStringSubmatch(body); m != nil {
					written = strings.Split(m[1], ",")
				} else if m := setLeaf.FindStringSubmatch(body); m != nil {
					for _, a := range strings.Split(m[1], ",") {
						written = append(written, strings.SplitN(a, "=", 2)[0])
					}
				}
				has := map[string]bool{}
				for _, c := range written {
					has[strings.TrimSpace(c)] = true
				}
				if !has["leaf"] {
					continue
				}
				writers++
				if !has["leaf_fingerprint"] {
					t.Errorf("%s: %s writes contacts.leaf and not leaf_fingerprint", dialect, name)
				}
			}
		}
		if writers < 5 {
			t.Fatalf("%s: %d statements write a contact's leaf; this guard is checking nothing", dialect, writers)
		}
	}
}
