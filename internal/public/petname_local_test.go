package public

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The petname's entire value is that it is the one name a peer cannot influence.
// That is not a property of the column; it is a property of which packages can
// write it. This package IS the peer-facing surface, so the moment anything here
// reaches SetContactPetname -- however reasonable it looks, "let a contact suggest
// a nicer name" -- the guarantee is gone and nothing else would notice.
func TestNoPeerFacingSurfaceCanSetAPetname(t *testing.T) {
	dir := repoRootPublic(t)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), "SetContactPetname") {
			t.Errorf("%s is on the peer-facing surface and writes a petname. The "+
				"petname is the owner's own name for a contact and must be "+
				"reachable only from the portal and the owner MCP.", filepath.Base(p))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repoRootPublic(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
