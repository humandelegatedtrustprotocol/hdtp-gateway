package integrationtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The README lists this package's files by what each holds, and a file added without a line there
// is a guard nobody reading the README knows exists (hardening_status_test.go went unlisted). It is
// read from the package's own directory.
func TestTheReadmeNamesEveryFile(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 20 {
		t.Fatalf("found %d Go files beside the README; the reader is broken", len(files))
	}
	for _, f := range files {
		if !strings.Contains(string(readme), "`"+f+"`") {
			t.Errorf("%s is not named in internal/integrationtest/README.md: add a line saying what it holds", f)
		}
	}
}
