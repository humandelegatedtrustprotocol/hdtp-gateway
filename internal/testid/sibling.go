package testid

// A test that holds a copy here to its source in a repository checked out beside this one, as the
// umbrella holds them (a fixture the cloud reads, the specification's table), reads it here.

import (
	"os"
	"path/filepath"
	"testing"
)

// SiblingFile returns the bytes of rel, a slash-separated path inside the repository repo, which sits beside
// this module's root (the directory holding go.mod). The test is skipped, saying what goes unchecked,
// only when repo's directory is absent. When it is present and the file cannot be read, the test
// fails: a guard that skipped on any missing file passed the day its file moved.
func SiblingFile(t testing.TB, repo, rel, unchecked string) []byte {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), "..", repo)
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("SKIPPED, and so %s: no %s checkout beside this repository (%v)", unchecked, repo, err)
	}
	path := filepath.Join(dir, filepath.FromSlash(rel))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the %s checkout is beside this repository but %s cannot be read: %v", repo, rel, err)
	}
	return b
}

// moduleRoot is the nearest directory upward from the test's working directory that holds go.mod.
func moduleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}
