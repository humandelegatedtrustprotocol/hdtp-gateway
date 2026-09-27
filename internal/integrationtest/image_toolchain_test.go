package integrationtest

// `go build` on the host follows go.mod's toolchain line (GOTOOLCHAIN), so it always
// uses whatever toolchain go.mod asks for. The Dockerfiles pin a golang image by tag instead, and
// nothing compared the two — so when go.mod's `go` directive was raised, the images
// silently stopped building:
//
//	go: go.mod requires go >= 1.26.6 (running go 1.25.14; GOTOOLCHAIN=local)
//
// That breaks `docker compose up`, which SPEC §12.4 and the README quickstart both
// present as the first thing a new owner does. `make check` cannot notice, because it
// never builds an image. This test is the comparison nobody was making.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	goDirective  = regexp.MustCompile(`(?m)^go\s+(\d+)\.(\d+)(?:\.(\d+))?`)
	golangImage  = regexp.MustCompile(`(?m)^FROM\s+golang:(\d+)\.(\d+)`)
	dockerfiles  = []string{"Dockerfile", "Dockerfile.full"}
	errNoVersion = "could not find a version to compare"
)

func TestImageToolchainSatisfiesGoMod(t *testing.T) {
	root := repoRoot(t)

	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := goDirective.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("go.mod: %s", errNoVersion)
	}
	wantMajor, wantMinor := atoi(t, m[1]), atoi(t, m[2])

	for _, f := range dockerfiles {
		df, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue // a variant that does not exist cannot be stale
		}
		im := golangImage.FindStringSubmatch(string(df))
		if im == nil {
			t.Errorf("%s: %s in its FROM golang: line", f, errNoVersion)
			continue
		}
		gotMajor, gotMinor := atoi(t, im[1]), atoi(t, im[2])
		if gotMajor < wantMajor || (gotMajor == wantMajor && gotMinor < wantMinor) {
			t.Errorf("%s builds with golang:%d.%d but go.mod requires go >= %d.%d — "+
				"the image cannot build at all, so `docker compose up` (SPEC §12.4, and the "+
				"README quickstart) is broken. make check does not catch this: "+
				"it builds with go.mod's toolchain and never builds an image.",
				f, gotMajor, gotMinor, wantMajor, wantMinor)
		}
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		t.Fatalf("parsing version component %q: %v", s, err)
	}
	return n
}
