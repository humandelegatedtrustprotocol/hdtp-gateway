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
//
// The `toolchain` line is the other half. The golang image sets GOTOOLCHAIN=local, under which
// a toolchain line is ignored rather than refused: an image older than the toolchain go.mod
// names does not fail to build, it builds with the older Go and ships that Go's standard
// library. So the image is held to the newer of the two lines, patch included — a floating
// `golang:1.26` tag does not satisfy `toolchain go1.26.9`.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	goDirective        = regexp.MustCompile(`(?m)^go\s+(\d+)\.(\d+)(?:\.(\d+))?`)
	toolchainDirective = regexp.MustCompile(`(?m)^toolchain\s+go(\d+)\.(\d+)(?:\.(\d+))?`)
	golangImage        = regexp.MustCompile(`(?m)^FROM\s+golang:(\d+)\.(\d+)(?:\.(\d+))?`)
	dockerfiles        = []string{"Dockerfile", "Dockerfile.full"}
	errNoVersion       = "could not find a version to compare"
)

// goVersion is major.minor.patch; a line that names no patch is .0.
type goVersion [3]int

func (v goVersion) below(w goVersion) bool {
	for i := range v {
		if v[i] != w[i] {
			return v[i] < w[i]
		}
	}
	return false
}

func (v goVersion) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// parseGoVersion reads the three capture groups of goDirective, toolchainDirective or golangImage.
func parseGoVersion(t *testing.T, m []string) goVersion {
	t.Helper()
	var v goVersion
	for i, s := range m[1:4] {
		if s != "" {
			v[i] = atoi(t, s)
		}
	}
	return v
}

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
	want, line := parseGoVersion(t, m), "go"
	if tm := toolchainDirective.FindStringSubmatch(string(b)); tm != nil {
		if tv := parseGoVersion(t, tm); want.below(tv) {
			want, line = tv, "toolchain"
		}
	}

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
		if got := parseGoVersion(t, im); got.below(want) {
			t.Errorf("%s: %q is below go.mod's %s line (go%s). The golang image sets GOTOOLCHAIN=local: "+
				"an image below the `go` line cannot build, and one below the `toolchain` line builds "+
				"with its own older Go, since local ignores that line. Either way `docker compose up` "+
				"(SPEC §12.4, and the README quickstart) does not ship what go.mod names, and make check "+
				"cannot notice: it builds with go.mod's toolchain and never builds an image.",
				f, strings.TrimSpace(im[0]), line, want)
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
