package integrationtest

// A fuzz target that CI never runs is just a slower unit test over its seed
// corpus: `go test` executes the seeds and stops. The value is in the generated
// inputs, and those only happen under `-fuzz`. The CI workflow therefore names
// each target explicitly — and this test is what keeps that list honest, because
// the failure mode is silent and the README has already twice claimed more
// fuzzing than was actually running.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var fuzzFunc = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`)

func TestEveryFuzzTargetRunsInCI(t *testing.T) {
	root := repoRoot(t)

	// The list may live in either file — CI calls `make fuzz`, so the target
	// names sit in the Makefile — and what matters is that SOMETHING CI reaches
	// names each one. Reading both means moving the list between them is not a
	// silent way to stop fuzzing.
	var ran string
	for _, f := range [][]string{
		{".github", "workflows", "ci.yml"},
		{"Makefile"},
	} {
		b, err := os.ReadFile(filepath.Join(append([]string{root}, f...)...))
		if err != nil {
			t.Fatal(err)
		}
		ran += string(b)
	}
	ci := ran

	var found int
	err := filepath.WalkDir(filepath.Join(root, "internal"), walkGoTests(func(path string, src []byte) {
		for _, m := range fuzzFunc.FindAllStringSubmatch(string(src), -1) {
			found++
			name := m[1]
			if !strings.Contains(ci, name) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s defines %s but neither ci.yml nor the Makefile's fuzz "+
					"target runs it under -fuzz, so only its seed corpus is ever "+
					"executed. Add it to `make fuzz`.", rel, name)
			}
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no fuzz targets found at all; this test is not checking anything")
	}
}
