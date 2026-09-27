package integrationtest

// A fuzz target that nothing runs under -fuzz is just a slower unit test over its
// seed corpus: `go test` executes the seeds and stops. The value is in the generated
// inputs, and those only happen under `-fuzz`. `make fuzz` therefore names each target
// explicitly, the pre-push hook runs it (githooks/pre-push), and this test is what keeps
// that list honest, because the failure mode is silent and the README has already twice
// claimed more fuzzing than was actually running.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var fuzzFunc = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`)

func TestEveryFuzzTargetRunsUnderMakeFuzz(t *testing.T) {
	root := repoRoot(t)

	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	fuzz := fuzzRecipe(t, string(b))

	var found int
	err = filepath.WalkDir(filepath.Join(root, "internal"), walkGoTests(func(path string, src []byte) {
		for _, m := range fuzzFunc.FindAllStringSubmatch(string(src), -1) {
			found++
			name := m[1]
			if !strings.Contains(fuzz, "-fuzz '^"+name+"$$'") {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s defines %s but the Makefile's fuzz target does not run "+
					"it under -fuzz, so only its seed corpus is ever executed. Add it "+
					"to `make fuzz`.", rel, name)
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

// fuzzRecipe returns the recipe lines of the Makefile's `fuzz:` target, so a target
// named anywhere else in the Makefile (a comment, another recipe) does not count.
func fuzzRecipe(t *testing.T, makefile string) string {
	t.Helper()
	var out strings.Builder
	in := false
	for _, line := range strings.Split(makefile, "\n") {
		switch {
		case strings.HasPrefix(line, "fuzz:"):
			in = true
		case in && strings.HasPrefix(line, "\t"):
			out.WriteString(line)
			out.WriteByte('\n')
		case in:
			in = false
		}
	}
	if out.Len() == 0 {
		t.Fatal("the Makefile has no fuzz: target with a recipe")
	}
	return out.String()
}
