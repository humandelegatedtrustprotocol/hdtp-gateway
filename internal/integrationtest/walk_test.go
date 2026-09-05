package integrationtest

import (
	"io/fs"
	"os"
	"strings"
)

// walkGoTests visits every _test.go file under a root, handing the callback its
// path and contents.
func walkGoTests(fn func(path string, src []byte)) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		fn(p, b)
		return nil
	}
}
