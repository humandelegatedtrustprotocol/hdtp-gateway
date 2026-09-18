package store_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// The query sources must be ASCII, and this is not a style rule.
//
// sqlc slices each statement out of the file by offset, and v1.30.0 computes that
// offset in RUNES while slicing BYTES. One em dash earlier in the file shifts every
// statement after it by two, and the drift accumulates: on 2026-09-18 the generator
// emitted `const setContactAccepted` as
//
//	t = ?;
//
//	UPDATE contacts SET status = 'active', ...
//	WHERE account_id = ? AND fingerpri
//
// from a file nobody had edited, and refused others outright ("extraneous input
// 'SELEaccount_id'"). Three em dashes and fourteen section signs in comments were the
// whole cause, and nothing would have told us: the SQL is text until it runs, and
// several corrupted statements were `:execrows` updates whose failure is a zero.
//
// Migration files are exempt on purpose — they are parsed for column metadata, not
// sliced for text, and stripping their comments was verified to change nothing in the
// generated output.
func TestQuerySourcesAreASCII(t *testing.T) {
	root := filepath.Join("..", "..", "..", "queries")
	var checked int
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		checked++
		for i, r := range string(b) {
			if r > 127 {
				line := 1 + strings.Count(string(b[:i]), "\n")
				t.Errorf("%s:%d: non-ASCII %q (U+%04X) in a query source: sqlc mis-slices every statement after it", path, line, r, r)
			}
			if r == utf8.RuneError {
				t.Errorf("%s:%d: invalid UTF-8", path, 1+strings.Count(string(b[:i]), "\n"))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no query sources found: this guard is looking in the wrong place")
	}
}
