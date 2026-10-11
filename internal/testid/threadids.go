package testid

import "strings"

// ThreadIDCase is one thread_id and HDTP §7's answer to it: "" for an id of one of the two forms,
// or the code a receiver refuses it with (too_large over 64 bytes, checked first, else bad_request).
type ThreadIDCase struct {
	Name, ID, Code string
}

// ThreadIDs is the one table of thread_ids every door's tests and the wipe's run: the ids of
// neither form, each with its refusal, and the controls of a form, which must get through. It holds
// the seed's cases (SEP-0006, Evidence) and the ones a URL path, a CSV cell or a C string reads
// apart.
func ThreadIDs() []ThreadIDCase {
	hex62 := strings.Repeat("0123456789abcdef", 4)[:62]
	return []ThreadIDCase{
		{"dot", ".", "bad_request"},
		{"two dots", "..", "bad_request"},
		{"percent-encoded dot", "%2e", "bad_request"},
		{"slash", "a/b", "bad_request"},
		{"hyphen", "my-thread", "bad_request"},
		{"space", "a b", "bad_request"},
		{"empty", "", "bad_request"},
		{"r- re-issue of 0.8.1", "r-" + hex62, "bad_request"},
		{"upper-case UUID", "3B1F0C9A-6E2D-4F5B-8A7C-1E0D9F2B4A6C", "bad_request"},
		{"32 hex with a hyphen", "3b1f0c9a6e2d4f5b-8a7c1e0d9f2b4a6c", "bad_request"},
		{"control character", "a\x01b", "bad_request"},
		{"trailing line break", "abc\n", "bad_request"},
		{"non-ASCII", "é", "bad_request"},
		{"CJK", "日本", "bad_request"},
		{"65 letters and digits", strings.Repeat("a", 65), "too_large"},
		{"33 two-byte characters", strings.Repeat("é", 33), "too_large"},
		{"64 letters and digits", strings.Repeat("Ab3", 21) + "z", ""},
		{"lower-case UUID", "3b1f0c9a-6e2d-4f5b-8a7c-1e0d9f2b4a6c", ""},
		{"r re-issue", "r" + hex62, ""},
		{"32 hex, as this node mints", "3b1f0c9a6e2d4f5b8a7c1e0d9f2b4a6c", ""},
		{"one letter", "x", ""},
		{"mixed case", "Abc", ""},
	}
}
