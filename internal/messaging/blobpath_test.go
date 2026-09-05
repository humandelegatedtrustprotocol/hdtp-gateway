package messaging

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

// A content hash is the only thing that decides which file the blob store opens,
// so anything that is not a hash must not reach the filesystem as one. Nothing
// passes a bad hash today — Put computes it, and the portal route looks the blob
// row up in the store first — but "the caller checks" is a property of today's
// callers, not of this function.
func TestBlobPathRefusesAnythingThatIsNotAHash(t *testing.T) {
	b := BlobDir{Root: t.TempDir()}

	for _, tc := range []struct{ name, hash string }{
		{"traversal", "../../../../etc/passwd"},
		{"traversal inside a valid-looking prefix", "ab/../../../../etc/passwd"},
		{"absolute path", "/etc/passwd"},
		{"empty", ""},
		{"one character", "a"},   // hash[:2] used to panic outright here
		{"two characters", "ab"}, // as did the directory split on a short hash
		{"uppercase hex", "AB" + "cd" + "00000000000000000000000000000000000000000000000000000000000000"[:60]},
		{"right length, not hex", "zz" + "00000000000000000000000000000000000000000000000000000000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p := b.path(tc.hash); p != "" {
				t.Errorf("path(%q) = %q; a non-hash reached the filesystem", tc.hash, p)
			}
			// And the accessors must report absence rather than panic or escape.
			if _, err := b.Get(tc.hash); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Get(%q) err = %v, want fs.ErrNotExist", tc.hash, err)
			}
			if err := b.Remove(tc.hash); err != nil {
				t.Errorf("Remove(%q) = %v, want nil", tc.hash, err)
			}
		})
	}
}

// The real thing still has to work, or the guard above is just an outage.
func TestBlobRoundTripStillWorks(t *testing.T) {
	b := BlobDir{Root: t.TempDir()}
	hash, err := b.Put([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if p := b.path(hash); p == "" {
		t.Fatalf("a hash from Put was rejected by path()")
	} else if filepath.Base(p) != hash {
		t.Errorf("path() = %q, want it to end in the hash", p)
	}
	got, err := b.Get(hash)
	if err != nil || string(got) != "hello" {
		t.Fatalf("Get after Put: %q %v", got, err)
	}
	if err := b.Remove(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(hash); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("after Remove, Get err = %v, want fs.ErrNotExist", err)
	}
}
