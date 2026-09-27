package scenario

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-identity/go/exportcorpus"

	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/registry"
)

// S22 — the shared hostile export corpus through the shipped image's own door.
//
// pact-identity's exportcorpus is one set of files both hosts are held to (zip-slip, absolute and
// backslash names, symlinks, encrypted entries, understated sizes, key material in a body or a
// cell, a key as media, the wrong owner, counts that lie, …), each with the refusal it must meet
// in words, and the valid files that must be taken whole. internal/portable reads every one of them
// through the package. What no test did is hand them to the binary a person runs: `pact-gateway
// import FILE.zip -slug S`, in the image, over a real data directory. Each file goes to a slug of
// its own data directory and a new slug, which is the door an attacker's file meets first; the file
// that belongs to another identity is imported into the corpus owner's identity instead (the two
// ways internal/portable's own corpus tests read it).
//
// A refused file must be refused in the corpus's words, say nothing was written, and leave no
// identity behind; a valid one must be reviewed first (nothing written) and then taken with the
// counts the corpus names. The valid files are the control: a door that refused everything would
// pass every hostile case.
func TestTheHostileCorpusIsRefusedByTheShippedImage(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S22", Name: "the shared hostile export corpus through the shipped image's import: each refused in its words, nothing written, the valid files taken whole", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage},
		Timeout: 15 * time.Minute,
	})
	raw, err := fs.ReadFile(exportcorpus.FS, "cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var idx exportcorpus.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	accepts := 0
	for _, c := range idx.Cases {
		if c.Accept != nil {
			accepts++
		}
	}
	// Floors, from the corpus's own promise of one file per check of §9.2 and at least one control.
	if len(idx.Cases) < 30 || accepts == 0 {
		t.Fatalf("the corpus names %d cases, %d of them valid: it is not being read", len(idx.Cases), accepts)
	}

	dir := t.TempDir()
	n := 0
	// fresh is a data directory of its own for one file: an import into a new slug is refused when
	// the file's root is already an identity on the node (every corpus file names one owner), so
	// each file meets a node that has never held it. The container is created, not started; the
	// file is copied into its data directory; `start -a` runs the import, and later commands run
	// over the same directory with --volumes-from.
	fresh := func(file string) (name, inNode string) {
		t.Helper()
		b, err := fs.ReadFile(exportcorpus.FS, file)
		if err != nil {
			t.Fatal(err)
		}
		host := filepath.Join(dir, file)
		if err := os.WriteFile(host, b, 0o644); err != nil { //nolint:gosec // a test file the nonroot node must read
			t.Fatal(err)
		}
		n++
		name = w.Fab.Name(fmt.Sprintf("corpus%02d", n))
		inNode = "/data/" + file
		docker(ctx, t, w.Fab, "create", "--name", name, images.Node, "export", "-slug", "none", "-out", "/data/none.zip")
		t.Cleanup(func() { _, _ = w.Fab.Raw(ctx, "docker", "rm", "-f", "-v", name) })
		docker(ctx, t, w.Fab, "cp", host, name+":"+inNode)
		return name, inNode
	}
	over := func(name string, args ...string) (string, error) {
		out, err := w.Fab.Raw(ctx, "docker", append([]string{"run", "--rm", "--volumes-from", name, images.Node}, args...)...)
		return string(out), err
	}
	// identities is what `export` finds for a slug: nothing, for a directory a refused file left.
	holds := func(name, slug string) bool {
		_, err := over(name, "export", "-slug", slug, "-out", "/data/probe-"+slug+".zip")
		return err == nil
	}
	refusedInItsWords := func(t *testing.T, c exportcorpus.Case, out string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s (%s) was not refused:\n%s", c.File, c.About, out)
		}
		if !strings.Contains(out, "nothing was written") {
			t.Errorf("%s was refused without saying nothing was written:\n%s", c.File, out)
		}
		switch {
		case c.Refusal != "" && !strings.Contains(out, "import: refused: "+c.Refusal+"\n"):
			t.Errorf("%s: refused with\n%s\nwant the words\n  %q", c.File, out, c.Refusal)
		case c.RefusalPrefix != "" && !strings.Contains(out, "import: refused: "+c.RefusalPrefix):
			t.Errorf("%s: refused with\n%s\nwant it to begin %q", c.File, out, c.RefusalPrefix)
		}
	}

	// Into a new slug: every file but the one whose point is that it belongs to another identity.
	for _, c := range idx.Cases {
		if c.File == "wrong-owner.zip" {
			continue
		}
		t.Run("new identity/"+c.File, func(t *testing.T) {
			name, inNode := fresh(c.File)
			review, rerr := over(name, "import", inNode, "-slug", "fresh")
			if c.Accept == nil {
				refusedInItsWords(t, c, review, rerr)
				if holds(name, "fresh") {
					t.Errorf("%s was refused and left an identity behind", c.File)
				}
				return
			}
			if rerr != nil || !strings.Contains(review, "nothing was written. If this is what you expect") {
				t.Fatalf("%s (valid) was not reviewed: %v\n%s", c.File, rerr, review)
			}
			if holds(name, "fresh") {
				t.Fatalf("%s: the review wrote an identity", c.File)
			}
			done, err := over(name, "import", inNode, "-slug", "fresh", "-yes")
			if err != nil {
				t.Fatalf("%s (valid) was refused: %v\n%s", c.File, err, done)
			}
			want := fmt.Sprintf("%d contact(s), %d thread(s), %d message(s), %d file(s)",
				c.Accept.Contacts, c.Accept.Threads, c.Accept.Messages, c.Accept.Media)
			if !strings.Contains(done, want) {
				t.Errorf("%s: imported\n%s\nwant %s", c.File, done, want)
			}
			if !holds(name, "fresh") {
				t.Errorf("%s was imported and no identity is held", c.File)
			}
		})
	}

	// Into the identity the corpus belongs to, which a valid file made: another identity's export
	// is refused there.
	t.Run("the owner's identity/wrong-owner.zip", func(t *testing.T) {
		var book, wrong exportcorpus.Case
		for _, c := range idx.Cases {
			switch {
			case c.File == "wrong-owner.zip":
				wrong = c
			case c.Accept != nil && book.File == "":
				book = c
			}
		}
		if wrong.File == "" || book.File == "" {
			t.Fatalf("the corpus has no wrong-owner.zip or no valid file")
		}
		name, inNode := fresh(book.File)
		if out, err := over(name, "import", inNode, "-slug", "alina", "-yes"); err != nil {
			t.Fatalf("the control, %s into alina: %v\n%s", book.File, err, out)
		}
		b, err := fs.ReadFile(exportcorpus.FS, wrong.File)
		if err != nil {
			t.Fatal(err)
		}
		host := filepath.Join(dir, wrong.File)
		if err := os.WriteFile(host, b, 0o644); err != nil { //nolint:gosec // as above
			t.Fatal(err)
		}
		docker(ctx, t, w.Fab, "cp", host, name+":/data/"+wrong.File)
		out, err := over(name, "import", "/data/"+wrong.File, "-slug", "alina")
		refusedInItsWords(t, wrong, out, err)
	})
}
