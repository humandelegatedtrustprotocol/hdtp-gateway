package outbound

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// PACT §2 and SPEC §10.3 give outbound calls two ways to accept a server: the
// pinned contact fingerprint, or WebPKI validity for the endpoint hostname. The
// second branch existed and could never succeed, because every production caller
// built the client with `Roots: x509.NewCertPool()` — an EMPTY, non-nil pool.
// Go's x509.Verify treats nil as "use the system roots" and a non-nil pool as an
// exhaustive list, so an empty one trusts nothing and every chain fails with
// "certificate signed by unknown authority".
//
// The consequence was not subtle: a node could not send to any contact whose
// endpoint terminates TLS at an edge — Cloudflare, ngrok, a terminate-mode
// ingress — nor connect to a public relay by hostname, which relaywiring's own
// comment says is "pinned by nothing here". Only direct-mode peers with pinned
// self-signed certificates worked, and those take the FIRST branch, which is why
// every existing test passed.
//
// Found by running two nodes behind real Cloudflare tunnels. It is pinned at the
// source level because the failure needs a real WebPKI chain to reproduce, and a
// test that needs the public internet is a test nobody runs.
func TestProductionNeverBuildsAnEmptyRootPool(t *testing.T) {
	root := repoRoot(t)
	// `Roots:` followed by an unpopulated pool on the same line.
	bad := regexp.MustCompile(`Roots:\s*x509\.NewCertPool\(\)`)

	var found []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(string(b), "\n") {
				if bad.MatchString(line) {
					rel, _ := filepath.Rel(root, p)
					found = append(found, rel+":"+itoa(i+1))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range found {
		t.Errorf("%s builds an outbound client with an EMPTY root pool. That is not "+
			"'no roots configured' — it is 'trust nothing', so WebPKI validation can "+
			"never succeed and this node cannot reach any peer behind a TLS-terminating "+
			"edge (SPEC §10.3). Pass nil for the system roots, or populate the pool.", f)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		d = filepath.Dir(d)
	}
	t.Fatal("no go.mod above the working directory")
	return ""
}
