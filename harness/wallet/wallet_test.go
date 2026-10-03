package wallet

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// An account nobody certified is nobody (HDTP §2): the node has no chain to present, and the
// first dial ends `tls: internal error`. Every live scenario in this module did exactly that for
// as long as an account has needed a wallet — create an account, call it — and nothing said so, because a live
// scenario is skipped unless HDTP_HARNESS_LIVE is set and the hook that runs this module does not
// set it. This is the hermetic half of the fix: it cannot tell that a scenario PASSES, but it can
// tell that a file creates an account and never hands it to a wallet.
func TestEveryAccountAScenarioCreatesIsCertified(t *testing.T) {
	// A file that creates an account and makes no HDTP call to it, with the reason.
	uncertified := map[string]string{
		"vm/live_test.go": "boots a guest to read its clock: it creates an account so a row is stamped, and dials nothing",
	}
	creates := regexp.MustCompile(`"account",\s*"create"|account create --slug`)
	certifies := regexp.MustCompile(`\.Certify(Until)?\(`)
	root := ".."
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		if rel == "wallet/wallet_test.go" {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := string(b)
		if !creates.MatchString(src) {
			return nil
		}
		if why, ok := uncertified[rel]; ok {
			seen[rel] = true
			_ = why
			return nil
		}
		if !certifies.MatchString(src) {
			t.Errorf("%s creates an account and never has a wallet certify it. An account is nobody until "+
				"it holds a leaf under its owner's root: use wallet.Certify, or list the file here with why it dials nothing.", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range uncertified {
		if !seen[rel] {
			t.Errorf("%s is listed as creating an account it never certifies, and creates none: the list is stale", rel)
		}
	}
}
