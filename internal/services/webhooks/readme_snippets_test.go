package webhooks

// The receiver's verifier the repository's README gives, in Go, runs against what the node signs:
// the snippet is read out of the README itself and run with `go run`, so it cannot go stale beside
// the signer. The node's tests need no tool but Go.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// readmeHowTo is the README's how-to a receiver follows.
const readmeHowTo = "### Wake your agent with a webhook"

// readmeHowToText is the README's how-to, to the next heading of its level.
func readmeHowToText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "\n"+readmeHowTo+"\n")
	if i < 0 {
		t.Fatalf("README.md has no %q", readmeHowTo)
	}
	s = s[i+len(readmeHowTo)+2:]
	if j := strings.Index(s, "\n### "); j >= 0 {
		s = s[:j]
	}
	return s
}

// readmeGoSnippet is the one fenced Go block in the README's how-to.
func readmeGoSnippet(t *testing.T) string {
	t.Helper()
	s := readmeHowToText(t)
	blocks := regexp.MustCompile("(?s)\n```go\n(.*?)\n```\n").FindAllStringSubmatch(s, -1)
	if len(blocks) != 1 {
		t.Fatalf("the README's how-to has %d ```go blocks, want 1", len(blocks))
	}
	return blocks[0][1] + "\n"
}

// verifyCase is one delivery a verifier is handed, and whether it must accept it.
type verifyCase struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Header string `json:"header"`
	Body   string `json:"body"`
	Now    int64  `json:"now"`
	want   bool
}

// verifyCases are deliveries signed by Signature: accepted as sent, by either secret while a
// rotation lasts, and up to ToleranceSeconds either way; refused with a changed body, under another
// secret, a second outside the window, and with no signature at all.
func verifyCases(t *testing.T) []verifyCase {
	t.Helper()
	const at = 1_800_000_000
	body, err := EnvelopeBody(EventEnvelope{ID: "evt_42", Type: "message.received", CreatedAt: at * 1000, Identity: "acct-1",
		Data: map[string]any{"thread_id": "thé", "message_id": "m1", "from": "sha256:a"}})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(secrets []string, ts int64) string {
		h, err := Signature(secrets, body, ts)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	const cur, old = "whsec_current", "whsec_replaced"
	return []verifyCase{
		{Name: "as sent", Secret: cur, Header: sign([]string{cur}, at), Body: body, Now: at, want: true},
		{Name: "rotating, the new secret", Secret: cur, Header: sign([]string{cur, old}, at), Body: body, Now: at, want: true},
		{Name: "rotating, the replaced secret", Secret: old, Header: sign([]string{cur, old}, at), Body: body, Now: at, want: true},
		{Name: "at the window's edge, late", Secret: cur, Header: sign([]string{cur}, at-ToleranceSeconds), Body: body, Now: at, want: true},
		{Name: "at the window's edge, early", Secret: cur, Header: sign([]string{cur}, at+ToleranceSeconds), Body: body, Now: at, want: true},
		{Name: "a changed body", Secret: cur, Header: sign([]string{cur}, at), Body: strings.Replace(body, "m1", "m2", 1), Now: at, want: false},
		{Name: "another secret", Secret: "whsec_other", Header: sign([]string{cur}, at), Body: body, Now: at, want: false},
		{Name: "a second too late", Secret: cur, Header: sign([]string{cur}, at-ToleranceSeconds-1), Body: body, Now: at, want: false},
		{Name: "a second too early", Secret: cur, Header: sign([]string{cur}, at+ToleranceSeconds+1), Body: body, Now: at, want: false},
		{Name: "no signature", Secret: cur, Header: "t=1800000000", Body: body, Now: at, want: false},
	}
}

// checkVerdicts compares what the snippet answered for each case with what it must answer.
func checkVerdicts(t *testing.T, cases []verifyCase, out []byte) {
	t.Helper()
	var got []bool
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("the Go snippet answered %q: %v", out, err)
	}
	for i, c := range cases {
		if got[i] != c.want {
			t.Errorf("the README's Go verifier answers %v for %q, want %v", got[i], c.Name, c.want)
		}
	}
	// The control: the cases are not all one answer, so a verifier that says the same to every
	// delivery fails one of them.
	if !slices.Contains(got, true) || !slices.Contains(got, false) {
		t.Errorf("the Go verifier answered %v", got)
	}
}

func casesJSON(t *testing.T, cases []verifyCase) string {
	t.Helper()
	b, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const goRunner = `package main

import (
	"encoding/json"
	"os"
	"time"
)

func main() {
	var cases []struct {
		Secret, Header, Body string
		Now                  int64
	}
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		panic(err)
	}
	var out []bool
	for _, c := range cases {
		out = append(out, verify(c.Secret, c.Header, []byte(c.Body), time.Unix(c.Now, 0)))
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
`

func TestTheREADMEsGoVerifierAcceptsWhatTheNodeSignsAndNothingElse(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("go is not on PATH, so the README's Go verifier cannot be run")
	}
	dir := t.TempDir()
	for name, text := range map[string]string{
		"go.mod":    "module readme.example/verify\n\ngo 1.26\n",
		"verify.go": "package main\n\n" + readmeGoSnippet(t),
		"main.go":   goRunner,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := verifyCases(t)
	cmd := exec.Command(gobin, "run", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local")
	cmd.Stdin = strings.NewReader(casesJSON(t, cases))
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("go run the README's verifier: %v\n%s", err, stderr)
	}
	checkVerdicts(t, cases, out)
}

// The how-to names every event a filter takes, and no name the node does not send, so its list
// cannot fall behind the table.
func TestTheREADMEsHowToNamesEveryEventTheNodeSends(t *testing.T) {
	s := readmeHowToText(t)
	sent := Subscribable()
	for _, n := range sent {
		if !strings.Contains(s, "`"+n+"`") {
			t.Errorf("the README's how-to does not name %s, which the node sends", n)
		}
	}
	named := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z]+\\.[a-z_]+)`").FindAllStringSubmatch(s, -1) {
		named[m[1]] = true
	}
	for n := range named {
		if !strings.HasPrefix(n, "data.") && !slices.Contains(sent, n) {
			t.Errorf("the README's how-to names %s, which the node does not send", n)
		}
	}
}
