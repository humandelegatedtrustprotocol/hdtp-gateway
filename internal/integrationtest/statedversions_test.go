package integrationtest

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// What the documents and the comments SAY about the wire's versions, held to what the code writes.
//
// A version is written in many sentences: the card builder's table in SPEC.md, the review brief's
// description of the header, a field's comment, a dozen comments that name the envelope. A
// sentence nobody compares with the code can say another number, and every test still passes,
// because no test reads a sentence. After the protocol's versions restarted, three sentences here
// went on giving the old number as the valid one, in a tree whose gate was green.
//
// So the statements are read out of the text, by kind, and each is compared with the value the
// code writes: the card a built identity serves, the header of an envelope the library seals, the
// manifest of an export it writes, and the library's own constants. Nothing below knows the right
// number.
//
// What is read: every Markdown file at the repository's root, every file under docs/, and the
// COMMENTS of every Go file. A Go string is not read. A test that feeds a wrong version in on
// purpose writes it in a string, and that is a value, not a statement.

// statement is one sentence's claim about a version: its kind, the value it gives, and where.
type statement struct {
	kind  string
	value string
	file  string
	line  int
}

const (
	kindCard       = "the card's major (X-HDTP-VERSION)"
	kindEnvelope   = "an envelope's `v`"
	kindVaultPlain = "a vault plaintext's `v`"
	kindExport     = "an export's `hdtp_export`"
	kindInfo       = "the HPKE info label"
	kindVaultFmt   = "the vault format"
	kindDerivation = "a derivation label"
	kindProtocol   = "a `Protocol` field's number"
)

// statedForms is every way a version is written here. Each pattern's first group is the value.
var statedForms = []struct {
	kind string
	re   *regexp.Regexp
}{
	// The property with its value, and the property followed on its line by a quoted number: the
	// builder table's "constant" cell, a field comment's MUST.
	{kindCard, regexp.MustCompile(`X-HDTP-VERSION:\s?(\d[\d.]*)`)},
	{kindCard, regexp.MustCompile("X-HDTP-VERSION`?[^\\n`\"]{0,48}[`\"](\\d[\\d.]*)[`\"]")},
	// The header's member: named and given a value in words, written as the member, or as JSON.
	{kindEnvelope, regexp.MustCompile("`v`\\s*\\(?\\s*(?:=|is not|is|MUST be|must be)\\s*`?(\\d+)")},
	{kindEnvelope, regexp.MustCompile(`\bv: ?(\d+)\b`)},
	{kindEnvelope, regexp.MustCompile(`"v": ?(\d+)`)},
	{kindExport, regexp.MustCompile("hdtp_export[`\"]?\\s*(?::|=|is)\\s*[`\"]?(\\d+)")},
	{kindInfo, regexp.MustCompile(`\b(HDTP-SEAL-v\d+)\b`)},
	{kindVaultFmt, regexp.MustCompile(`\b(hdtp-vault/\d+)\b`)},
	{kindDerivation, regexp.MustCompile(`\b(hdtp/[a-z-]+/\d+)\b`)},
	// A number given to a `Protocol` field. The code has no such field (held below), so a sentence
	// that gives it a number describes a generation flag that is gone.
	{kindProtocol, regexp.MustCompile("`(?:Client)?Protocol\\b`?(?:\\s+(?:field|number))?[^.;`]{0,80}?(?:==|!=|=|:|\\bis\\b|\\bsaid\\b|\\bsaying\\b|\\bsays\\b|\\bset to\\b)\\s*`?\"?(\\d+)\\b")},
	{kindProtocol, regexp.MustCompile(`\b(?:Client)?Protocol (?:is|was|==) (\d+)\b`)},
}

// vaultContext is what makes a `v` the vault plaintext's and not an envelope's: the line it is
// on, or the one before it, names the vault or its plaintext.
var vaultContext = regexp.MustCompile(`(?i)vault|plaintext`)

// statedIn reads every statement out of one text.
func statedIn(file, text string) []statement {
	lines := strings.Split(text, "\n")
	lineAt := func(offset int) int { return 1 + strings.Count(text[:offset], "\n") }
	var out []statement
	seen := map[string]bool{}
	for _, form := range statedForms {
		for _, m := range form.re.FindAllStringSubmatchIndex(text, -1) {
			value := strings.TrimRight(text[m[2]:m[3]], ".")
			line := lineAt(m[2])
			kind := form.kind
			if kind == kindEnvelope {
				here := lines[line-1]
				before := ""
				if line >= 2 {
					before = lines[line-2]
				}
				if vaultContext.MatchString(here) || vaultContext.MatchString(before) {
					kind = kindVaultPlain
				}
			}
			// Two forms can read one sentence ("`v: N`" is the member form inside the words form).
			key := fmt.Sprintf("%s|%d|%d", kind, line, m[2])
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, statement{kind: kind, value: value, file: file, line: line})
		}
	}
	return out
}

// goComments is a Go file's comments and nothing else, each on the line it stands on, so that a
// statement found in it is reported where it is.
func goComments(t *testing.T, path string, src []byte) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	lines := make([]string, bytes.Count(src, []byte("\n"))+2)
	for _, group := range f.Comments {
		for _, c := range group.List {
			start := fset.Position(c.Pos()).Line
			for i, l := range strings.Split(c.Text, "\n") {
				l = strings.TrimSpace(l)
				l = strings.TrimPrefix(l, "//")
				l = strings.TrimPrefix(l, "/*")
				l = strings.TrimSuffix(l, "*/")
				if at := start - 1 + i; at < len(lines) {
					lines[at] += strings.TrimSpace(l)
				}
			}
		}
	}
	return strings.Join(lines, "\n")
}

// statedSources is what is read: path (from the repository's root) to the text statements are
// looked for in. The counts are how many documents and how many Go files were read.
func statedSources(t *testing.T, root string) (texts map[string]string, docs, goFiles int) {
	t.Helper()
	texts = map[string]string{}
	rootDocs, err := filepath.Glob(filepath.Join(root, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rootDocs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		texts[filepath.Base(p)] = string(b)
		docs++
	}
	err = filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.IndexByte(b, 0) >= 0 {
			return nil // an image
		}
		rel, _ := filepath.Rel(root, p)
		texts[filepath.ToSlash(rel)] = string(b)
		docs++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"cmd", "internal", "harness", "migrations", "web"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "dist", "target", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			texts[filepath.ToSlash(rel)] = goComments(t, p, b)
			goFiles++
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return texts, docs, goFiles
}

// wireVersions is what the code writes, read off the things it writes.
func wireVersions(t *testing.T) map[string]string {
	t.Helper()
	now := time.Now().UTC()
	out := map[string]string{
		kindVaultPlain: strconv.Itoa(hdtpidentity.PlaintextV),
		kindInfo:       hdtpidentity.Info,
		kindVaultFmt:   hdtpidentity.VaultFormat,
	}

	// The card an identity serves.
	card, w, h := testid.Card(t, "P", "https://p.example/mcp", "required")
	m := regexp.MustCompile(`(?m)^X-HDTP-VERSION:([^\r\n]+)\r?$`).FindStringSubmatch(card)
	if m == nil {
		t.Fatalf("a built card carries no X-HDTP-VERSION line:\n%s", card)
	}
	out[kindCard] = m[1]

	// The header of an envelope the library seals.
	to := w.Issue(t, "https://q.example/mcp")
	env, err := hdtpidentity.SealRequest(hdtpidentity.SealOpts{
		RecipientKey: to.Key.Public(), Sender: h.Key, Form: "chain", SenderChain: h.Chain,
		MsgID: "stated-versions", TS: now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := hdtpidentity.DecodeB64url(env.Protected)
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		V json.Number `json:"v"`
	}
	if err := json.Unmarshal(header, &head); err != nil || head.V == "" {
		t.Fatalf("a sealed envelope's header carries no `v`: %s (%v)", header, err)
	}
	out[kindEnvelope] = head.V.String()

	// The manifest of an export the library writes.
	var file bytes.Buffer
	if _, err := hdtpidentity.WriteExportZip(&file, hdtpidentity.ExportInput{Owner: w.Fpr, OwnerName: "P", Tool: "stated-versions", ExportedAt: now}, nil); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(file.Bytes()), int64(file.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range zr.File {
		if member.Name != "manifest.json" {
			continue
		}
		rc, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Export json.Number `json:"hdtp_export"`
		}
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		out[kindExport] = manifest.Export.String()
	}
	if out[kindExport] == "" {
		t.Fatal("a written export carries no manifest.json with `hdtp_export`")
	}
	return out
}

// derivationHolds reports whether a derivation label is one the library derives with: one of its
// HKDF infos, or the label whose SHA-256 is the PRF salt.
func derivationHolds(label string) bool {
	for _, info := range hdtpidentity.DerivationInfos {
		if label == info {
			return true
		}
	}
	sum := sha256.Sum256([]byte(label))
	return bytes.Equal(sum[:], hdtpidentity.PrfSalt())
}

// wrong is every statement that does not say what the code writes, as a sentence each.
func wrong(found []statement, wire map[string]string) []string {
	var out []string
	for _, s := range found {
		where := s.file + ":" + strconv.Itoa(s.line)
		switch s.kind {
		case kindDerivation:
			if !derivationHolds(s.value) {
				out = append(out, fmt.Sprintf("%s: names the derivation label %q, which the library does not derive with", where, s.value))
			}
		case kindProtocol:
			out = append(out, fmt.Sprintf("%s: gives %s as %s; the code has no such field", where, s.kind, s.value))
		default:
			if want := wire[s.kind]; s.value != want {
				out = append(out, fmt.Sprintf("%s: states %s as %s; the code writes %s", where, s.kind, s.value, want))
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestEveryStatedWireVersionIsTheOneTheCodeWrites(t *testing.T) {
	root := repoRoot(t)
	wire := wireVersions(t)
	texts, docs, goFiles := statedSources(t, root)
	// A reader that read nothing finds nothing wrong. Both floors are far below today's counts.
	if docs < 10 || goFiles < 300 {
		t.Fatalf("read %d documents and %d Go files: the walk is broken, not the tree", docs, goFiles)
	}
	var found []statement
	for file, text := range texts {
		found = append(found, statedIn(file, text)...)
	}
	// And a reader whose patterns stopped matching finds nothing wrong either: the kinds this
	// repository is known to state, each with a floor below what it states today.
	count := map[string]int{}
	for _, s := range found {
		count[s.kind]++
	}
	for kind, floor := range map[string]int{kindCard: 2, kindEnvelope: 5, kindExport: 1, kindInfo: 1} {
		if count[kind] < floor {
			t.Errorf("found %d statement(s) of %s, fewer than %d: the reader is broken, or the documents stopped saying it", count[kind], kind, floor)
		}
	}
	if bad := wrong(found, wire); len(bad) > 0 {
		t.Errorf("%d sentence(s) state a version the code does not write. Correct the sentence; the code is what the wire carries.\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}

	// The `Protocol` statements are refused because the code has no such field. If it gains one,
	// this is where that is noticed, and its statements are then held to it.
	for file := range texts {
		if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, file), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if field, ok := n.(*ast.Field); ok {
				for _, name := range field.Names {
					if name.Name == "Protocol" || name.Name == "ClientProtocol" {
						t.Errorf("%s declares a field named %s: hold its statements to it here", fset.Position(name.Pos()), name.Name)
					}
				}
			}
			return true
		})
	}
}

// The reader itself: each form is found with its kind and its value, and a Go string is not read.
func TestTheStatedVersionReaderFindsEachForm(t *testing.T) {
	const prose = "a card is `X-HDTP-VERSION:7` plus that leaf\n" +
		"| `X-HDTP-VERSION` | constant `8` |\n" +
		"Version string // X-HDTP-VERSION as carried; MUST be \"9\"\n" +
		"The header carries `v` (= 4), `suite`, `kid`\n" +
		"a `v: 5` envelope is decided by the library\n" +
		"{\"cty\":\"application/hdtp-call+json\",\"v\":6}\n" +
		"`manifest.json` (the format, `hdtp_export: 3`; the owner)\n" +
		"`info = \"HDTP-SEAL-v9\"`, AAD = the raw bytes\n" +
		"not an hdtp-vault/9 document\n" +
		"the vault file { v: 2, roots: [] }\n" +
		"fixed salt `SHA-256(\"hdtp/vault/9\")`, and the info `hdtp/root/9`\n" +
		"a `ClientProtocol` field used to sit beside them saying 2 exactly\n" +
		"there used to be a `Protocol` field\nbeside these that said 2 exactly when they were filled\n" +
		"it was asked as `Protocol == 2`\n" +
		"Protocol is 2 for such an envelope\n"
	got := map[string][]string{}
	for _, s := range statedIn("prose", prose) {
		got[s.kind] = append(got[s.kind], s.value)
	}
	for kind, want := range map[string][]string{
		kindCard:       {"7", "8", "9"},
		kindEnvelope:   {"4", "5", "6"},
		kindExport:     {"3"},
		kindInfo:       {"HDTP-SEAL-v9"},
		kindVaultFmt:   {"hdtp-vault/9"},
		kindVaultPlain: {"2"},
		kindDerivation: {"hdtp/vault/9", "hdtp/root/9"},
		kindProtocol:   {"2", "2", "2", "2"},
	} {
		sort.Strings(got[kind])
		sort.Strings(want)
		if strings.Join(got[kind], ",") != strings.Join(want, ",") {
			t.Errorf("%s: read %v, want %v", kind, got[kind], want)
		}
	}
	// Every one of those is wrong against any real value, and is reported.
	wire := map[string]string{kindCard: "1", kindEnvelope: "1", kindVaultPlain: "1", kindExport: "1", kindInfo: "HDTP-SEAL-v1", kindVaultFmt: "hdtp-vault/1"}
	if bad := wrong(statedIn("prose", prose), wire); len(bad) != 16 {
		t.Errorf("reported %d of the 16 wrong statements:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	// A sentence that names a thing and gives it no number states nothing.
	for _, silent := range []string{
		"the card carries no X-HDTP-VERSION",
		"asked of a `Protocol` number that had come to stand for it.",
		"negotiated ProtocolVersion: 2025",
		"the envelope's `v`, `suite` and `kid` (HDTP §13.1)",
	} {
		if s := statedIn("prose", silent); len(s) != 0 {
			t.Errorf("%q: read as %+v, and it states no version", silent, s)
		}
	}

	// A Go file is read for its comments only: the string is a value a test feeds in.
	src := []byte("package p\n\n// An envelope is `v: 4`.\nconst wrongOnPurpose = \"X-HDTP-VERSION:9\" // the property, with a value this node refuses\n")
	stated := statedIn("p.go", goComments(t, "p.go", src))
	if len(stated) != 1 || stated[0].kind != kindEnvelope || stated[0].value != "4" || stated[0].line != 3 {
		t.Errorf("a Go file's comments were read as %+v; want the one statement of line 3, and the string left alone", stated)
	}
}
