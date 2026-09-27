package cli

// `export` and `import` (SPEC §3.10, PACT §9.2): one identity's contacts, chats and files out of
// one host and into another, as one unencrypted zip, and nothing else. internal/portable is the
// format and says why; this is the two verbs. Both are offline and reachable only from a shell on
// the host: never the portal, never the owner MCP.
//
// They replace `backup create` and `backup restore`, and the change of name is the point. That
// command copied the whole database — settings, credentials, the audit chain, and (until
// 2026-09-19) every leaf's private key — beside the master key that unsealed them, and called the
// result a backup. What leaves a host now is not a copy of the host, so it is not called one.

import (
	"archive/zip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/portable"
	"github.com/pact-cloud/pact-gateway/internal/services/auditsink"
)

// exportNotice is PACT §9.2's words to the person, said before the file is written, on every
// surface that writes one (design §4.5). The cloud's portal, /v1 and MCP say the same.
const exportNotice = "This file is not encrypted. Anyone who gets it can read your contact list and all your conversations and files. It holds no keys, so it cannot be used to speak as you. Keep it where you keep private documents, and delete it once it has been imported."

// portableStore opens what both verbs need: the config, the data directory's lock (both are
// offline — a consistent read and an atomic write want the node stopped), and a migrated store.
//
// The verb's own arguments are checked BEFORE any of that, by check. A verb typed without them
// should cost nothing, and the documentation lint runs every command bare: the first draft made
// the default data directory and migrated a store in it before saying `-out is required`.
func portableStore(name string, args []string, stderr io.Writer, define func(*flag.FlagSet), check func(fs *flag.FlagSet) string) (*core.Config, store.Store, func(), int) {
	var cfgPath string
	fs := commonFlags(name, &cfgPath, stderr)
	define(fs)
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, 2
	}
	if why := check(fs); why != "" {
		fmt.Fprintf(stderr, "%s: %s\n", name, why)
		return nil, nil, nil, 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, name+":", err)
		return nil, nil, nil, 1
	}
	// An import onto a fresh machine has no data directory yet, and the lock lives in it.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintln(stderr, name+":", err)
		return nil, nil, nil, 1
	}
	lock, err := core.AcquireLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, name+":", err)
		return nil, nil, nil, 1
	}
	st, err := openStore(cfg)
	if err == nil {
		err = st.Migrate(context.Background())
	}
	if err != nil {
		lock.Release()
		fmt.Fprintln(stderr, name+":", err)
		return nil, nil, nil, 1
	}
	return cfg, st, func() { st.Close(); lock.Release() }, 0
}

// exportCmd is `export -slug S -out FILE.zip`: one identity, since an export names one owner.
func exportCmd(args []string, version string, stdout, stderr io.Writer) int {
	var slug, out string
	cfg, st, done, code := portableStore("export", args, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&slug, "slug", "", "the identity to export")
		fs.StringVar(&out, "out", "", "the file to write; it must not exist")
	}, func(*flag.FlagSet) string {
		switch {
		case slug == "":
			return "-slug is required"
		case out == "":
			return "-out is required"
		}
		return ""
	})
	if code != 0 {
		return code
	}
	defer done()
	ctx := context.Background()
	auditFn := auditsink.New(ctx, st, io.Discard).Owner()
	accountID := ""
	if a, err := st.GetAccountBySlug(ctx, slug); err == nil {
		accountID = a.ID
	}
	// Said before the file is written (design §4.5), on every surface that writes one.
	fmt.Fprintln(stdout, exportNotice)
	// O_EXCL: an export never replaces a file. 0600: it is somebody's address book and mail.
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	res, err := portable.Export(ctx, st, messaging.BlobDir{Root: filepath.Join(cfg.DataDir, "blobs")}, f, slug, "pact-gateway "+version, time.Now())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		outcome := "error"
		if errors.Is(err, portable.ErrRefused) {
			outcome = "refused"
		}
		auditFn("account_export", "account:"+accountID+" slug:"+slug, outcome)
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	auditFn("account_export", fmt.Sprintf("account:%s contacts:%d threads:%d messages:%d media:%d", accountID, res.Contacts, res.Threads, res.Messages, res.Media), "ok")
	fmt.Fprintf(stdout, "exported %s to %s: %s\n", slug, out, countsLine(res))
	for _, s := range res.LeftOut {
		fmt.Fprintf(stdout, "left out: %s\n", s)
	}
	return 0
}

// importCmd is `import FILE.zip -slug S [-yes]`. Without -yes it reads and checks the whole file,
// shows what it would write, and writes nothing (PACT §9.2's import step 2: the person reviews the
// contacts before they are written). With -yes it writes.
func importCmd(args []string, stdout, stderr io.Writer) int {
	// The file comes first, as it is typed; the flag package stops at the first argument that is
	// not a flag, so it is taken off before the flags are read.
	var from string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		from, args = args[0], args[1:]
	}
	var slug string
	var yes bool
	cfg, st, done, code := portableStore("import", args, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&slug, "slug", "", "the identity to import into: a new one, or the one the file belongs to")
		fs.BoolVar(&yes, "yes", false, "write what the review shows")
	}, func(fs *flag.FlagSet) string {
		if from == "" && fs.NArg() > 0 {
			from = fs.Arg(0)
		}
		switch {
		case from == "":
			return "the export to read is required: import FILE.zip -slug S"
		case slug == "":
			return "-slug is required"
		}
		return ""
	})
	if code != 0 {
		return code
	}
	defer done()
	ctx := context.Background()
	auditFn := auditsink.New(ctx, st, io.Discard).Owner()
	accountID := ""
	if a, err := st.GetAccountBySlug(ctx, slug); err == nil {
		accountID = a.ID
	}
	refused := func(err error) int {
		outcome := "error"
		if errors.Is(err, portable.ErrRefused) {
			outcome = "refused"
		}
		auditFn("account_import", "account:"+accountID+" slug:"+slug, outcome)
		fmt.Fprintln(stderr, "import:", err)
		fmt.Fprintln(stderr, "nothing was written")
		return 1
	}
	zr, err := zip.OpenReader(from)
	if errors.Is(err, zip.ErrInsecurePath) && zr != nil {
		err = nil // a name that climbs out: the core refuses it by its own rule
	}
	if err != nil {
		return refused(fmt.Errorf("%w: not a zip file: %v", portable.ErrRefused, err))
	}
	defer zr.Close()
	plan, err := portable.Read(ctx, st, &zr.Reader, slug, time.Now())
	if err != nil {
		return refused(err)
	}
	review(stdout, plan)
	if !yes {
		fmt.Fprintf(stdout, "nothing was written. If this is what you expect, run it again with -yes\n")
		return 0
	}
	res, err := plan.Apply(ctx, st, messaging.BlobDir{Root: filepath.Join(cfg.DataDir, "blobs")}, time.Now())
	if err != nil {
		auditFn("account_import", "account:"+accountID+" slug:"+slug, "error")
		fmt.Fprintln(stderr, "import:", err)
		return 1
	}
	auditFn("account_import", fmt.Sprintf("account:%s contacts:%d threads:%d messages:%d media:%d already:%d new:%t",
		plan.AccountID, res.Contacts, res.Threads, res.Messages, res.Media, res.AlreadyHere, plan.New), "ok")
	fmt.Fprintf(stdout, "imported %s into %s: %s", from, slug, countsLine(res))
	if res.AlreadyHere > 0 {
		fmt.Fprintf(stdout, "; %d already here, left as they were", res.AlreadyHere)
	}
	fmt.Fprintln(stdout)
	// Every import ends with a NEW leaf from the wallet (standing rule 5), and the handshake to the
	// imported contacts goes out when it is installed.
	purpose := "renew"
	if plan.New {
		purpose = "move"
		fmt.Fprintf(stdout, "not served yet: %s holds its root and no key.\n", slug)
	}
	fmt.Fprintf(stdout, "next: a new leaf from the wallet — start the node, run `pact-gateway account csr -slug %s -purpose %s`, have the wallet sign it, then `pact-gateway account install-leaf -slug %s -chain <file>`. Installing it sends every imported contact this host's handshake\n", slug, purpose, slug)
	return 0
}

// review is what the person sees before anything is written: every contact the file would write,
// what this identity already holds and keeps, and where the file disagrees with it.
func review(w io.Writer, p *portable.Plan) {
	if p.New {
		fmt.Fprintf(w, "a new identity %s, root %s (%s)\n", p.Slug, p.Owner, p.OwnerName)
	} else {
		fmt.Fprintf(w, "into %s, root %s, which is already here\n", p.Slug, p.Owner)
	}
	for _, c := range p.Write {
		pin := "pinned by its root only: its leaf did not travel or did not validate"
		if c.Leaf != nil {
			pin = "pinned at " + c.Endpoint
		}
		fmt.Fprintf(w, "  write %s %q (%s), %s, %s\n", c.Root, c.DisplayName, c.Name, c.Status, pin)
	}
	for _, root := range p.Keep {
		fmt.Fprintf(w, "  keep  %s as this host holds it\n", root)
	}
	for _, c := range p.Conflicts {
		fmt.Fprintf(w, "  the file says %s's %s is %v; this host's %v stands\n", c.Root, c.Field, c.Row, c.Held)
	}
	fmt.Fprintf(w, "and %d thread(s), %d message(s), %d file(s)\n", len(p.Contents.Threads), len(p.Contents.Messages), len(p.Contents.Media))
}

func countsLine(r portable.Result) string {
	return fmt.Sprintf("%d contact(s), %d thread(s), %d message(s), %d file(s)", r.Contacts, r.Threads, r.Messages, r.Media)
}
