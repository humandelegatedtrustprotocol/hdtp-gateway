package cli

// `export` and `import` (SPEC §3.10, HDTP §9.2): one identity's contacts, chats and files out of
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
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/portable"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/auditsink"
)

// exportNotice is HDTP §9.2's words to the person, said before the file is written, on every
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
	accountID, owner := "", ""
	if a, err := st.GetAccountBySlug(ctx, slug); err == nil {
		accountID, owner = a.ID, a.RootFingerprint
	}
	// Said before the file is written (design §4.5), on every surface that writes one.
	fmt.Fprintln(stdout, exportNotice)
	// O_EXCL: an export never replaces a file. 0600: it is somebody's address book and mail.
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	now := time.Now()
	res, err := portable.Export(ctx, st, messaging.BlobDir{Root: cfg.Blobs()}, f, slug, "hdtp-gateway "+version, now)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	// The file is read back as an importer reads it before it is reported: a file every importer
	// refuses is not an export, and is removed rather than left behind with a zero exit.
	var warnings []string
	if err == nil {
		err = checkWritten(out, owner, now, &warnings)
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
	auditFn("account_export", fmt.Sprintf("account:%s contacts:%d removed:%d threads:%d messages:%d media:%d left_out:%s", accountID, res.Contacts, res.Removed, res.Threads, res.Messages, res.Media, strings.Join(res.LeftOutMessages, ",")), "ok")
	fmt.Fprintf(stdout, "exported %s to %s: %s\n", slug, out, countsLine(res))
	for _, s := range res.LeftOut {
		fmt.Fprintf(stdout, "left out: %s\n", s)
	}
	// Over what BatonDeck takes back in: written all the same (another host may take it), and said.
	for _, w := range warnings {
		fmt.Fprintf(stdout, "warning: %s: BatonDeck's import would refuse this file; another host may take it\n", w)
	}
	return 0
}

// checkWritten reads the file just written back through the importer's check (portable.CheckWritten)
// and names each of BatonDeck's import ceilings it is over.
func checkWritten(path, owner string, now time.Time, warnings *[]string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("%w: the file written does not open as a zip, so it was not kept: %v", portable.ErrRefused, err)
	}
	defer zr.Close()
	if err := portable.CheckWritten(&zr.Reader, owner, now); err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	var size uint64
	if n := fi.Size(); n > 0 {
		size = uint64(n)
	}
	*warnings = portable.CloudCeilings(&zr.Reader, size)
	return nil
}

// importCmd is `import FILE.zip -slug S [-yes]`. Without -yes it reads and checks the whole file,
// shows what it would write, and writes nothing (HDTP §9.2's import step 2: the person reviews the
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
	// HDTP §9.2's step 1: the person sees the contacts, and nothing is written until they agree.
	// The review is printed on EVERY run, -yes or not, before anything is written; -yes is the
	// agreement only because the review it agrees to is on the screen above it, in the same run.
	review(stdout, plan)
	if !yes {
		fmt.Fprintf(stdout, "nothing was written. If this is what you expect, run it again with -yes\n")
		return 0
	}
	now := time.Now()
	res, err := plan.Apply(ctx, st, messaging.BlobDir{Root: cfg.Blobs()}, now, cfg.ContactCap())
	if err != nil {
		// A failure after the rows committed (a file that could not be written) names the account
		// the import made; one before names what was there, if anything.
		if plan.AccountID != "" {
			accountID = plan.AccountID
		}
		auditFn("account_import", "account:"+accountID+" slug:"+slug, "error")
		fmt.Fprintln(stderr, "import:", err)
		return 1
	}
	auditFn("account_import", fmt.Sprintf("account:%s contacts:%d removed:%d pins_filled:%d threads:%d messages:%d media:%d already:%d new:%t",
		plan.AccountID, res.Contacts, res.Removed, res.PinsFilled, res.Threads, res.Messages, res.Media, res.AlreadyHere, plan.New), "ok")
	fmt.Fprintf(stdout, "imported %s into %s: %s", from, slug, countsLine(res))
	if res.PinsFilled > 0 {
		fmt.Fprintf(stdout, "; %d held contact(s) given the file's pin", res.PinsFilled)
	}
	if res.AlreadyHere > 0 {
		fmt.Fprintf(stdout, "; %d already here, left as they were", res.AlreadyHere)
	}
	fmt.Fprintln(stdout)
	if plan.New {
		fmt.Fprintf(stdout, "not served yet: %s holds its root and no key.\n", slug)
	}
	return nextLeaf(ctx, cfg, st, auditFn, plan, stdout, stderr)
}

// nextLeaf is how every import ends (HDTP §9.2 step 4, SPEC §3.10): with a request for a new leaf
// for the importing endpoint, minted here — `move` for an identity new to this host, `renew` for
// one it already serves — which the person completes in their wallet. Installing that leaf sends
// every imported contact this host's handshake. The request goes through the same service
// `account csr` uses (leafService.Mint), audited account_csr.
func nextLeaf(ctx context.Context, cfg *core.Config, st store.Store, auditFn func(action, resource, outcome string), plan *portable.Plan, stdout, stderr io.Writer) int {
	purpose, endpoint := identity.PurposeMove, identity.EndpointFor(cfg.PublicURL, plan.Slug)
	acct, err := st.GetAccountByID(ctx, plan.AccountID)
	if err != nil {
		fmt.Fprintln(stderr, "import: the identity is imported and could not be read back:", err)
		return 1
	}
	if !plan.New {
		purpose = identity.PurposeRenew
		// A renewal names the address the identity answers at now: its current leaf's.
		if leaves, lerr := st.ListLeaves(ctx, acct.ID); lerr == nil {
			for _, l := range leaves {
				if l.State == identity.LeafCurrent && l.Endpoint != "" {
					endpoint = l.Endpoint
				}
			}
		}
	}
	by := func(why string) int {
		fmt.Fprintf(stdout, "next: a new leaf from the wallet. %s Then: `hdtp-gateway account csr -slug %s -purpose %s`, have the wallet sign it, and `hdtp-gateway account install-leaf -slug %s -chain <file>`. Installing it sends every imported contact this host's handshake\n", why, plan.Slug, purpose, plan.Slug)
		return 0
	}
	if endpoint == "" {
		return by("This node has no public URL yet, so there is no address to ask a leaf for: set public_url.")
	}
	kr, err := openKeyringFor(cfg)
	if err != nil {
		return by("The request could not be made here (" + err.Error() + ").")
	}
	leaves := leafService{idm: &identity.Manager{Store: st, Keyring: kr}, audit: auditFn, endpointFor: func(string) string { return endpoint }}
	csr, err := leaves.Mint(ctx, acct, purpose, endpoint, "")
	if err != nil {
		return by("The request could not be made here (" + err.Error() + ").")
	}
	for _, w := range csr.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w.Text)
	}
	fmt.Fprintf(stdout, "next: a request for a new leaf is waiting: %s at %s, key %s, under root %s. Complete it in your wallet:\n", csr.Purpose, csr.Endpoint, csr.Kid, acct.RootFingerprint)
	fmt.Fprintf(stdout, "  - the web wallet: start the node, sign in to its portal and open /identity/%s/wallet (the page asks your wallet for this leaf, replacing this request with one it can send);\n", plan.Slug)
	fmt.Fprintf(stdout, "  - the CLI wallet: sign the request below (`hdtp id issue`), then `hdtp-gateway account install-leaf -slug %s -chain <file>`.\n", plan.Slug)
	fmt.Fprintf(stdout, "Installing the leaf sends every imported contact this host's handshake.\n")
	fmt.Fprint(stdout, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.CSR})))
	return 0
}

// review is what the person sees before anything is written: every contact the file would write,
// what this identity already holds and keeps, the requests it leaves undecided, and where the file
// disagrees with it.
func review(w io.Writer, p *portable.Plan) {
	if p.New {
		fmt.Fprintf(w, "a new identity %s, root %s (%q)\n", p.Slug, p.Owner, p.OwnerName)
	} else {
		fmt.Fprintf(w, "into %s, root %s, which is already here\n", p.Slug, p.Owner)
	}
	fill := map[string]bool{}
	for _, root := range p.Fill {
		fill[root] = true
	}
	for _, c := range p.Write {
		if fill[c.Root] {
			fmt.Fprintf(w, "  fill  %s, held here with no leaf: the file's pin at %s fills it\n", c.Root, c.Endpoint)
			continue
		}
		pin := "pinned by its root only: its leaf did not travel or did not validate"
		if c.Leaf != nil {
			pin = "pinned at " + c.Endpoint
		}
		fmt.Fprintf(w, "  write %s %q (%q), %s, %s\n", c.Root, c.DisplayName, c.Name, c.Status, pin)
	}
	for _, root := range p.Keep {
		fmt.Fprintf(w, "  keep  %s as this host holds it\n", root)
	}
	for _, root := range p.Skip {
		fmt.Fprintf(w, "  skip  %s: a request from them this host holds and nobody has decided; the file does not decide it\n", root)
	}
	for _, c := range p.Conflicts {
		fmt.Fprintf(w, "  the file says %s's %s is %v; this host's %v stands\n", c.Root, c.Field, c.Row, c.Held)
	}
	// HDTP §9.2 step 1: each former contact, by its root and the names its removed threads carry. It
	// is never a contact here.
	for _, r := range p.Removed {
		fmt.Fprintf(w, "  removed %s %q (%q): a former contact's conversation, never written as a contact\n", r.Root, r.DisplayName, r.Name)
	}
	fmt.Fprintf(w, "and %d thread(s), %d message(s), %d file(s)\n", len(p.Contents.Threads), len(p.Contents.Messages), len(p.Contents.Media))
}

func countsLine(r portable.Result) string {
	return fmt.Sprintf("%d contact(s), %d removed contact(s), %d thread(s), %d message(s), %d file(s)", r.Contacts, r.Removed, r.Threads, r.Messages, r.Media)
}
