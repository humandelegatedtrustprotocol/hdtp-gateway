package cli

// `export` and `import` (SPEC §3.10, PACT §9): a person's contacts and chats out of one host and
// into another, and nothing else. internal/portable is the format and says why; this is the two
// verbs.
//
// They replace `backup create` and `backup restore`, and the change of name is the point. That
// command copied the whole database — settings, credentials, the audit chain, and (until
// 2026-09-19) every leaf's private key — beside the master key that unsealed them, and called the
// result a backup. What leaves a host now is not a copy of the host, so it is not called one.

import (
	"context"
	"errors"
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
)

// portableStore opens what both verbs need: the config, the data directory's lock (both are
// offline — a consistent read and an atomic write want the node stopped), and a migrated store.
//
// The file flag is checked BEFORE any of that. A verb typed without it should cost nothing, and
// the documentation lint runs every command bare: the first draft made the default data directory
// and migrated a store in it before saying `-out is required`.
func portableStore(name string, args []string, stderr io.Writer, fileFlag, fileUsage string, file *string) (*core.Config, store.Store, func(), int) {
	var cfgPath string
	fs := commonFlags(name, &cfgPath, stderr)
	fs.StringVar(file, fileFlag, "", fileUsage)
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, 2
	}
	if *file == "" {
		fmt.Fprintf(stderr, "%s: -%s is required\n", name, fileFlag)
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

func exportCmd(args []string, version string, stdout, stderr io.Writer) int {
	var out string
	cfg, st, done, code := portableStore("export", args, stderr, "out", "the file to write; it must not exist", &out)
	if code != 0 {
		return code
	}
	defer done()
	// O_EXCL: an export never replaces a file. 0600: it is somebody's address book and mail.
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	res, err := portable.Export(context.Background(), st, messaging.BlobDir{Root: filepath.Join(cfg.DataDir, "blobs")}, f, "pact-gateway "+version, time.Now())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	fmt.Fprintf(stdout, "exported %s: %s\n", out, countsLine(res.Counts))
	for _, s := range res.Skipped {
		fmt.Fprintf(stdout, "left out: %s\n", s)
	}
	fmt.Fprintln(stdout, "it carries contacts and chats and nothing else: no key, no settings, no credentials. Wherever it is imported, each identity is issued a NEW certificate by its wallet before it is served")
	return 0
}

func importCmd(args []string, stdout, stderr io.Writer) int {
	var from string
	cfg, st, done, code := portableStore("import", args, stderr, "from", "the export to read", &from)
	if code != 0 {
		return code
	}
	defer done()
	f, err := os.Open(from)
	if err != nil {
		fmt.Fprintln(stderr, "import:", err)
		return 1
	}
	defer f.Close()
	res, err := portable.Import(context.Background(), st, messaging.BlobDir{Root: filepath.Join(cfg.DataDir, "blobs")}, f)
	if err != nil {
		fmt.Fprintln(stderr, "import:", err)
		if errors.Is(err, portable.ErrRefused) {
			fmt.Fprintln(stderr, "nothing was written")
		}
		return 1
	}
	fmt.Fprintf(stdout, "imported %s: %s\n", from, countsLine(res.Counts))
	fmt.Fprintf(stdout, "not served yet: %s. No export carries a key, so each needs a certificate from its wallet for THIS host — start the node, and `serve` names the request to make for each\n", strings.Join(res.Identities, ", "))
	return 0
}

func countsLine(counts map[string]int) string {
	order := []string{portable.KindIdentity, portable.KindContact, portable.KindThread, portable.KindMessage, portable.KindMedia}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], plural(k, counts[k])))
	}
	return strings.Join(parts, ", ")
}

func plural(kind string, n int) string {
	if n == 1 {
		return kind
	}
	switch kind {
	case portable.KindIdentity:
		return "identities"
	case portable.KindMedia:
		return "media files"
	}
	return kind + "s"
}
