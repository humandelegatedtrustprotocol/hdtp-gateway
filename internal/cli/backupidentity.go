package cli

// `backup identity` / `backup restore-identity` (SPEC §3.10): one account's
// keypair, portable to a different node.
//
// Offline and host-shell-only, deliberately. The portal and the owner MCP do not
// get this: §8.6 keeps a leaked bearer token from minting a login credential, and
// the same reasoning keeps a session or a token from exfiltrating the identity
// that credential protects. Host shell access is already the recovery root of
// trust (§3.1), so this grants no authority that access did not already have.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

const passphraseEnv = "PACT_IDENTITY_PASSPHRASE"

// readPassphrase resolves the passphrase the way the keyring resolves its master
// key (SPEC §12.2): environment variable, then a 0600 file. A passphrase file
// readable by anyone else is refused for the same reason the master key file is —
// the secret is only as good as the thing holding it.
func readPassphrase(file string, lookup func(string) (string, bool)) (string, error) {
	if v, ok := lookup(passphraseEnv); ok && v != "" {
		return v, nil
	}
	if file == "" {
		return "", fmt.Errorf("no passphrase: set %s or pass -passphrase-file", passphraseEnv)
	}
	fi, err := os.Stat(file)
	if err != nil {
		return "", fmt.Errorf("passphrase file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("passphrase file %s is mode %o; require 0600", file, fi.Mode().Perm())
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("passphrase file: %w", err)
	}
	p := strings.TrimRight(string(b), "\r\n")
	if p == "" {
		return "", fmt.Errorf("passphrase file %s is empty", file)
	}
	return p, nil
}

// exportIdentity writes one account's keypair as a passphrase-sealed document.
func exportIdentity(cfg *core.Config, slug, out, passFile string, stdout, stderr io.Writer) int {
	if slug == "" || out == "" {
		fmt.Fprintln(stderr, "backup identity: -slug and -out are required")
		return 2
	}
	pass, err := readPassphrase(passFile, os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "backup identity:", err)
		return 1
	}
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "backup identity:", err)
		return 1
	}
	defer st.Close()
	kr, err := openKeyringFor(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "backup identity:", err)
		return 1
	}
	ctx := context.Background()
	a, err := st.GetAccountBySlug(ctx, slug)
	if err != nil {
		fmt.Fprintf(stderr, "backup identity: no account with slug %q\n", slug)
		return 1
	}
	sealed, err := st.GetAccountSealedKey(ctx, a.ID)
	if err != nil || len(sealed) == 0 {
		fmt.Fprintf(stderr, "backup identity: account %q has no key to back up\n", slug)
		return 1
	}
	idm := &identity.Manager{Store: st, Keyring: kr}
	kp, err := idm.LoadKeypair(sealed)
	if err != nil {
		fmt.Fprintln(stderr, "backup identity: could not open the stored key:", err)
		return 1
	}
	doc, err := identity.ExportIdentity(kp, a.Slug, a.DisplayName, a.Algo, pass)
	if err != nil {
		fmt.Fprintln(stderr, "backup identity:", err)
		return 1
	}
	raw, err := identity.MarshalBackup(doc)
	if err != nil {
		fmt.Fprintln(stderr, "backup identity:", err)
		return 1
	}
	// 0600 from the start: never widen, never write it readable and fix it after.
	if err := os.WriteFile(out, append(raw, '\n'), 0o600); err != nil {
		fmt.Fprintln(stderr, "backup identity:", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s\n", out)
	fmt.Fprintf(stdout, "  identity %s (%s)\n  %s\n", a.DisplayName, a.Slug, kp.Fingerprint)
	fmt.Fprintln(stdout, "This file IS that identity. Anyone who opens it can be this person to every")
	fmt.Fprintln(stdout, "contact who pinned the key. It is only as safe as the passphrase and the place")
	fmt.Fprintln(stdout, "you keep it; there is no way to revoke it once it leaves.")
	return 0
}

// restoreIdentity brings a backed-up keypair onto this node.
func restoreIdentity(cfg *core.Config, from, passFile string, stdout, stderr io.Writer) int {
	if from == "" {
		fmt.Fprintln(stderr, "backup restore-identity: -from is required")
		return 2
	}
	pass, err := readPassphrase(passFile, os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "backup restore-identity:", err)
		return 1
	}
	raw, err := os.ReadFile(from)
	if err != nil {
		fmt.Fprintln(stderr, "backup restore-identity:", err)
		return 1
	}
	var doc identity.IdentityBackup
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintln(stderr, "backup restore-identity: that file is not an identity backup:", err)
		return 1
	}
	kp, err := identity.OpenIdentity(doc, pass)
	if err != nil {
		fmt.Fprintln(stderr, "backup restore-identity:", err)
		return 1
	}
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "backup restore-identity:", err)
		return 1
	}
	defer st.Close()
	kr, err := openKeyringFor(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "backup restore-identity:", err)
		return 1
	}
	ctx := context.Background()
	// Refuse a collision rather than resolve it silently. Either name landing on
	// something that already exists is the owner's call, not ours.
	if existing, err := st.GetAccountBySlug(ctx, doc.Slug); err == nil {
		fmt.Fprintf(stderr, "backup restore-identity: this node already has an account with slug %q (%s).\n",
			doc.Slug, existing.Fingerprint)
		fmt.Fprintln(stderr, "Remove it or restore onto a node that does not have it.")
		return 1
	}
	accts, err := st.ListAccounts(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "backup restore-identity:", err)
		return 1
	}
	for _, a := range accts {
		if a.Fingerprint == kp.Fingerprint {
			fmt.Fprintf(stderr, "backup restore-identity: this identity is already on this node as %q.\n", a.Slug)
			return 1
		}
	}
	idm := &identity.Manager{Store: st, Keyring: kr}
	a, err := idm.ImportAccount(ctx, doc.Slug, doc.DisplayName, identity.Algo(doc.Algo), kp)
	if err != nil {
		fmt.Fprintln(stderr, "backup restore-identity:", err)
		return 1
	}
	fmt.Fprintf(stdout, "restored %s (%s)\n  %s\n", a.DisplayName, a.Slug, a.Fingerprint)
	fmt.Fprintln(stdout, "The keypair is back. Contacts, threads and media are NOT — they were the other")
	fmt.Fprintln(stdout, "node's record of its relationships. Peers who pinned this key still reach you;")
	fmt.Fprintln(stdout, "your own view of them starts empty. Set a public URL before sharing your card.")
	return 0
}

func openKeyringFor(cfg *core.Config) (*core.Keyring, error) {
	path := cfg.MasterKeyFile
	if path == "" {
		path = cfg.DataDir + "/keyring.key"
	}
	return core.OpenKeyring(path, os.LookupEnv)
}

var _ = store.Account{}
