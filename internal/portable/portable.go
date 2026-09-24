// Package portable is what a person takes with them when they leave a host, and what a host takes
// in when they arrive (SPEC §3.10, PACT §9): their CONTACTS and their CHATS, and nothing else.
//
// "Nothing else" is the whole design, so it is worth saying what is not here and why.
//
//   - No key of any kind. Not the leaf's — a leaf is the person's root entrusting ONE host for one
//     address until one date, and a copy of its key would let whoever held the file speak as that
//     host — and not the node's master key either, which used to ride along and unseal whatever
//     else did.
//   - No settings, no integration credentials, no sessions, tokens or passkeys, no invites, no
//     audit chain, no ledger of leaves. Those belong to the HOST that made them. An invite minted
//     by one host is a promise that host made; a token is a door into that host.
//
// What is left is the identity's name — a slug, a display name, and the root that IS the identity,
// all of it public — so the data has somebody to belong to; the contacts that identity has pinned;
// and the conversations it has had, with the media in them.
//
// It is written THROUGH the Store interface rather than by copying a database, and that is what
// makes the list above true rather than hoped for: the file holds what this package asks the store
// for, so there is no column to forget to blank and no table to forget to drop. The first version
// of this was a snapshot of the whole database with the dangerous columns NULLed afterwards — a
// deny-list, which is a list that is wrong the day somebody adds a table. It also means a node on
// Postgres can export, which it never could: there was no database file to copy.
//
// Every import ends the same way. The identity is here by name, its contacts and conversations are
// here, and it is NOT SERVED until its wallet issues this host a leaf of its own.
package portable

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// Version is bumped when a reader would have to change to keep reading.
const Version = 1

// The members of the archive. Anything else in it is refused.
const (
	memberManifest = "MANIFEST.json"
	memberData     = "data.jsonl"
	memberMedia    = "media/"
)

// What an import will read out of a compressed member before it stops. A gzip stream says nothing
// trustworthy about how large it becomes, so the reader decides. Media is the protocol's own
// bound (PACT §12); the data's is far above any history a person accumulates and far below a disk.
const (
	maxDataBytes  = 16 << 30
	maxMediaBytes = messaging.MaxMediaBytes
)

// The kinds of line in data.jsonl. Anything else is refused.
const (
	KindIdentity = "identity"
	KindContact  = "contact"
	KindThread   = "thread"
	KindMessage  = "message"
	KindMedia    = "media"
)

// Manifest is the archive's first member: what is in it, and the digest of the data that follows,
// so a reader knows what is coming and can tell a truncated file from a whole one.
type Manifest struct {
	PactExport int            `json:"pact_export"`
	CreatedAt  string         `json:"created_at"`
	Tool       string         `json:"tool"`
	Carries    []string       `json:"carries"`
	Counts     map[string]int `json:"counts"`
	DataSHA256 string         `json:"data_sha256"`
}

// Identity names who the rows after it belong to. Root is the identity (PACT §2); everything here
// is public, and a card says as much to anybody who asks.
type Identity struct {
	Kind        string `json:"kind"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Root        string `json:"root"`
	RootCert    string `json:"root_cert"` // base64url DER
}

// Contact is one pin and what the owner decided about it. It carries no invite — invites do not
// travel — and no record of which of the old host's leaves the contact had seen.
type Contact struct {
	Kind             string   `json:"kind"`
	Identity         string   `json:"identity"` // the root this contact belongs to
	Fingerprint      string   `json:"fingerprint"`
	Status           string   `json:"status"`
	Preset           string   `json:"preset"`
	Permissions      []string `json:"permissions"`
	TheirPermissions []string `json:"their_permissions"`
	TrustFlag        string   `json:"trust_flag"`
	DisplayName      string   `json:"display_name"`
	Petname          string   `json:"petname"`
	Card             string   `json:"card"`
	CreatedAt        int64    `json:"created_at"`
	PinnedAt         int64    `json:"pinned_at"`
	Endpoint         string   `json:"endpoint"`
	Leaf             string   `json:"leaf"`      // base64url DER
	SPKI             string   `json:"spki"`      // base64url DER
	RootCert         string   `json:"root_cert"` // base64url DER
	// EverActive is whether this relationship was ever active, which is what an unblock on the
	// importing host needs: a contact the owner blocked is restored, a rejected request forgotten
	// (SPEC §9.1). This node always writes it. A producer that does not (the cloud's `leave`,
	// pact-cloud gateway/src/leave/convert.ts) leaves it nil, and the importer reads its pinned_at.
	EverActive *bool `json:"ever_active,omitempty"`
}

// everActiveOf is what an imported contact's ever_active is. Written, it is taken as written. Not
// written, the archive came from the cloud, whose pinned_at is set by activation and by nothing
// else (pact-cloud gateway/src/identity/identity.ts, unblockContact's comment), so a blocked row
// with a pin was a contact the owner blocked. Active is always a contact.
func everActiveOf(v Contact) bool {
	if v.Status == "active" {
		return true
	}
	if v.EverActive != nil {
		return *v.EverActive
	}
	return v.Status == "blocked" && v.PinnedAt != 0
}

// Thread is one conversation.
type Thread struct {
	Kind      string `json:"kind"`
	Identity  string `json:"identity"`
	ID        string `json:"id"`
	Contact   string `json:"contact"`
	Topic     string `json:"topic"`
	CreatedAt int64  `json:"created_at"`
	LastAt    int64  `json:"last_at"`
}

// Message is one message in a thread. The retry schedule of an undelivered one stays behind: it
// is the old host's plan for sending it, and the old host is not the one reading this.
type Message struct {
	Kind      string `json:"kind"`
	Identity  string `json:"identity"`
	ID        string `json:"id"`
	Contact   string `json:"contact"`
	MsgID     string `json:"msg_id"`
	ThreadID  string `json:"thread_id"`
	Direction string `json:"direction"`
	Sender    string `json:"sender"`
	Type      string `json:"type"` // text | media
	Body      string `json:"body"`
	ReplyTo   string `json:"reply_to"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

// Media describes one file a conversation refers to; its bytes are the member media/<hash>.
type Media struct {
	Kind      string `json:"kind"`
	Identity  string `json:"identity"`
	Hash      string `json:"hash"`
	Size      int64  `json:"size"`
	Mime      string `json:"mime"`
	Filename  string `json:"filename"`
	CreatedAt int64  `json:"created_at"`
}

// Result says what an export wrote or an import took in.
type Result struct {
	Counts map[string]int
	// Identities are the slugs carried, in order.
	Identities []string
	// Skipped are accounts an export left out, with why: an account that has never been to a
	// wallet has no root, so it has no name anybody else could know it by and nothing pinned.
	Skipped []string
}

var b64 = base64.RawURLEncoding

/* --------------------------------- export --------------------------------- */

// Export writes every identity this store holds — its name, its contacts, its conversations and
// their media — to w. tool names the writer in the manifest; now dates it.
func Export(ctx context.Context, st store.Store, blobs messaging.BlobDir, w io.Writer, tool string, now time.Time) (Result, error) {
	res := Result{Counts: map[string]int{}}
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	// The rows go to a temporary file first: the manifest is the archive's FIRST member and
	// carries their count and digest, which are not known until they have all been written.
	tmp, err := os.CreateTemp("", "pact-export-*.jsonl")
	if err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	digest := sha256.New()
	lines := bufio.NewWriter(io.MultiWriter(tmp, digest))
	enc := json.NewEncoder(lines)
	enc.SetEscapeHTML(false)
	emit := func(kind string, v any) error {
		res.Counts[kind]++
		return enc.Encode(v)
	}

	type mediaRef struct{ hash string }
	var media []mediaRef
	seenMedia := map[string]bool{}
	for _, a := range accounts {
		if !a.HasRoot() {
			res.Skipped = append(res.Skipped, a.Slug+": it has never been issued a certificate, so it has no root to be known by and nothing pinned")
			continue
		}
		res.Identities = append(res.Identities, a.Slug)
		if err := emit(KindIdentity, Identity{Kind: KindIdentity, Slug: a.Slug, DisplayName: a.DisplayName, Root: a.RootFingerprint, RootCert: b64.EncodeToString(a.RootCert)}); err != nil {
			return res, err
		}
		contacts, err := st.ListContacts(ctx, a.ID)
		if err != nil {
			return res, fmt.Errorf("export: contacts of %s: %w", a.Slug, err)
		}
		for _, c := range contacts {
			everActive := c.EverActive
			if err := emit(KindContact, Contact{
				Kind: KindContact, Identity: a.RootFingerprint, Fingerprint: c.Fingerprint, Status: c.Status,
				Preset: c.Preset, Permissions: orEmpty(c.Permissions), TheirPermissions: orEmpty(c.TheirPermissions),
				TrustFlag: c.TrustFlag, DisplayName: c.DisplayName, Petname: c.Petname, Card: c.Card,
				CreatedAt: c.CreatedAt, PinnedAt: c.PinnedAt, Endpoint: c.Endpoint,
				Leaf: b64.EncodeToString(c.Leaf), SPKI: b64.EncodeToString(c.SPKI), RootCert: b64.EncodeToString(c.RootCert),
				EverActive: &everActive,
			}); err != nil {
				return res, err
			}
		}
		threads, err := st.ListThreadsByAccount(ctx, a.ID)
		if err != nil {
			return res, fmt.Errorf("export: threads of %s: %w", a.Slug, err)
		}
		// Oldest first, so an import that inserts in file order rebuilds the same sequence.
		sort.SliceStable(threads, func(i, j int) bool { return threads[i].CreatedAt < threads[j].CreatedAt })
		for _, t := range threads {
			if err := emit(KindThread, Thread{Kind: KindThread, Identity: a.RootFingerprint, ID: t.ID, Contact: t.ContactFpr, Topic: t.Topic, CreatedAt: t.CreatedAt, LastAt: t.LastAt}); err != nil {
				return res, err
			}
			msgs, err := st.ListMessagesByThread(ctx, a.ID, t.ID)
			if err != nil {
				return res, fmt.Errorf("export: messages of %s: %w", a.Slug, err)
			}
			for _, m := range msgs {
				if err := emit(KindMessage, Message{
					Kind: KindMessage, Identity: a.RootFingerprint, ID: m.ID, Contact: m.ContactFpr, MsgID: m.MsgID,
					ThreadID: m.ThreadID, Direction: m.Direction, Sender: m.Sender, Type: m.Kind, Body: m.Body,
					ReplyTo: m.ReplyTo, Status: m.Status, CreatedAt: m.CreatedAt,
				}); err != nil {
					return res, err
				}
			}
		}
		files, err := st.ListBlobs(ctx, a.ID)
		if err != nil {
			return res, fmt.Errorf("export: media of %s: %w", a.Slug, err)
		}
		for _, f := range files {
			if err := emit(KindMedia, Media{Kind: KindMedia, Identity: a.RootFingerprint, Hash: f.Hash, Size: f.Size, Mime: f.Mime, Filename: f.Filename, CreatedAt: f.CreatedAt}); err != nil {
				return res, err
			}
			if !seenMedia[f.Hash] {
				seenMedia[f.Hash] = true
				media = append(media, mediaRef{hash: f.Hash})
			}
		}
	}
	if err := lines.Flush(); err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return res, fmt.Errorf("export: %w", err)
	}

	man := Manifest{
		PactExport: Version, CreatedAt: now.UTC().Format(time.RFC3339), Tool: tool,
		Carries: []string{KindIdentity, KindContact, KindThread, KindMessage, KindMedia},
		Counts:  res.Counts, DataSHA256: hex.EncodeToString(digest.Sum(nil)),
	}
	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return res, err
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	add := func(name string, size int64, r io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: now}); err != nil {
			return err
		}
		_, err := io.Copy(tw, r)
		return err
	}
	if err := add(memberManifest, int64(len(mb)), bytes.NewReader(mb)); err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	if err := add(memberData, size, tmp); err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	for _, m := range media {
		data, err := blobs.Get(m.hash)
		if err != nil {
			return res, fmt.Errorf("export: media %s is on record and not on disk: %w", m.hash, err)
		}
		if err := add(memberMedia+m.hash, int64(len(data)), bytes.NewReader(data)); err != nil {
			return res, fmt.Errorf("export: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	if err := gz.Close(); err != nil {
		return res, fmt.Errorf("export: %w", err)
	}
	return res, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

/* --------------------------------- import --------------------------------- */

// ErrRefused marks an archive this host will not take: it is not an export, it is a newer one than
// this reader knows, it carries something an export does not carry, or it names an identity that
// is already here.
var ErrRefused = errors.New("import refused")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// Import takes an export in. All of it lands or none of it does: the rows go in under one
// transaction, and the media is written only after that transaction has committed.
//
// It is strict on purpose, and the strictness is the importer's half of "nothing else": a member
// it does not know, a kind of line it does not know, or a FIELD it does not know is a refusal, not
// something skipped. PACT §9 has an importing host refuse key material; a reader that ignores what
// it does not recognise cannot promise that, because it never looked.
//
// An identity that is already on this node — by slug or by root — is refused before anything is
// written. Importing creates an identity; it does not merge into one.
func Import(ctx context.Context, st store.Store, blobs messaging.BlobDir, r io.Reader) (Result, error) {
	res := Result{Counts: map[string]int{}}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return res, refuse("not a PACT export (gzip): %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	// Pass 1: the members, in order, into a scratch directory. Nothing touches the store yet.
	scratch, err := os.MkdirTemp("", "pact-import-*")
	if err != nil {
		return res, fmt.Errorf("import: %w", err)
	}
	defer os.RemoveAll(scratch)
	var man *Manifest
	var haveData bool
	mediaSeen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, refuse("the archive is damaged: %v", err)
		}
		name := path.Clean(h.Name)
		switch {
		case name == memberManifest && man == nil && !haveData:
			var m Manifest
			dec := json.NewDecoder(io.LimitReader(tr, 1<<20))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&m); err != nil {
				return res, refuse("the manifest does not read: %v", err)
			}
			if m.PactExport != Version {
				return res, refuse("this is export format %d and this node reads %d", m.PactExport, Version)
			}
			man = &m
		case name == memberData && man != nil && !haveData:
			f, err := os.OpenFile(filepath.Join(scratch, memberData), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
			if err != nil {
				return res, fmt.Errorf("import: %w", err)
			}
			digest := sha256.New()
			n, cerr := io.Copy(io.MultiWriter(f, digest), io.LimitReader(tr, maxDataBytes+1))
			if err := errors.Join(cerr, f.Close()); err != nil {
				return res, fmt.Errorf("import: %w", err)
			}
			if n > maxDataBytes {
				return res, refuse("the data is larger than %d bytes once unpacked", int64(maxDataBytes))
			}
			if got := hex.EncodeToString(digest.Sum(nil)); got != man.DataSHA256 {
				return res, refuse("the data does not match the manifest's digest: the file is truncated or was edited")
			}
			haveData = true
		case strings.HasPrefix(name, memberMedia) && haveData:
			hash := strings.TrimPrefix(name, memberMedia)
			if !isHash(hash) || mediaSeen[hash] {
				return res, refuse("unexpected member %q", h.Name)
			}
			data, err := io.ReadAll(io.LimitReader(tr, maxMediaBytes+1))
			if err != nil {
				return res, refuse("the archive is damaged: %v", err)
			}
			if len(data) > maxMediaBytes {
				return res, refuse("media %s is larger than the %d bytes a message may carry (PACT §12)", hash, maxMediaBytes)
			}
			if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != hash {
				return res, refuse("media %s is not the file its name says it is", hash)
			}
			if err := os.WriteFile(filepath.Join(scratch, hash), data, 0o600); err != nil {
				return res, fmt.Errorf("import: %w", err)
			}
			mediaSeen[hash] = true
		default:
			return res, refuse("unexpected member %q: an export holds a manifest, its data, and the media the data names", h.Name)
		}
	}
	if man == nil || !haveData {
		return res, refuse("not a PACT export: no manifest, or no data")
	}

	// Pass 2: the rows, under one transaction.
	data, err := os.Open(filepath.Join(scratch, memberData))
	if err != nil {
		return res, fmt.Errorf("import: %w", err)
	}
	defer data.Close()
	wantMedia := map[string]bool{}
	err = st.Atomically(ctx, func(tx store.Store) error {
		accountOf := map[string]string{} // root → the local account id
		sc := bufio.NewScanner(data)
		sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
		for n := 1; sc.Scan(); n++ {
			line := sc.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var head struct {
				Kind     string `json:"kind"`
				Identity string `json:"identity"`
			}
			if err := json.Unmarshal(line, &head); err != nil {
				return refuse("line %d does not read: %v", n, err)
			}
			strict := func(v any) error {
				dec := json.NewDecoder(bytes.NewReader(line))
				dec.DisallowUnknownFields()
				if err := dec.Decode(v); err != nil {
					return refuse("line %d (%s): %v", n, head.Kind, err)
				}
				return nil
			}
			owner := func() (string, error) {
				id, ok := accountOf[head.Identity]
				if !ok {
					return "", refuse("line %d (%s) belongs to %q, which no identity line before it names", n, head.Kind, head.Identity)
				}
				return id, nil
			}
			res.Counts[head.Kind]++
			switch head.Kind {
			case KindIdentity:
				var v Identity
				if err := strict(&v); err != nil {
					return err
				}
				id, err := createIdentity(ctx, tx, v)
				if err != nil {
					return err
				}
				accountOf[v.Root] = id
				res.Identities = append(res.Identities, v.Slug)
			case KindContact:
				var v Contact
				if err := strict(&v); err != nil {
					return err
				}
				id, err := owner()
				if err != nil {
					return err
				}
				leaf, e1 := b64.DecodeString(v.Leaf)
				spki, e2 := b64.DecodeString(v.SPKI)
				root, e3 := b64.DecodeString(v.RootCert)
				if err := errors.Join(e1, e2, e3); err != nil {
					return refuse("line %d (contact): %v", n, err)
				}
				// A pin is a root. If the certificate travelled with it, it has to be that root's.
				if len(root) > 0 {
					if got, err := rootFingerprint(root); err != nil || got != v.Fingerprint {
						return refuse("line %d (contact): the root certificate is not the root %s this contact is pinned by", n, v.Fingerprint)
					}
				}
				if err := tx.ImportContact(ctx, store.Contact{
					AccountID: id, Fingerprint: v.Fingerprint, SPKI: spki, Status: v.Status, Preset: v.Preset,
					Permissions: v.Permissions, TheirPermissions: v.TheirPermissions, TrustFlag: v.TrustFlag,
					DisplayName: v.DisplayName, Petname: v.Petname, Card: v.Card, CreatedAt: v.CreatedAt,
					PinnedAt: v.PinnedAt, Endpoint: v.Endpoint, Leaf: leaf, RootCert: root,
					EverActive: everActiveOf(v),
				}); err != nil {
					return fmt.Errorf("import: line %d (contact): %w", n, err)
				}
			case KindThread:
				var v Thread
				if err := strict(&v); err != nil {
					return err
				}
				id, err := owner()
				if err != nil {
					return err
				}
				if err := tx.InsertThread(ctx, store.Thread{ID: v.ID, AccountID: id, ContactFpr: v.Contact, Topic: v.Topic, CreatedAt: v.CreatedAt, LastAt: v.LastAt}); err != nil {
					return fmt.Errorf("import: line %d (thread): %w", n, err)
				}
			case KindMessage:
				var v Message
				if err := strict(&v); err != nil {
					return err
				}
				id, err := owner()
				if err != nil {
					return err
				}
				// An undelivered message was the OLD host's to deliver, under the old host's leaf.
				// This host has not been asked to send it, so it does not inherit the queue: it
				// keeps the message and records that it was never delivered.
				status := v.Status
				if status == "pending" {
					status = "failed"
				}
				if err := tx.InsertMessage(ctx, store.Message{
					ID: v.ID, AccountID: id, ContactFpr: v.Contact, MsgID: v.MsgID, ThreadID: v.ThreadID,
					Direction: v.Direction, Sender: v.Sender, Kind: v.Type, Body: v.Body, ReplyTo: v.ReplyTo,
					Status: status, CreatedAt: v.CreatedAt,
				}); err != nil {
					return fmt.Errorf("import: line %d (message): %w", n, err)
				}
			case KindMedia:
				var v Media
				if err := strict(&v); err != nil {
					return err
				}
				id, err := owner()
				if err != nil {
					return err
				}
				if !mediaSeen[v.Hash] {
					return refuse("line %d names media %s, which is not in the archive", n, v.Hash)
				}
				wantMedia[v.Hash] = true
				if err := tx.InsertBlob(ctx, store.Blob{AccountID: id, Hash: v.Hash, Size: v.Size, Mime: v.Mime, Filename: v.Filename, CreatedAt: v.CreatedAt}); err != nil {
					return fmt.Errorf("import: line %d (media): %w", n, err)
				}
			default:
				return refuse("line %d is a %q, which an export does not carry", n, head.Kind)
			}
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("import: %w", err)
		}
		for hash := range mediaSeen {
			if !wantMedia[hash] {
				return refuse("the archive holds media %s that no line names", hash)
			}
		}
		for kind, want := range man.Counts {
			if res.Counts[kind] != want {
				return refuse("the manifest promises %d %s line(s) and the data holds %d", want, kind, res.Counts[kind])
			}
		}
		return nil
	})
	if err != nil {
		return Result{Counts: map[string]int{}}, err
	}

	// The rows are in. The media follows; a file that fails to land leaves a row pointing at
	// nothing, which the message view already treats as "media unavailable", and says so here.
	for hash := range wantMedia {
		data, err := os.ReadFile(filepath.Join(scratch, hash))
		if err != nil {
			return res, fmt.Errorf("import: %w", err)
		}
		if _, err := blobs.Put(data); err != nil {
			return res, fmt.Errorf("import: the rows are in and media %s could not be written: %w", hash, err)
		}
	}
	return res, nil
}

// createIdentity makes the account an imported identity lives in: named, rooted, and KEYLESS. It
// is not served until its wallet issues this host a leaf, and the account's algorithm is only this
// host's default for the key it will generate when asked for a certificate request.
func createIdentity(ctx context.Context, tx store.Store, v Identity) (string, error) {
	if v.Slug == "" || v.Root == "" {
		return "", refuse("an identity line needs a slug and a root")
	}
	rootCert, err := b64.DecodeString(v.RootCert)
	if err != nil || len(rootCert) == 0 {
		return "", refuse("identity %s: its root certificate does not read", v.Slug)
	}
	// The root IS the identity, so the certificate has to be the one the fingerprint names. A
	// file that paired somebody's fingerprint with another certificate would otherwise create
	// an account that claims one root and would present another.
	if got, err := rootFingerprint(rootCert); err != nil || got != v.Root {
		return "", refuse("identity %s: its root certificate is not the root %s it names", v.Slug, v.Root)
	}
	accounts, err := tx.ListAccounts(ctx)
	if err != nil {
		return "", fmt.Errorf("import: %w", err)
	}
	for _, a := range accounts {
		if a.Slug == v.Slug {
			return "", refuse("an identity called %q is already on this node; importing creates an identity, it does not merge into one", v.Slug)
		}
		if a.RootFingerprint == v.Root {
			return "", refuse("the identity %s is already on this node, as %q", v.Root, a.Slug)
		}
	}
	a, err := tx.CreateAccount(ctx, store.CreateAccountParams{Slug: v.Slug, DisplayName: v.DisplayName, Algo: string(identity.AlgoP256)})
	if err != nil {
		return "", fmt.Errorf("import: identity %s: %w", v.Slug, err)
	}
	if err := tx.SetAccountRoot(ctx, a.ID, v.Root, rootCert); err != nil {
		return "", fmt.Errorf("import: identity %s: %w", v.Slug, err)
	}
	if err := identity.GrantToAllOwners(ctx, tx, a.ID); err != nil {
		return "", fmt.Errorf("import: identity %s: %w", v.Slug, err)
	}
	return a.ID, nil
}

// rootFingerprint is the fingerprint of the key a certificate certifies: what PACT calls the root.
func rootFingerprint(der []byte) (string, error) {
	cert, err := pactidentity.Parse(der)
	if err != nil {
		return "", err
	}
	return pactidentity.Fingerprint(cert.SPKI), nil
}

func isHash(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
