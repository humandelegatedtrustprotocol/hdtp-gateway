package portable

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// Conflict is one place where a file disagrees with a pin this identity already holds. The held
// pin stands (PACT §14.5); the conflict is shown so the person knows.
type Conflict struct {
	Root  string `json:"root"`
	Field string `json:"field"`
	Held  any    `json:"held"`
	Row   any    `json:"row"`
}

// Plan is a whole export read and checked, and merged against what this identity already holds,
// with nothing written. Read makes it; the person reviews it (PACT §9.2's import step 2); Apply
// writes it.
type Plan struct {
	Slug      string
	Owner     string
	OwnerName string
	// New says the import creates the identity, keyless, holding only its root.
	New bool
	// AccountID is the identity the rows go into; empty until Apply when New.
	AccountID string
	Contents  *pactidentity.ExportContents
	// Write are the contacts Apply writes: every row not held, and every row held with no leaf
	// that the file gives one. Keep are the roots held already, left as they are.
	Write     []pactidentity.ContactRow
	Keep      []string
	Conflicts []Conflict
	zr        *zip.Reader
}

// Read checks a whole export for the identity called slug (PACT §9.2) and writes nothing.
//
//   - A slug that is not here will be created keyless, holding only the root the file names as
//     its owner; the wallet's first leaf must be under that root (identity.InstallLeaf).
//   - A slug that is here must be that same root, and the file's contacts are merged with the
//     ones it holds: a pin this host holds is never replaced by one from a file.
//   - A root that is here under ANOTHER slug is refused: one identity, one slug on a host.
func Read(ctx context.Context, st store.Store, zr *zip.Reader, slug string, now time.Time) (*Plan, error) {
	p := &Plan{Slug: slug, New: true, zr: zr}
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("import: %w", err)
	}
	for _, a := range accounts {
		if a.Slug == slug {
			p.New, p.AccountID, p.Owner = false, a.ID, a.RootFingerprint
		}
	}
	if !p.New && p.Owner == "" {
		return nil, refuse("%s has never been issued a certificate, so no file can be its", slug)
	}
	if p.New {
		// A new slug takes the root the file names; the core checks every row against it.
		if p.Owner, err = manifestOwner(zr); err != nil {
			return nil, err
		}
		for _, a := range accounts {
			if a.RootFingerprint == p.Owner {
				return nil, refuse("the identity %s is already on this node as %q; import into that slug", p.Owner, a.Slug)
			}
		}
	}
	// An existing slug's own root is what the file must be (the core's owner rule, in its words).
	p.Contents, err = pactidentity.ReadExportZip(zr, p.Owner, now, ImportCeiling)
	if err != nil {
		return nil, refuse("%v", err)
	}
	if p.New {
		p.OwnerName = ownerName(zr)
	}
	held := []pactidentity.ContactRow{}
	if !p.New {
		cs, err := st.ListContacts(ctx, p.AccountID)
		if err != nil {
			return nil, fmt.Errorf("import: %w", err)
		}
		for _, c := range cs {
			held = append(held, contactRow(c))
		}
	}
	if err := merge(held, p.Contents.Contacts, p); err != nil {
		return nil, err
	}
	return p, nil
}

// manifestOwner reads whose a file says it is, for a slug that is not here yet: the one thing read
// before the core, because it decides which identity the rows are checked against.
func manifestOwner(zr *zip.Reader) (string, error) {
	var head struct {
		Owner string `json:"owner"`
	}
	if !readManifest(zr, &head) || head.Owner == "" {
		return "", refuse("manifest.json: names no owner this host can read")
	}
	return head.Owner, nil
}

// ownerName is the name a validated manifest gives its owner.
func ownerName(zr *zip.Reader) string {
	var head struct {
		OwnerName string `json:"owner_name"`
	}
	readManifest(zr, &head)
	return head.OwnerName
}

func readManifest(zr *zip.Reader, v any) bool {
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		defer rc.Close()
		return json.NewDecoder(io.LimitReader(rc, pactidentity.ExportManifestMax)).Decode(v) == nil
	}
	return false
}

// merge is export_merge (PACT §9.2's import step 2).
func merge(held, rows []pactidentity.ContactRow, p *Plan) error {
	in, err := json.Marshal(map[string]any{"held": held, "rows": rows})
	if err != nil {
		return err
	}
	var out struct {
		Write     []pactidentity.ContactRow `json:"write"`
		Keep      []string                  `json:"keep"`
		Conflicts []Conflict                `json:"conflicts"`
		Error     string                    `json:"error"`
		Why       string                    `json:"why"`
	}
	if err := json.Unmarshal(pactidentity.Call("export_merge", in), &out); err != nil {
		return fmt.Errorf("import: export_merge: %w", err)
	}
	if out.Error != "" {
		return refuse("%s", out.Why)
	}
	p.Write, p.Keep, p.Conflicts = out.Write, out.Keep, out.Conflicts
	return nil
}

// Apply writes a plan: the rows under one transaction, then the files. Every contact written is
// owed this host's handshake (PACT §9.2), which the campaign after the identity's next leaf sends.
func (p *Plan) Apply(ctx context.Context, st store.Store, blobs messaging.BlobDir) (Result, error) {
	var res Result
	err := st.Atomically(ctx, func(tx store.Store) error {
		res = Result{}
		accountID := p.AccountID
		if p.New {
			a, err := tx.CreateAccount(ctx, store.CreateAccountParams{Slug: p.Slug, DisplayName: p.OwnerName, Algo: string(identity.AlgoP256)})
			if err != nil {
				return fmt.Errorf("import: %w", err)
			}
			// Its root's fingerprint and nothing more: the certificate comes with the first chain.
			if err := tx.SetAccountRoot(ctx, a.ID, p.Owner, nil); err != nil {
				return fmt.Errorf("import: %w", err)
			}
			if err := identity.GrantToAllOwners(ctx, tx, a.ID); err != nil {
				return fmt.Errorf("import: %w", err)
			}
			accountID = a.ID
		}
		for _, r := range p.Write {
			c, err := storeContact(accountID, r)
			if err != nil {
				return err
			}
			if _, gerr := tx.GetContact(ctx, accountID, r.Root); gerr == nil {
				// Held with no leaf (export_merge wrote it only so): the file's pin fills it.
				wrote, err := tx.ImportContactPin(ctx, c)
				if err != nil {
					return fmt.Errorf("import: contact %s: %w", r.Root, err)
				}
				if !wrote {
					return fmt.Errorf("import: contact %s gained a leaf while the file was read", r.Root)
				}
			} else if err := tx.ImportContact(ctx, c); err != nil {
				return fmt.Errorf("import: contact %s: %w", r.Root, err)
			}
			res.Contacts++
		}
		for _, t := range p.Contents.Threads {
			wrote, err := tx.ImportThread(ctx, store.Thread{ID: t.ID, AccountID: accountID, ContactFpr: t.Contact, Topic: t.Topic, CreatedAt: unixOf(t.CreatedAt), LastAt: unixOf(t.LastAt)})
			if err != nil {
				return fmt.Errorf("import: thread %s: %w", t.ID, err)
			}
			res.count(&res.Threads, wrote)
		}
		for _, m := range p.Contents.Messages {
			sm, blob := storeMessage(accountID, m)
			if blob != nil {
				if _, err := tx.ImportBlob(ctx, *blob); err != nil {
					return fmt.Errorf("import: file %s: %w", blob.Hash, err)
				}
			}
			wrote, err := tx.ImportMessage(ctx, sm)
			if err != nil {
				return fmt.Errorf("import: message %s: %w", m.ID, err)
			}
			res.count(&res.Messages, wrote)
		}
		p.AccountID = accountID
		return nil
	})
	if err != nil {
		if p.New {
			p.AccountID = ""
		}
		return Result{}, err
	}
	// The rows are in; the files follow. ReadExportZip checked each one's bytes; they are read
	// again from the zip, and a file whose bytes are not its name now is not written.
	for _, m := range p.Contents.Media {
		data, err := mediaBytes(p.zr, m.Hash)
		if err != nil {
			return res, err
		}
		got, err := blobs.Put(data)
		if err != nil {
			return res, fmt.Errorf("import: the rows are in and file %s could not be written: %w", m.Hash, err)
		}
		if got != m.Hash {
			return res, fmt.Errorf("import: the rows are in and file %s changed since it was checked", m.Hash)
		}
		res.Media++
	}
	return res, nil
}

func (r *Result) count(n *int, wrote bool) {
	if wrote {
		*n++
	} else {
		r.AlreadyHere++
	}
}

func mediaBytes(zr *zip.Reader, hash string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name != "media/"+hash {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("import: media/%s: %w", hash, err)
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, pactidentity.ExportMediaMax+1))
		if err != nil {
			return nil, fmt.Errorf("import: media/%s: %w", hash, err)
		}
		return b, nil
	}
	return nil, errors.New("import: media/" + hash + " is gone from the file")
}

// storeContact is a contacts.csv row as the store holds it. A row whose leaf export_read kept
// (it validated at the row's endpoint) pins that leaf and its key; any other pins the root alone.
func storeContact(accountID string, r pactidentity.ContactRow) (store.Contact, error) {
	c := store.Contact{
		AccountID: accountID, Fingerprint: r.Root, Status: r.Status, Permissions: r.Permissions,
		TheirPermissions: r.TheirPermissions, TrustFlag: "messages_only", DisplayName: r.DisplayName,
		Petname: r.Name, CreatedAt: unixOf(r.Added), Endpoint: r.Endpoint, EverActive: r.WasActive,
	}
	if r.RootCert != nil {
		c.RootCert = pactidentity.FromB64url(*r.RootCert)
	}
	if r.Leaf != nil {
		c.Leaf = pactidentity.FromB64url(*r.Leaf)
		cert, err := pactidentity.Parse(c.Leaf)
		if err != nil {
			return c, refuse("contacts.csv: %s: its leaf does not parse", r.Root)
		}
		c.SPKI = cert.SPKI
		if c.Status == "active" || c.Status == "blocked" || c.Status == "pending_out" {
			c.PinnedAt = unixOf(r.Added)
		}
	}
	return c, nil
}

// storeMessage is a messages.jsonl line as the store holds it, with the file row it needs. An
// undelivered outbound message was the old host's to deliver, under the old host's leaf; this host
// has not been asked to, so it arrives failed, with no retry schedule.
func storeMessage(accountID string, m pactidentity.MessageRow) (store.Message, *store.Blob) {
	status := "delivered"
	switch m.Status {
	case "queued", "failed":
		status = "failed"
	}
	out := store.Message{
		ID: m.ID, AccountID: accountID, ContactFpr: m.Contact, MsgID: m.MsgID, ThreadID: m.Thread,
		Direction: m.Direction, Sender: m.Sender, Kind: "text", Body: m.Body, Status: status, CreatedAt: unixOf(m.Time),
	}
	if m.ReplyTo != nil {
		out.ReplyTo = *m.ReplyTo
	}
	if len(m.Attachments) == 0 {
		return out, nil
	}
	a := m.Attachments[0] // the format carries at most one, as send_media does
	meta, _ := json.Marshal(messaging.MediaMeta{Filename: a.Filename, Mime: a.MIME, Hash: a.File, Size: a.Size})
	out.Kind, out.Body = "media", string(meta)
	return out, &store.Blob{AccountID: accountID, Hash: a.File, Size: a.Size, Mime: a.MIME, Filename: a.Filename, CreatedAt: out.CreatedAt}
}

func unixOf(s string) int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0
	}
	return t.Unix()
}
