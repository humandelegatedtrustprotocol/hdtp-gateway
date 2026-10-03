package portable

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Conflict is one place where a file disagrees with a pin this identity already holds. The held
// pin stands (HDTP §14.5); the conflict is shown so the person knows.
type Conflict struct {
	Root  string `json:"root"`
	Field string `json:"field"`
	Held  any    `json:"held"`
	Row   any    `json:"row"`
}

// Plan is a whole export read and checked, and merged against what this identity already holds,
// with nothing written. Read makes it; the person reviews it (HDTP §9.2's import step 2); Apply
// writes it.
type Plan struct {
	Slug      string
	Owner     string
	OwnerName string
	// New says the import creates the identity, keyless, holding only its root.
	New bool
	// AccountID is the identity the rows go into; empty until Apply when New.
	AccountID string
	Contents  *hdtpidentity.ExportContents
	// Write are the contacts Apply writes: every row not held, and every row held with no leaf
	// that the file gives one. Fill names the second kind: held here, with no leaf, and the file's
	// pin fills it. Keep are the roots held already, left as they are. Skip are the roots of file
	// rows this host holds as a stranger's request (aRequest): not a contact, so not merged, and
	// left as they are.
	Write     []hdtpidentity.ContactRow
	Fill      []string
	Keep      []string
	Skip      []string
	Conflicts []Conflict
	zr        *zip.Reader
}

// Read checks a whole export for the identity called slug (HDTP §9.2) and writes nothing.
//
//   - A slug that is not here will be created keyless, holding only the root the file names as
//     its owner; the wallet's first leaf must be under that root (identity.InstallLeaf).
//   - A slug that is here must be that same root, and the file's contacts are merged with the
//     ones it holds: a pin this host holds is never replaced by one from a file.
//   - A root that is here under ANOTHER slug is refused: one identity, one slug on a host.
//   - A slug reserved after an identity left this node (HDTP §9) is refused here, in the review,
//     and not first by the write.
//   - Into a slug that is here, a file thread whose id this identity already holds for another
//     contact is refused: thread ids are the account's own, and the file's messages would be
//     written into the other contact's conversation.
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
		// The store refuses the account too (CreateAccount); this says so before the review, not
		// after the person has agreed to it. It does not say whose the address was: it may be this
		// very identity, returning.
		if reserved, err := st.LiveVacatedSlug(ctx, slug, now.Unix()); err != nil {
			return nil, fmt.Errorf("import: %w", err)
		} else if reserved {
			return nil, refuse("%q is reserved: an identity left this node from that address, and a leaf issued for it has not yet expired; choose another slug", slug)
		}
	}
	// What is read into memory is bounded before it is read (ImportMessagesCeiling).
	for _, f := range zr.File {
		if f.Name == "messages.jsonl" && f.UncompressedSize64 > ImportMessagesCeiling {
			return nil, refuse("messages.jsonl: %d bytes, over the %d this host reads into memory for one import", f.UncompressedSize64, ImportMessagesCeiling)
		}
	}
	// An existing slug's own root is what the file must be (the core's owner rule, in its words).
	p.Contents, err = hdtpidentity.ReadExportZip(zr, p.Owner, now, ImportCeiling)
	if err != nil {
		return nil, refuse("%v", err)
	}
	if p.New {
		// The one rule every door holds a display name to (identity.ValidDisplayName): the new
		// account takes this as its name, and a name is one line of its card.
		p.OwnerName = ownerName(zr)
		if err := identity.ValidDisplayName(p.OwnerName); err != nil {
			return nil, refuse("manifest.json: owner_name: %v", err)
		}
	}
	held := []hdtpidentity.ContactRow{}
	heldRoots, requests := map[string]bool{}, map[string]bool{}
	if !p.New {
		cs, err := st.ListContacts(ctx, p.AccountID)
		if err != nil {
			return nil, fmt.Errorf("import: %w", err)
		}
		for _, c := range cs {
			// A request is not a contact, so export_merge is not handed one. It was, and it kept the
			// request and reported every field the file said otherwise as a conflict, where the
			// cloud skips it (batondeck portable.ts).
			if aRequest(c) {
				requests[c.Fingerprint] = true
				continue
			}
			held = append(held, contactRow(c))
			heldRoots[c.Fingerprint] = true
		}
		for _, t := range p.Contents.Threads {
			if err := threadFits(ctx, st, p.AccountID, t); err != nil {
				return nil, err
			}
		}
	}
	if err := merge(held, p.Contents.Contacts, p); err != nil {
		return nil, err
	}
	// Unheld, a request's root comes back from export_merge as a row to write: it is skipped here,
	// or Apply would write a contact over the request (ImportContactPin refuses a row that holds a
	// leaf, and the import would fail).
	write := p.Write[:0]
	for _, r := range p.Write {
		switch {
		case requests[r.Root]:
			p.Skip = append(p.Skip, r.Root)
			continue
		case heldRoots[r.Root]:
			p.Fill = append(p.Fill, r.Root)
		}
		write = append(write, r)
	}
	p.Write = write
	return p, nil
}

// threadFits refuses a file thread whose id this identity already holds for another contact.
func threadFits(ctx context.Context, st store.Store, accountID string, t hdtpidentity.ThreadRow) error {
	h, err := st.GetThread(ctx, accountID, t.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("import: thread %s: %w", t.ID, err)
	}
	if h.ContactFpr != t.Contact {
		return refuse("thread %s: this identity already holds a conversation of that id with %s, and the file's is with %s; it cannot be merged into it", t.ID, h.ContactFpr, t.Contact)
	}
	return nil
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
		return json.NewDecoder(io.LimitReader(rc, hdtpidentity.ExportManifestMax)).Decode(v) == nil
	}
	return false
}

// merge is export_merge (HDTP §9.2's import step 2).
func merge(held, rows []hdtpidentity.ContactRow, p *Plan) error {
	in, err := json.Marshal(map[string]any{"held": held, "rows": rows})
	if err != nil {
		return err
	}
	var out struct {
		Write     []hdtpidentity.ContactRow `json:"write"`
		Keep      []string                  `json:"keep"`
		Conflicts []Conflict                `json:"conflicts"`
		Error     string                    `json:"error"`
		Why       string                    `json:"why"`
	}
	if err := json.Unmarshal(hdtpidentity.Call("export_merge", in), &out); err != nil {
		return fmt.Errorf("import: export_merge: %w", err)
	}
	if out.Error != "" {
		return refuse("%s", out.Why)
	}
	p.Write, p.Keep, p.Conflicts = out.Write, out.Keep, out.Conflicts
	return nil
}

// Apply writes a plan: the rows under one transaction, then the files. Every contact written is
// owed this host's handshake from `now` (HDTP §9.2), which the campaign of the identity's next leaf
// — the first one requested after the import — sends.
//
// contactCap is how many contacts the identity may hold (limit.contacts): the import is refused,
// with nothing written, when what it leaves held is over the cap AND it added to the count. An
// identity already over it (the cap lowered since) may still re-import what it holds. As the cloud
// holds its import (batondeck src/identity/identity.ts, checkContactCap).
func (p *Plan) Apply(ctx context.Context, st store.Store, blobs messaging.BlobDir, now time.Time, contactCap int) (Result, error) {
	var res Result
	newFiles := map[string]bool{} // by hash: whether this import wrote the file's record
	err := st.Atomically(ctx, func(tx store.Store) error {
		res = Result{}
		clear(newFiles)
		accountID := p.AccountID
		if p.New {
			a, err := tx.CreateAccount(ctx, store.CreateAccountParams{Slug: p.Slug, DisplayName: p.OwnerName, Algo: string(identity.AlgoP256)})
			if errors.Is(err, store.ErrAddressVacated) {
				// An identity left this node from that address, and a leaf issued for it is still
				// live (HDTP §9): the store's one guard, said as a refusal of this import.
				return refuse("%q is reserved: an identity left this node from that address, and a leaf issued for it has not yet expired; choose another slug", p.Slug)
			}
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
		before, err := tx.CountHeldContacts(ctx, accountID)
		if err != nil {
			return fmt.Errorf("import: %w", err)
		}
		for _, r := range p.Write {
			c, err := storeContact(accountID, r)
			if err != nil {
				return err
			}
			c.HandshakeDueAt = now.Unix()
			if _, gerr := tx.GetContact(ctx, accountID, r.Root); gerr == nil {
				// Held with no leaf (export_merge wrote it only so): the file's pin fills it.
				wrote, err := tx.ImportContactPin(ctx, c)
				if err != nil {
					return fmt.Errorf("import: contact %s: %w", r.Root, err)
				}
				if !wrote {
					return fmt.Errorf("import: contact %s gained a leaf while the file was read", r.Root)
				}
				res.PinsFilled++
				continue
			}
			if err := tx.ImportContact(ctx, c); err != nil {
				return fmt.Errorf("import: contact %s: %w", r.Root, err)
			}
			res.Contacts++
		}
		after, err := tx.CountHeldContacts(ctx, accountID)
		if err != nil {
			return fmt.Errorf("import: %w", err)
		}
		if after > int64(contactCap) && after > before {
			return fmt.Errorf("%w: %w", ErrRefused, core.ContactCapRefusal(after, contactCap))
		}
		for _, t := range p.Contents.Threads {
			wrote, err := tx.ImportThread(ctx, store.Thread{ID: t.ID, AccountID: accountID, ContactFpr: t.Contact, Topic: t.Topic, CreatedAt: unixOf(t.CreatedAt), LastAt: unixOf(t.LastAt)})
			if err != nil {
				return fmt.Errorf("import: thread %s: %w", t.ID, err)
			}
			if !wrote {
				// Here already: the same conversation, or another contact's under that id (checked
				// by the review too; again here, in the transaction that writes).
				if err := threadFits(ctx, tx, accountID, t); err != nil {
					return err
				}
			}
			res.count(&res.Threads, wrote)
		}
		for _, m := range p.Contents.Messages {
			sm, blob := storeMessage(accountID, m)
			if blob != nil {
				wrote, err := tx.ImportBlob(ctx, *blob)
				if err != nil {
					return fmt.Errorf("import: file %s: %w", blob.Hash, err)
				}
				newFiles[blob.Hash] = newFiles[blob.Hash] || wrote
			}
			wrote, err := tx.ImportMessage(ctx, sm)
			if err != nil {
				return fmt.Errorf("import: message %s: %w", m.ID, err)
			}
			if !wrote {
				// A message's id is unique on the node and its msg_id per contact and direction:
				// "already here" is THIS message, in this conversation, and nothing else is.
				h, gerr := tx.GetMessageByMsgID(ctx, accountID, sm.ContactFpr, sm.Direction, sm.MsgID)
				if gerr != nil || h.ID != sm.ID || h.ThreadID != sm.ThreadID {
					return refuse("message %s: its id, or its msg_id with that contact, is another message's on this node", m.ID)
				}
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
		res.count(&res.Media, newFiles[m.Hash])
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
		b, err := io.ReadAll(io.LimitReader(rc, hdtpidentity.ExportMediaMax+1))
		if err != nil {
			return nil, fmt.Errorf("import: media/%s: %w", hash, err)
		}
		return b, nil
	}
	return nil, errors.New("import: media/" + hash + " is gone from the file")
}

// storeContact is a contacts.csv row as the store holds it. A row whose leaf export_read kept
// (it validated at the row's endpoint) pins that leaf and its key; any other pins the root alone.
func storeContact(accountID string, r hdtpidentity.ContactRow) (store.Contact, error) {
	c := store.Contact{
		AccountID: accountID, Fingerprint: r.Root, Status: r.Status, Permissions: r.Permissions,
		TheirPermissions: r.TheirPermissions, TrustFlag: "messages_only", DisplayName: r.DisplayName,
		Petname: r.Name, CreatedAt: unixOf(r.Added), Endpoint: r.Endpoint, EverActive: r.WasActive,
	}
	if r.RootCert != nil {
		der, err := hdtpidentity.DecodeB64url(*r.RootCert)
		if err != nil {
			return c, refuse("contacts.csv: %s: its root_cert is not base64url", r.Root)
		}
		c.RootCert = der
	}
	if r.Leaf != nil {
		der, err := hdtpidentity.DecodeB64url(*r.Leaf)
		if err != nil {
			return c, refuse("contacts.csv: %s: its leaf is not base64url", r.Root)
		}
		c.Leaf = der
		cert, err := hdtpidentity.Parse(c.Leaf)
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
// has not been asked to, so it arrives failed, with no retry schedule. An inbound message reached
// the host that exported it, whatever the file says of it (a message that was waiting for its
// human travels `queued`), and arrives delivered.
func storeMessage(accountID string, m hdtpidentity.MessageRow) (store.Message, *store.Blob) {
	status := "delivered"
	switch {
	case m.Direction == "in":
	case m.Status == "queued", m.Status == "failed":
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
