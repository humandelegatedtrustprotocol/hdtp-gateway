package messaging

// Media (SPEC §7.4–§7.5): inline data is content-addressed into the blob store
// with per-account quotas; url media is NEVER fetched automatically — fetching is
// an explicit action, size-capped, private-range-blocked against the RESOLVED
// address, and dialed pinned to that vetted address so DNS rebinding cannot swap
// the target between check and connect.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// MaxMediaBytes is the most one inline media item may hold, received, sent or fetched (HDTP 12).
const MaxMediaBytes = 5 << 20 // HDTP §12: media ≤ 5 MiB inline

// ErrQuota is the account's media quota exhausted; it carries the same wire code as ErrTooLarge,
// so errors.Is(err, ErrTooLarge) is false for it and callers match ErrQuota to tell them apart.
var ErrQuota = errors.New("too_large") // quota exhausted maps to the §12 code

// BlobDir stores blob content on disk, content-addressed (SPEC §7.4).
type BlobDir struct{ Root string }

// path maps a content hash to its file. It returns "" for anything that is not a
// lowercase hex SHA-256, and every caller treats "" as absent.
//
// Nothing reaches this with a bad hash today: Put computes it, and the portal
// route looks the blob row up in the store first, so a traversal string fails
// that lookup before it gets here. This is the layer under that. `hash[:2]` also
// panicked outright on a hash shorter than two characters, which made the
// difference between "not found" and "the process is gone" one careless caller
// wide.
func (b BlobDir) path(hash string) string {
	if len(hash) != sha256.Size*2 {
		return ""
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return filepath.Join(b.Root, hash[:2], hash)
}

// Put writes data if absent; returns the hex SHA-256. Existing content dedups.
func (b BlobDir) Put(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	p := b.path(hash)
	if _, err := os.Stat(p); err == nil {
		return hash, nil // dedup
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	return hash, os.Rename(tmp, p)
}

// Get reads the bytes behind a hash; a string that is not a lowercase hex SHA-256 is fs.ErrNotExist.
func (b BlobDir) Get(hash string) ([]byte, error) {
	p := b.path(hash)
	if p == "" {
		return nil, fs.ErrNotExist
	}
	return os.ReadFile(p)
}

// Remove deletes the bytes behind a hash. Retention calls it only once no
// account still references that content (SPEC §7.9); an already-absent file is
// not an error, so a re-run after a partial sweep completes cleanly.
func (b BlobDir) Remove(hash string) error {
	p := b.path(hash)
	if p == "" {
		return nil // nothing that shape was ever stored
	}
	err := os.Remove(p)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// MediaMeta is the messages.body payload for kind=media rows.
type MediaMeta struct {
	Filename string `json:"filename"`
	Mime     string `json:"mime"`
	Hash     string `json:"hash,omitempty"` // set once content is held locally: sent inline, or a URL fetched
	URL      string `json:"url,omitempty"`  // the link a contact sent; kept when the owner fetches it
	Size     int64  `json:"size,omitempty"`
}

// MediaService stores and fetches media for an account under its byte quota. Inline media is
// content-addressed into Blobs and recorded as a kind=media message through a Service; url media
// is recorded without fetching, and FetchMessage is the explicit act that retrieves it.
type MediaService struct {
	Store ConversationStore
	Blobs BlobDir
	// Quota reports this account's current byte allowance. It is a FUNCTION on
	// purpose: the owner can change the quota from the portal at any time, and a
	// value captured when the account was built would make that control do
	// nothing until the next restart. nil falls back to MaxBytes.
	Quota    func() int64
	MaxBytes int64 // fixed per-account quota; 0 = DefaultQuotaBytes
	Now      func() time.Time

	// isPrivate reports whether an address must be refused (SPEC §7.5 ranges);
	// injectable for tests, defaults to the real range list.
	isPrivate func(ip net.IP) bool
	// Audit receives refusals (SPEC §11.5). Three fields, like the chain it
	// feeds: the resource says what was touched, the outcome is the verdict.
	Audit func(action, resource, outcome string)
}

// DefaultQuotaBytes is SPEC §7.4's per-account storage quota: 10 GiB. It is a
// documented default, so it belongs in one named place — the value the code
// enforced and the value the spec promised had drifted apart.
const DefaultQuotaBytes int64 = 10 << 30

func (m *MediaService) quota() int64 {
	if m.Quota != nil {
		if q := m.Quota(); q > 0 {
			return q
		}
	}
	if m.MaxBytes > 0 {
		return m.MaxBytes
	}
	return DefaultQuotaBytes
}

func (m *MediaService) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *MediaService) privateCheck(ip net.IP) bool {
	if m.isPrivate != nil {
		return m.isPrivate(ip)
	}
	return isPrivateAddr(ip)
}

// IsPrivateAddr reports whether an address is in SPEC §7.5's refused range list.
// Exported so the outbound leg can apply the same rule: a contact controls the
// endpoint on their own card, so dialing it is the same class of primitive as
// fetching a URL they sent.
func IsPrivateAddr(ip net.IP) bool { return isPrivateAddr(ip) }

// isPrivateAddr implements the SPEC §7.5 range list: loopback, RFC 1918,
// unique-local, link-local (incl. cloud metadata 169.254.0.0/16), CGNAT.
func isPrivateAddr(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if cgnat := ip.Mask(net.CIDRMask(10, 32)); ip.To4() != nil && cgnat.Equal(net.IPv4(100, 64, 0, 0).Mask(net.CIDRMask(10, 32))) {
		return true
	}
	return false
}

// ReceiveInline stores inline media (send_media with data) as a media message.
func (m *MediaService) ReceiveInline(ctx context.Context, msgSvc *Service, accountID, contactFpr string, in Input, filename, mime string, data []byte) (Result, error) {
	if len(data) == 0 || len(data) > MaxMediaBytes {
		return Result{}, fmt.Errorf("%w: media empty or over 5 MiB", ErrTooLarge)
	}
	used, err := m.Store.SumBlobBytes(ctx, accountID)
	if err != nil {
		return Result{}, err
	}
	if used+int64(len(data)) > m.quota() {
		return Result{}, fmt.Errorf("%w: account media quota exhausted", ErrQuota)
	}
	return m.keepAndRecord(ctx, msgSvc, accountID, contactFpr, DirIn, in, data, mime, filename)
}

// SendInline stores media the OWNER is sending as an outbound media message:
// the bytes go into the blob store under the account's quota, the row is
// recorded pending, and the node delivers it through the peer's `send_media`.
// Same caps as inbound (HDTP §12: ≤ 5 MiB inline) — a node must not accept from
// its owner what it would refuse from a peer.
func (m *MediaService) SendInline(ctx context.Context, msgSvc *Service, accountID, contactFpr string, in Input, filename, mime string, data []byte) (Result, error) {
	if len(data) == 0 || len(data) > MaxMediaBytes {
		return Result{}, fmt.Errorf("%w: media empty or over 5 MiB", ErrTooLarge)
	}
	used, err := m.Store.SumBlobBytes(ctx, accountID)
	if err != nil {
		return Result{}, err
	}
	if used+int64(len(data)) > m.quota() {
		return Result{}, fmt.Errorf("%w: account media quota exhausted", ErrQuota)
	}
	return m.keepAndRecord(ctx, msgSvc, accountID, contactFpr, DirOut, in, data, mime, filename)
}

// ReceiveURL records url media WITHOUT fetching (SPEC §7.5).
func (m *MediaService) ReceiveURL(ctx context.Context, msgSvc *Service, accountID, contactFpr string, in Input, filename, mime, url string) (Result, error) {
	meta, _ := json.Marshal(MediaMeta{Filename: filename, Mime: mime, URL: url})
	in.Text = string(meta)
	return msgSvc.record(ctx, accountID, contactFpr, DirIn, in, "media")
}

// errGone rolls back a fetch whose message went while its link was fetched.
var errGone = errors.New("messaging: the message went")

// FetchMessage is the EXPLICIT owner action for one url media message (SPEC §7.5): it fetches the
// link the message carries and records the file on that message, so the message names its file as
// an inline one does — the conversation view opens it, retention and a deleted conversation collect
// it (Files), the quota counts it, and an export carries it. A message whose file is already held
// answers its hash and fetches nothing. A message the account does not hold is store.ErrNotFound;
// one that is not url media is ErrBadRequest. A message deleted while its file was being fetched is
// store.ErrNotFound, and the file it leaves unnamed goes with the next orphan sweep after FileGrace.
func (m *MediaService) FetchMessage(ctx context.Context, accountID, messageID string) (string, error) {
	msg, err := m.Store.GetMessage(ctx, accountID, messageID)
	if err != nil {
		return "", err
	}
	var meta MediaMeta
	if msg.Kind != "media" || json.Unmarshal([]byte(msg.Body), &meta) != nil || (meta.URL == "" && meta.Hash == "") {
		return "", fmt.Errorf("%w: not a media message with a link", ErrBadRequest)
	}
	if meta.Hash != "" {
		return meta.Hash, nil
	}
	data, mime, err := m.fetchURL(ctx, accountID, meta.URL)
	if err != nil {
		return "", err
	}
	// The file and the message that names it change in one transaction, under the file's lock: a
	// conversation deleted meanwhile leaves neither a record nor bytes that nothing names.
	var hash string
	gone := false
	err = m.Store.Atomically(ctx, func(tx store.Store) error {
		var err error
		if hash, _, err = fileRecord(ctx, tx, accountID, data, mime, "", m.now().Unix()); err != nil {
			return err
		}
		meta.Hash, meta.Size = hash, int64(len(data))
		body, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		n, err := tx.SetMediaBody(ctx, accountID, messageID, string(body))
		if err != nil {
			return err
		}
		if n == 0 {
			// The message went while its link was fetched: the record rolls back with this
			// transaction, and no byte is written.
			gone = true
			return errGone
		}
		_, err = m.Blobs.Put(data)
		return err
	})
	if gone {
		return "", fmt.Errorf("%w: the message went while its file was fetched", store.ErrNotFound)
	}
	if err != nil {
		return "", err
	}
	if gone {
		return "", fmt.Errorf("%w: the message went while its file was fetched", store.ErrNotFound)
	}
	return hash, nil
}

// fetchURL retrieves a link for the owner: resolve, vet every address, pin the dial, cap the read,
// count the quota. It answers the bytes and the type the server named; FetchMessage stores them.
func (m *MediaService) fetchURL(ctx context.Context, accountID, rawURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("bad_request: %w", err)
	}
	host := req.URL.Hostname()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, "", fmt.Errorf("unavailable: cannot resolve %s", host)
	}
	for _, ip := range ips {
		if m.privateCheck(ip) {
			if m.Audit != nil {
				m.Audit("media_fetch_refused", "account:"+accountID+" host:"+host+" ip:"+ip.String(), "denied")
			}
			return nil, "", fmt.Errorf("permission_denied: %s resolves to a private address", host)
		}
	}
	pinned := ips[0].String()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// Pin the connection to the vetted address: rebinding cannot swap it.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort(pinned, port))
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects refused on media fetch") // each hop would need re-vetting
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("unavailable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxMediaBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("unavailable: %w", err)
	}
	if len(data) > MaxMediaBytes {
		return nil, "", fmt.Errorf("%w: fetched media over 5 MiB", ErrTooLarge)
	}
	used, err := m.Store.SumBlobBytes(ctx, accountID)
	if err != nil {
		return nil, "", err
	}
	if used+int64(len(data)) > m.quota() {
		return nil, "", fmt.Errorf("%w: account media quota exhausted", ErrQuota)
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// fileRecord is the first half of storing a file inside tx, a transaction its caller holds and in
// which the message naming the file is written too: it takes the file's lock (store.LockFile, the
// lock Files.Collect takes to delete one) and writes the account's record when there is none. The
// caller writes the message next and the bytes LAST (BlobDir.Put), still in the transaction and
// under the lock, so a refusal anywhere before leaves neither a record nor bytes. A collection
// therefore sees either the message that names the file or no file being stored; one that deleted
// the record and the bytes just before is followed by both being written anew. It returns the
// file's hash (the hex SHA-256 its bytes are stored under) and whether it wrote the record.
func fileRecord(ctx context.Context, tx store.Store, accountID string, data []byte, mime, filename string, now int64) (string, bool, error) {
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if err := tx.LockFile(ctx, hash); err != nil {
		return "", false, err
	}
	if _, err := tx.GetBlob(ctx, accountID, hash); err == nil {
		return hash, false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", false, err
	}
	if err := tx.InsertBlob(ctx, store.Blob{
		AccountID: accountID, Hash: hash, Size: int64(len(data)), Mime: mime,
		Filename: filename, CreatedAt: now,
	}); err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// keepAndRecord stores a media message's file and records the message in one transaction
// (fileRecord, the message, then the bytes), and publishes the message once it is committed.
func (m *MediaService) keepAndRecord(ctx context.Context, msgSvc *Service, accountID, contactFpr string, dir Direction, in Input, data []byte, mime, filename string) (Result, error) {
	if in.MsgID == "" {
		return Result{}, fmt.Errorf("%w: msg_id required", ErrBadRequest)
	}
	var res Result
	var fresh bool
	err := m.Store.Atomically(ctx, func(tx store.Store) error {
		hash, _, err := fileRecord(ctx, tx, accountID, data, mime, filename, m.now().Unix())
		if err != nil {
			return err
		}
		meta, _ := json.Marshal(MediaMeta{Filename: filename, Mime: mime, Hash: hash, Size: int64(len(data))})
		in.Text = string(meta)
		if res, fresh, err = msgSvc.write(ctx, tx, accountID, contactFpr, dir, in, "media"); err != nil {
			return err // refused: the record rolls back, and no byte was written
		}
		_, err = m.Blobs.Put(data)
		return err
	})
	if err != nil {
		return Result{}, err
	}
	if fresh {
		msgSvc.publish(accountID, contactFpr, res.ThreadID)
	}
	return res, nil
}
