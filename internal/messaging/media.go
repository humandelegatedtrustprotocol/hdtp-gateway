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

const MaxMediaBytes = 5 << 20 // HDTP §12: media ≤ 5 MiB inline

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
	Hash     string `json:"hash,omitempty"` // set once content is held locally
	URL      string `json:"url,omitempty"`  // present until an explicit fetch
	Size     int64  `json:"size,omitempty"`
}

type MediaService struct {
	Store store.MessageStore
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
	hash, err := m.Blobs.Put(data)
	if err != nil {
		return Result{}, err
	}
	// per-account row (idempotent: dedup on (account, hash))
	if _, err := m.Store.GetBlob(ctx, accountID, hash); err != nil {
		if err := m.Store.InsertBlob(ctx, store.Blob{
			AccountID: accountID, Hash: hash, Size: int64(len(data)), Mime: mime,
			Filename: filename, CreatedAt: m.now().Unix(),
		}); err != nil {
			return Result{}, err
		}
	}
	meta, _ := json.Marshal(MediaMeta{Filename: filename, Mime: mime, Hash: hash, Size: int64(len(data))})
	in.Text = string(meta)
	return msgSvc.record(ctx, accountID, contactFpr, DirIn, in, "media")
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
	hash, err := m.Blobs.Put(data)
	if err != nil {
		return Result{}, err
	}
	if _, err := m.Store.GetBlob(ctx, accountID, hash); err != nil {
		if err := m.Store.InsertBlob(ctx, store.Blob{
			AccountID: accountID, Hash: hash, Size: int64(len(data)), Mime: mime,
			Filename: filename, CreatedAt: m.now().Unix(),
		}); err != nil {
			return Result{}, err
		}
	}
	meta, _ := json.Marshal(MediaMeta{Filename: filename, Mime: mime, Hash: hash, Size: int64(len(data))})
	in.Text = string(meta)
	return msgSvc.record(ctx, accountID, contactFpr, DirOut, in, "media")
}

// ReceiveURL records url media WITHOUT fetching (SPEC §7.5).
func (m *MediaService) ReceiveURL(ctx context.Context, msgSvc *Service, accountID, contactFpr string, in Input, filename, mime, url string) (Result, error) {
	meta, _ := json.Marshal(MediaMeta{Filename: filename, Mime: mime, URL: url})
	in.Text = string(meta)
	return msgSvc.record(ctx, accountID, contactFpr, DirIn, in, "media")
}

// Fetch is the EXPLICIT owner action for url media: resolve, vet every address,
// pin the dial, cap the read, count the quota, store content-addressed.
func (m *MediaService) Fetch(ctx context.Context, accountID, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("bad_request: %w", err)
	}
	host := req.URL.Hostname()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("unavailable: cannot resolve %s", host)
	}
	for _, ip := range ips {
		if m.privateCheck(ip) {
			if m.Audit != nil {
				m.Audit("media_fetch_refused", "account:"+accountID+" host:"+host+" ip:"+ip.String(), "denied")
			}
			return "", fmt.Errorf("permission_denied: %s resolves to a private address", host)
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
		return "", fmt.Errorf("unavailable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxMediaBytes+1))
	if err != nil {
		return "", fmt.Errorf("unavailable: %w", err)
	}
	if len(data) > MaxMediaBytes {
		return "", fmt.Errorf("%w: fetched media over 5 MiB", ErrTooLarge)
	}
	used, err := m.Store.SumBlobBytes(ctx, accountID)
	if err != nil {
		return "", err
	}
	if used+int64(len(data)) > m.quota() {
		return "", fmt.Errorf("%w: account media quota exhausted", ErrQuota)
	}
	hash, err := m.Blobs.Put(data)
	if err != nil {
		return "", err
	}
	if _, err := m.Store.GetBlob(ctx, accountID, hash); err != nil {
		if err := m.Store.InsertBlob(ctx, store.Blob{
			AccountID: accountID, Hash: hash, Size: int64(len(data)),
			Mime: resp.Header.Get("Content-Type"), CreatedAt: m.now().Unix(),
		}); err != nil {
			return "", err
		}
	}
	return hash, nil
}
