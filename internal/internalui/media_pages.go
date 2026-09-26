package internalui

// The owner's media surface (SPEC §7.4, §7.5, §8.2).
//
// The portal had none. A contact could send a file, the node stored it
// content-addressed and quota-counted, and the owner had no way to look at it:
// `BlobDir.Get` and `MediaService.Fetch` both existed with no production caller,
// so P2-05's "click-to-fetch" was a claim about code nobody could reach.
//
// Two routes, and the difference between them matters. `/media/{hash}` serves
// bytes this node already holds. `/media/fetch` performs the DELIBERATE fetch of
// a `url` a contact sent — never automatic, because §7.5's whole point is that
// auto-fetching attacker-supplied URLs would let any contact drive server-side
// requests into a home LAN. The SSRF guard lives in MediaService and is not
// re-implemented here.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
)

// MediaDeps is what the media routes need.
type MediaDeps struct {
	Store store.Store
	Blobs messaging.BlobDir
	// Fetch performs an owner-initiated fetch of a contact-supplied URL.
	// nil disables the route rather than half-serving it.
	Fetch func(ctx context.Context, accountID, rawURL string) (string, error)
	Audit func(action, resource, outcome string)
}

func (d MediaDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// MountMediaPages registers the owner's media routes.
func MountMediaPages(mux *http.ServeMux, d MediaDeps) {
	mux.HandleFunc("GET /media/{hash}", d.getMediaHash)
	mux.HandleFunc("POST /media/fetch", d.postMediaFetch)
}

// getMediaHash serves `GET /media/{hash}`.
func (d MediaDeps) getMediaHash(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	hash := r.PathValue("hash")
	if account == "" || hash == "" {
		http.Error(w, "account and hash are required", http.StatusBadRequest)
		return
	}
	// The blob row is the authorization: content is addressed by hash, so
	// without this check any account could read any other account's media
	// by guessing — and a hash sent BY a contact is not a guess.
	b, err := d.Store.GetBlob(r.Context(), account, hash)
	if err != nil {
		d.audit("media_read", "account:"+account+" blob:"+hash, "not_found")
		http.NotFound(w, r)
		return
	}
	data, err := d.Blobs.Get(hash)
	if err != nil {
		d.audit("media_read", "account:"+account+" blob:"+hash, "missing_bytes")
		http.Error(w, "the stored bytes for that media are gone", http.StatusGone)
		return
	}
	// Never let a contact's file choose how the browser treats it: a stored
	// MIME from a peer is untrusted input, and rendering it inline is how a
	// sent file becomes script on the portal's own origin.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment; filename="+quoteFilename(b.Filename))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	d.audit("media_read", "account:"+account+" blob:"+hash, "ok")
	_, _ = w.Write(data)
}

// postMediaFetch serves `POST /media/fetch`.
func (d MediaDeps) postMediaFetch(w http.ResponseWriter, r *http.Request) {
	if d.Fetch == nil {
		http.Error(w, "media fetching is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := r.PostForm.Get("account")
	raw := r.PostForm.Get("url")
	if account == "" || raw == "" {
		http.Error(w, "account and url are required", http.StatusBadRequest)
		return
	}
	// SPEC §7.5: this is the owner asking, explicitly. The SSRF range check,
	// the size cap and the quota accounting all live in MediaService.
	hash, err := d.Fetch(r.Context(), account, raw)
	if err != nil {
		d.audit("media_fetch", "account:"+account, "refused")
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	d.audit("media_fetch", "account:"+account+" blob:"+hash, "ok")
	writeJSON(w, map[string]string{"hash": hash})
}

// quoteFilename makes a peer-supplied name safe to put in a header: quotes and
// control characters would otherwise let it inject header syntax.
func quoteFilename(name string) string {
	if name == "" {
		return `"download"`
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
			// drop control characters entirely
		case r == '"' || r == '\\':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// mediaRef is the JSON body a media message row carries (§7.4).
type mediaRef struct {
	Filename string `json:"filename"`
	Mime     string `json:"mime"`
	Hash     string `json:"hash,omitempty"`
	URL      string `json:"url,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

// parseMediaRef decodes a media row's body, returning false for anything else.
func parseMediaRef(body string) (mediaRef, bool) {
	var m mediaRef
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return mediaRef{}, false
	}
	return m, m.Hash != "" || m.URL != ""
}
