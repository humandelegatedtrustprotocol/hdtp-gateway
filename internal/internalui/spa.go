package internalui

// Serving the embedded SPA (SPEC §8.2). The portal is a React app compiled into
// the binary; this file is the only place that knows that. Data lives under
// /api (api.go and the per-page files), writes on the original POST endpoints.

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/pact-cloud/pact-gateway/web"
)

// mountSPA registers the asset routes and the history fallback. It is called by
// HandlerWithAuth so every composition — production and tests — serves the same
// portal. The catch-all runs LAST in ServeMux precedence: any registered route
// (pages' POSTs, /api, /media, /events, /i/…) wins over it.
func mountSPA(mux *http.ServeMux) {
	files, fileServer := spaFiles()

	// Hashed build assets are immutable by construction — the name changes when
	// the content does — so the browser may keep them for as long as it likes.
	mux.Handle("GET /assets/", assetCache(fileServer))

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		// An unmatched /api path must fail like an API, not answer HTML that a
		// fetch() would try to JSON-parse.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		// A real file at the root of dist (favicon, manifest) serves as itself.
		if p != "" && !strings.Contains(p, "..") {
			if f, err := files.Open("/" + p); err == nil {
				if st, serr := f.Stat(); serr == nil && !st.IsDir() {
					_ = f.Close()
					fileServer.ServeHTTP(w, r)
					return
				}
				_ = f.Close()
			}
		}
		// Everything else is a view the SPA routes client-side. The shell is
		// no-store: it references hashed assets, and a cached stale shell after
		// an upgrade would reference assets this binary no longer embeds.
		w.Header().Set("Cache-Control", "no-store")
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

func assetCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		next.ServeHTTP(w, r)
	})
}

func spaFiles() (http.FileSystem, http.Handler) {
	sub, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		panic("webui: embedded dist missing: " + err.Error()) // build-time invariant
	}
	files := http.FS(sub)
	return files, http.FileServer(files)
}

// serveShell serves the SPA index for a route that carries its own server-side
// gate (the §8.6 setup wizard). The shell is static code; what the gate decides
// is whether THIS caller gets even that much of the wizard.
func serveShell(w http.ResponseWriter, r *http.Request) {
	_, fileServer := spaFiles()
	w.Header().Set("Cache-Control", "no-store")
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/"
	fileServer.ServeHTTP(w, r2)
}
