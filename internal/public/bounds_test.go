package public

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyCap(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, `{"code":"too_large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(200)
	})
	h := CapBody(inner, 1024)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 2048))))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d, want 413", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest("POST", "/", strings.NewReader("small")))
	if rr2.Code != 200 {
		t.Fatalf("small body: %d", rr2.Code)
	}
}
