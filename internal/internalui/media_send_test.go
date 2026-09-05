package internalui

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
)

func mediaMux(t *testing.T, sendMedia func(ctx context.Context, accountID, contactFpr string, in messaging.Input, filename, mime string, data []byte) (messaging.Result, error)) *http.ServeMux {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountMessagePages(mux, MessagesDeps{Store: st, SendMedia: sendMedia})
	return mux
}

func upload(t *testing.T, mux *http.ServeMux, fields map[string]string, filename string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	if filename != "" {
		fw, _ := w.CreateFormFile("file", filename)
		_, _ = fw.Write(data)
	}
	_ = w.Close()
	req := httptest.NewRequest("POST", "/messages/send_media?account=acct-1", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// The composer's file lands on the node with its bytes, a base filename, and a
// MIME type sniffed from the content — never the browser's word for it.
func TestSendMediaUploadReachesTheNode(t *testing.T) {
	var gotName, gotMime string
	var gotData []byte
	mux := mediaMux(t, func(_ context.Context, acct, fpr string, in messaging.Input, name, mime string, data []byte) (messaging.Result, error) {
		// The composer is the owner's own surface, so what reaches the node is
		// that fact — and the label it implies, which no caller supplied.
		if acct != "acct-1" || fpr != "sha256:bob" || in.MsgID != "m-1" ||
			in.Origin != messaging.OriginPortal || in.Label() != messaging.SenderHuman {
			t.Errorf("wrong routing: acct=%s fpr=%s msg=%s origin=%s label=%s", acct, fpr, in.MsgID, in.Origin, in.Label())
		}
		gotName, gotMime, gotData = name, mime, data
		return messaging.Result{ThreadID: "t1", Status: "delivered"}, nil
	})
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 64)...)
	rr := upload(t, mux, map[string]string{"contact": "sha256:bob", "msg_id": "m-1"}, "../../evil/photo.png", png)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	if gotName != "photo.png" {
		t.Errorf("filename should be the base name only, got %q", gotName)
	}
	if gotMime != "image/png" {
		t.Errorf("mime should be sniffed from the bytes, got %q", gotMime)
	}
	if !bytes.Equal(gotData, png) {
		t.Error("bytes did not arrive intact")
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["ok"] != true || out["status"] != "delivered" {
		t.Errorf("answer should report delivery: %s", rr.Body.String())
	}
}

func TestSendMediaUploadRefusesOversizeAndMissingFile(t *testing.T) {
	called := false
	mux := mediaMux(t, func(context.Context, string, string, messaging.Input, string, string, []byte) (messaging.Result, error) {
		called = true
		return messaging.Result{}, nil
	})
	big := bytes.Repeat([]byte{1}, messaging.MaxMediaBytes+1)
	if rr := upload(t, mux, map[string]string{"contact": "sha256:bob", "msg_id": "m-2"}, "big.bin", big); rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a 5 MiB+1 upload must be refused with 413, got %d", rr.Code)
	}
	if rr := upload(t, mux, map[string]string{"contact": "sha256:bob", "msg_id": "m-3"}, "", nil); rr.Code != http.StatusBadRequest {
		t.Errorf("no file must be 400, got %d", rr.Code)
	}
	if rr := upload(t, mux, map[string]string{"msg_id": "m-4"}, "a.txt", []byte("hi")); rr.Code != http.StatusBadRequest {
		t.Errorf("no contact must be 400, got %d", rr.Code)
	}
	if called {
		t.Error("a refused upload must never reach the node")
	}
}

// A contact's tools are listed as the peer answered them, and a call carries
// the JSON arguments through untouched and returns the raw result.
func TestContactToolsAreListedAndCallable(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var gotTool string
	var gotArgs map[string]any
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{
		Store: st,
		ListTools: func(_ context.Context, acct, fpr string) ([]ContactTool, error) {
			if acct != "acct-1" || fpr != "sha256:bob" {
				t.Errorf("wrong routing: %s %s", acct, fpr)
			}
			return []ContactTool{{Name: "check_availability", Description: "when are they free", InputSchema: json.RawMessage(`{"type":"object"}`)}}, nil
		},
		Call: func(_ context.Context, acct, fpr, tool string, args map[string]any) (string, error) {
			gotTool, gotArgs = tool, args
			return `{"content":[{"type":"text","text":"slots"}]}`, nil
		},
	})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/contacts/sha256:bob/tools?account=acct-1", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"check_availability"`) || !strings.Contains(rr.Body.String(), `"input_schema"`) {
		t.Fatalf("tools: %d %s", rr.Code, rr.Body.String())
	}

	form := "tool=check_availability&args=" + `{"window":{"from":"2026-09-01T09:00:00Z","to":"2026-09-01T18:00:00Z"},"duration_min":30}`
	req := httptest.NewRequest("POST", "/contacts/sha256:bob/call?account=acct-1", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"slots"`) {
		t.Fatalf("call: %d %s", rr.Code, rr.Body.String())
	}
	if gotTool != "check_availability" || gotArgs["duration_min"] != float64(30) {
		t.Errorf("arguments did not pass through: tool=%s args=%v", gotTool, gotArgs)
	}
	if w, ok := gotArgs["window"].(map[string]any); !ok || w["from"] != "2026-09-01T09:00:00Z" {
		t.Errorf("nested arguments did not survive: %v", gotArgs["window"])
	}

	req = httptest.NewRequest("POST", "/contacts/sha256:bob/call?account=acct-1", strings.NewReader("tool=x&args=not-json"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed arguments must be 400, got %d", rr.Code)
	}
}
