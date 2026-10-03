package scenario

// An owner's portal session, as plain HTTP.
//
// The portal requires a session on every bind (SPEC §8.3). Scenarios written before that read
// pages and posted forms as nobody — a CSRF cookie off an unauthenticated GET was enough — and
// they read server-rendered HTML, which the portal stopped producing when it became a single
// page over a JSON API. So a scenario is an OWNER now: the browser that ran the passkey ceremony
// hands over its cookies, and what a scenario asserts on is what the page itself is built from.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/portal"
)

// OwnerSession is a signed-in owner of one node's portal.
type OwnerSession struct {
	// Base is where the portal is published on the host, e.g. http://localhost:18680.
	Base    string
	cookies []*http.Cookie
}

// csrf is the double-submit token: the cookie's value, echoed in a header and a form field. The
// cookie's name carries the node's tag, so it is found by its prefix.
func (s *OwnerSession) csrf() string {
	for _, c := range s.cookies {
		if strings.HasPrefix(c.Name, "hdtp_csrf") {
			return c.Value
		}
	}
	return ""
}

// Response is what one portal request answered.
type Response struct {
	Code   int
	Header http.Header
	Body   string
}

func (s *OwnerSession) do(ctx context.Context, method, path string, body io.Reader, contentType string) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.Base+path, body)
	if err != nil {
		return Response{}, err
	}
	for _, c := range s.cookies {
		req.AddCookie(c)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-HDTP-Csrf", s.csrf())
	}
	// No redirects followed: a form answers 303 to a page that is an application shell, and
	// what a scenario wants to know is whether the POST was taken.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	return Response{Code: res.StatusCode, Header: res.Header, Body: string(b)}, nil
}

// Get reads a portal path — a JSON endpoint, which is what the page reads too.
func (s *OwnerSession) Get(ctx context.Context, path string) (int, string, error) {
	r, err := s.Read(ctx, path)
	return r.Code, r.Body, err
}

// Read is Get with the answer's headers, for a route whose headers are the point (a download).
func (s *OwnerSession) Read(ctx context.Context, path string) (Response, error) {
	return s.do(ctx, http.MethodGet, path, nil, "")
}

// Post submits a portal form as the owner and returns what it answered, whatever the status: a
// route that answers in JSON (media fetch) says in its body what it did. accountID may be empty
// for node-wide forms.
func (s *OwnerSession) Post(ctx context.Context, path, accountID string, fields map[string]string) (Response, error) {
	form := url.Values{"csrf": {s.csrf()}}
	if accountID != "" {
		form.Set("account", accountID)
	}
	for k, v := range fields {
		form.Set(k, v)
	}
	return s.do(ctx, http.MethodPost, path, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
}

// PostForm submits a portal form as the owner and fails on a 4xx or 5xx.
func (s *OwnerSession) PostForm(ctx context.Context, path, accountID string, fields map[string]string) error {
	r, err := s.Post(ctx, path, accountID, fields)
	if err != nil {
		return err
	}
	if r.Code >= 400 {
		return fmt.Errorf("POST %s answered %d: %s", path, r.Code, shorten(r.Body, 300))
	}
	return nil
}

// Browser opens a browser that is this owner, for what only a browser can answer: what a view
// draws, and whether it draws it in both themes. The caller closes it.
func (s *OwnerSession) Browser(ctx context.Context) (*portal.Session, error) {
	br, err := portal.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("chrome: %w", err)
	}
	if err := br.SignIn(ctx, s.Base, s.cookies); err != nil {
		br.Close()
		return nil, err
	}
	return br, nil
}
