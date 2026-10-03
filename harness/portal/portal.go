// Package portal drives the owner-facing portal with a real browser over CDP.
//
// The setup wizard is a WebAuthn ceremony, and WebAuthn cannot be exercised by an
// HTTP client — it needs an authenticator and a browser that speaks to one. CDP's
// virtual authenticator gives us Chrome's OWN WebAuthn implementation rather than a
// Go reimplementation of it, which is the closest a machine gets to the real thing
// without a physical key.
package portal

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// progressMsg is what the wizard shows the moment the button is clicked, before
// the ceremony resolves. It is not an outcome.
const progressMsg = "Waiting for your device"

// Session is a browser attached to one portal.
type Session struct {
	ctx    context.Context
	cancel context.CancelFunc
	authID webauthn.AuthenticatorID
}

// Open launches a headless browser with a virtual authenticator installed.
func Open(parent context.Context) (*Session, error) { return OpenTrusting(parent) }

// OpenTrusting is Open with a browser that accepts the certificates whose public keys hash to
// spki (base64 SHA-256 of the SubjectPublicKeyInfo, Chrome's --ignore-certificate-errors-spki-list),
// for a portal served over TLS with a certificate no public authority signed. Only those keys are
// trusted; every other certificate error is still an error.
func OpenTrusting(parent context.Context, spki ...string) (*Session, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", "new"))
	if len(spki) > 0 {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors-spki-list", strings.Join(spki, ",")))
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, opts...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	cancel := func() { cancelBrowser(); cancelAlloc() }

	if err := chromedp.Run(browserCtx); err != nil {
		cancel()
		return nil, fmt.Errorf("portal: starting Chrome: %w", err)
	}

	s := &Session{ctx: browserCtx, cancel: cancel}
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		if err := webauthn.Enable().Do(ctx); err != nil {
			return err
		}
		// A platform authenticator with resident keys and user verification is what
		// a laptop's own biometric sensor looks like — the case the wizard is
		// written for. isUserVerified:true stands in for the fingerprint prompt,
		// which no automated run can satisfy.
		id, err := webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
			Protocol:                    webauthn.AuthenticatorProtocolCtap2,
			Transport:                   webauthn.AuthenticatorTransportInternal,
			HasResidentKey:              true,
			HasUserVerification:         true,
			IsUserVerified:              true,
			AutomaticPresenceSimulation: true,
		}).Do(ctx)
		if err != nil {
			return err
		}
		s.authID = id
		return nil
	})); err != nil {
		cancel()
		return nil, fmt.Errorf("portal: installing a virtual authenticator: %w", err)
	}
	return s, nil
}

func (s *Session) Close() { s.cancel() }

// RegisterFirstPasskey drives the setup wizard to completion and returns the
// message the page reported.
//
// setupURL must already carry its token: the wizard is loopback-or-token gated
// (SPEC §3.1), and the token is NOT burned by loading the page — a ceremony is two
// requests, which is exactly why P12-07 corrected the copy that called it
// single-use.
func (s *Session) RegisterFirstPasskey(ctx context.Context, setupURL, tag string) (string, error) {
	runCtx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer cancel()

	var msg string
	err := chromedp.Run(runCtx,
		chromedp.Navigate(setupURL),
		chromedp.WaitVisible("#go", chromedp.ByID),
		chromedp.SetValue("#tag", tag, chromedp.ByID),
		chromedp.Click("#go", chromedp.ByID),
		// The page reports the ceremony's outcome into #msg. It sets a PROGRESS
		// message the instant the button is clicked, so waiting for "#msg is
		// non-empty" returns immediately with "Waiting for your device…" and
		// reports a hang that never happened. Wait for a TERMINAL message.
		chromedp.ActionFunc(func(ctx context.Context) error {
			return until(ctx, 45*time.Second, 250*time.Millisecond, "the wizard to move past "+progressMsg, func(ctx context.Context) (bool, error) {
				// Check the LOCATION first. On success the wizard navigates to
				// "/", and #msg goes with it — so reading the message first races
				// the navigation and reports a failure that did not happen. The
				// URL is the durable signal; the message is the diagnostic.
				var url string
				if err := chromedp.Location(&url).Do(ctx); err == nil &&
					url != "" && !strings.Contains(url, "/setup") {
					msg = "Registered. Opening your node…"
					return true, nil
				}
				var cur string
				if err := chromedp.Text("#msg", &cur, chromedp.ByID).Do(ctx); err == nil {
					if t := strings.TrimSpace(cur); t != "" && !strings.HasPrefix(t, progressMsg) {
						msg = t
						return true, nil
					}
				}
				return false, nil
			})
		}),
	)
	if err != nil {
		return msg, fmt.Errorf("portal: registering a passkey: %w", err)
	}
	return strings.TrimSpace(msg), nil
}

// Cookies returns what the browser holds for a URL — after RegisterFirstPasskey, the owner's
// session and its CSRF token.
//
// The portal requires a session on EVERY bind (SPEC §8.3), loopback included, so a scenario
// that wants to do what an owner does — read a conversation, change a setting — has to be one.
// The ceremony is the only way to become one, and only a browser can run it; this hands the
// result to plain HTTP, so the rest of a scenario does not have to be a browser too.
func (s *Session) Cookies(ctx context.Context, rawURL string) ([]*http.Cookie, error) {
	var got []*network.Cookie
	runCtx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	if err := chromedp.Run(runCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		got, err = network.GetCookies().WithURLs([]string{rawURL}).Do(ctx)
		return err
	})); err != nil {
		return nil, fmt.Errorf("portal: reading the browser's cookies for %s: %w", rawURL, err)
	}
	out := make([]*http.Cookie, 0, len(got))
	for _, c := range got {
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	return out, nil
}

// SignIn gives this browser an owner's session — the cookies another browser earned by running
// the passkey ceremony (Cookies). The virtual authenticator that holds the passkey dies with the
// browser that registered it, so a later browser cannot sign in the way a person would; what it
// can do is carry the session that person already has.
func (s *Session) SignIn(ctx context.Context, base string, cookies []*http.Cookie) error {
	runCtx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	return chromedp.Run(runCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		for _, c := range cookies {
			if err := network.SetCookie(c.Name, c.Value).WithURL(base + "/").Do(ctx); err != nil {
				return fmt.Errorf("portal: setting %s for %s: %w", c.Name, base, err)
			}
		}
		return nil
	}))
}

// SignInWithPasskey signs this browser in the way a person does once their session is gone: its
// cookies are cleared, the sign-in page is opened, and its button runs the ceremony against the
// passkey this browser's authenticator registered. The sign-in is discoverable — the node offers no
// credential list — so this is what proves a registered passkey can be found again; SignIn, which
// carries cookies, proves nothing about that.
func (s *Session) SignInWithPasskey(ctx context.Context, base string) (string, error) {
	runCtx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer cancel()
	const button = `//button[contains(., "Sign in with a passkey")]`
	var msg string
	err := chromedp.Run(runCtx,
		network.ClearBrowserCookies(),
		chromedp.Navigate(base+"/login"),
		chromedp.WaitVisible(button, chromedp.BySearch),
		chromedp.Click(button, chromedp.BySearch),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return until(ctx, 45*time.Second, 250*time.Millisecond, "the sign-in page to move past "+progressMsg, func(ctx context.Context) (bool, error) {
				var url string
				if err := chromedp.Location(&url).Do(ctx); err == nil && url != "" && !strings.Contains(url, "/login") {
					msg = ""
					return true, nil
				}
				var cur string
				if err := chromedp.Text("#msg", &cur, chromedp.ByID).Do(ctx); err == nil {
					if t := strings.TrimSpace(cur); t != "" && !strings.HasPrefix(t, progressMsg) {
						msg = t
						return true, nil
					}
				}
				return false, nil
			})
		}),
	)
	if err != nil {
		return msg, fmt.Errorf("portal: signing in with a passkey: %w", err)
	}
	if msg != "" {
		return msg, fmt.Errorf("portal: the sign-in page did not sign in: %s", msg)
	}
	return "", nil
}

// Page is what a person is looking at once the application has drawn a view: the words, where
// the links go, what can be pressed or typed into, and whether there is a way to go anywhere.
type Page struct {
	Text     string   `json:"text"`
	Links    []string `json:"links"`
	Controls []string `json:"controls"`
	HasNav   bool     `json:"hasNav"`
}

// Rendered opens a URL and reports the view once it has settled.
//
// The portal is one page over a JSON API: the document a server returns for any path is the same
// empty shell, and what an owner can DO is decided by what the script draws. So an affordance is
// asserted on the drawn page or not at all — fetching the HTML and looking for a form asserts on
// a document no browser ever shows anybody.
func (s *Session) Rendered(ctx context.Context, url string) (Page, error) {
	return s.rendered(ctx, url, false)
}

// RenderedOpen is Rendered after the person has opened every collapsed section on the page.
//
// The portal puts a page's lists before its forms and keeps a form collapsed behind its heading
// (a `<details>` whose `<summary>` is the heading) once there is a list to show: "Create an
// invite" is folded away as soon as one invite exists. A control in a closed section is not
// drawn, so Rendered does not see it, and is right not to. It is still offered: one click on a
// heading the page shows. This opens each closed section the way a person does, by clicking its
// summary, and then reads the page; a control the page does not draw even then is still missing.
func (s *Session) RenderedOpen(ctx context.Context, url string) (Page, error) {
	return s.rendered(ctx, url, true)
}

func (s *Session) rendered(ctx context.Context, url string, openSections bool) (Page, error) {
	runCtx, cancel := context.WithTimeout(s.ctx, 45*time.Second)
	defer cancel()
	var page Page
	const read = `(() => {
		// A control's name as assistive technology reads it: aria-label first (it replaces the
		// visible text: an icon button's "Remove" is "Remove probe"), then what it shows.
		const label = (e) => (e.getAttribute("aria-label") || e.innerText || e.value || e.getAttribute("placeholder") || e.getAttribute("name") || "").trim();
		return {
			text: document.body.innerText,
			links: [...document.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")),
			controls: [...document.querySelectorAll("button, input, textarea, select")].map(label).filter(Boolean),
			hasNav: !!document.querySelector("nav"),
		};
	})()`
	err := chromedp.Run(runCtx,
		chromedp.Navigate(url),
		chromedp.WaitVisible("main", chromedp.ByQuery),
		// A view draws its frame first and its data after the first fetch answers. Wait for the
		// loading placeholder to go rather than sleeping a guessed interval.
		chromedp.ActionFunc(func(ctx context.Context) error {
			return until(ctx, 20*time.Second, 150*time.Millisecond, "the view to finish loading", func(ctx context.Context) (bool, error) {
				var loading bool
				if err := chromedp.Evaluate(`!!document.querySelector("[aria-busy=true], .loading")`, &loading).Do(ctx); err != nil {
					return false, err
				}
				return !loading, nil
			})
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if !openSections {
				return nil
			}
			var opened int
			if err := chromedp.Evaluate(`(() => { const closed = [...document.querySelectorAll("details:not([open]) > summary")]; closed.forEach((s) => s.click()); return closed.length; })()`, &opened).Do(ctx); err != nil {
				return err
			}
			// Clicking a summary toggles its section; a section that did not open would leave its
			// controls undrawn, and the read below would report them missing, which is the truth.
			return until(ctx, 5*time.Second, 50*time.Millisecond, "the opened sections to draw", func(ctx context.Context) (bool, error) {
				var still int
				err := chromedp.Evaluate(`document.querySelectorAll("details:not([open]) > summary").length`, &still).Do(ctx)
				return still == 0, err
			})
		}),
		chromedp.Evaluate(read, &page),
	)
	if err != nil {
		return page, fmt.Errorf("portal: rendering %s: %w", url, err)
	}
	return page, nil
}

// LogConsole prints browser console output and page errors to stdout. A WebAuthn
// ceremony that silently never resolves is almost always explained there.
func (s *Session) LogConsole() {
	chromedp.ListenTarget(s.ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			for _, a := range e.Args {
				fmt.Printf("[console.%s] %s\n", e.Type, strings.Trim(string(a.Value), `"`))
			}
		case *runtime.EventExceptionThrown:
			fmt.Printf("[pageerror] %s\n", e.ExceptionDetails.Error())
		}
	})
}

// Visit loads a page, captures a screenshot, and reports what the browser
// complained about.
//
// The HTML-level tests assert structure; this asserts that a real browser could
// render it without errors. Those are different questions, and the second one is
// what `docs/conformance.md` lists as uncovered.
type Visit struct {
	Path       string
	Status     string
	ConsoleErr []string
	Screenshot []byte
}

// Theme selects the emulated colour scheme, so a page can be checked against both
// grounds — six of the portal's nine standalone pages once rendered black-on-white
// on a dark desktop, and no HTML assertion could have noticed.
type Theme string

const (
	Light Theme = "light"
	Dark  Theme = "dark"
)

// Capture visits one URL under one theme and screenshots it full-page.
func (s *Session) Capture(ctx context.Context, url string, theme Theme) (Visit, error) {
	v := Visit{Path: url}
	var errs []string
	// Collect console errors for THIS visit only.
	stop := make(chan struct{})
	chromedp.ListenTarget(s.ctx, func(ev interface{}) {
		select {
		case <-stop:
			return
		default:
		}
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			if e.Type == "error" {
				for _, a := range e.Args {
					errs = append(errs, strings.Trim(string(a.Value), `"`))
				}
			}
		case *runtime.EventExceptionThrown:
			errs = append(errs, e.ExceptionDetails.Error())
		}
	})
	defer close(stop)

	runCtx, cancel := context.WithTimeout(s.ctx, 45*time.Second)
	defer cancel()
	var shot []byte
	err := chromedp.Run(runCtx,
		emulation.SetEmulatedMedia().WithFeatures([]*emulation.MediaFeature{
			{Name: "prefers-color-scheme", Value: string(theme)},
		}),
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.FullScreenshot(&shot, 80),
	)
	v.ConsoleErr, v.Screenshot = errs, shot
	if err != nil {
		return v, fmt.Errorf("portal: capturing %s (%s): %w", url, theme, err)
	}
	return v, nil
}

// SaveScreenshot writes a capture to disk so a failed run leaves evidence.
func (v Visit) SaveScreenshot(dir, name string) error {
	if len(v.Screenshot) == 0 {
		return fmt.Errorf("portal: nothing captured for %s", v.Path)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".png"), v.Screenshot, 0o644)
}

// until asks probe every interval until it answers done, and fails when the budget runs out or ctx
// ends — never returns as if the thing had happened. Rendered's wait for the loading placeholder
// used to return nil at its deadline, so a view still showing its placeholder was read and asserted
// on as if it had drawn. A probe's error ends the wait at once.
func until(ctx context.Context, budget, interval time.Duration, what string, probe func(context.Context) (bool, error)) error {
	deadline := time.Now().Add(budget)
	for {
		done, err := probe(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("portal: waited %s for %s", budget, what)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("portal: waiting for %s: %w", what, ctx.Err())
		case <-time.After(interval):
		}
	}
}
