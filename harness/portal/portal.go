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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
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
func Open(parent context.Context) (*Session, error) {
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent,
		append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", "new"))...)
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
			deadline := time.Now().Add(45 * time.Second)
			for {
				// Check the LOCATION first. On success the wizard navigates to
				// "/", and #msg goes with it — so reading the message first races
				// the navigation and reports a failure that did not happen. The
				// URL is the durable signal; the message is the diagnostic.
				var url string
				if err := chromedp.Location(&url).Do(ctx); err == nil &&
					url != "" && !strings.Contains(url, "/setup") {
					msg = "Registered. Opening your node…"
					return nil
				}
				var cur string
				if err := chromedp.Text("#msg", &cur, chromedp.ByID).Do(ctx); err != nil { //nolint:staticcheck
					_ = err
				} else if t := strings.TrimSpace(cur); t != "" && !strings.HasPrefix(t, progressMsg) {
					msg = t
					return nil
				}
				if time.Now().After(deadline) {
					msg = strings.TrimSpace(msg)
					return fmt.Errorf("the wizard never moved past %q", progressMsg)
				}
				time.Sleep(250 * time.Millisecond)
			}
		}),
	)
	if err != nil {
		return msg, fmt.Errorf("portal: registering a passkey: %w", err)
	}
	return strings.TrimSpace(msg), nil
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
