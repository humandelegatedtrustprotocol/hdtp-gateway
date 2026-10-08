// Command screenshots photographs the portal for docs/quickstart.md and README.md (`make
// screenshots`). It walks the guide on the node image: the setup link read from the log, the wizard
// before the first passkey, the overview after it, the public URL typed into the Settings form,
// `account create`, Identity and My card before and after the wallet's chain, an invite made on the
// People page's own form, then — after a second party has redeemed it over mTLS, sealed, been
// approved and sent one message — People, the inbox, Owners, Integrations, the overview and the
// audit trail. Each page is saved as a PNG, 1280 px wide, light theme, under the name the guide
// uses; nothing in a picture is drawn or edited. It is not a scenario: it records no verdict and
// no tier runs it.
//
//	go run ./cmd/screenshots <dir>
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/fabric"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/images"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/peer"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/portal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/scenario"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/topology"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/wallet"
)

// width is the viewport the pictures are taken at.
const width = 1280

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: screenshots <dir>")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "screenshots:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	w := &scenario.World{Fab: fabric.New(fabric.PrefixFor("DOCS"), fabric.Local)}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = w.Fab.Teardown(ctx)
	}()

	net, err := w.LAN(ctx)
	if err != nil {
		return err
	}
	ownerPort, err := fabric.FreePort()
	if err != nil {
		return err
	}
	publicPort, err := fabric.FreePort()
	if err != nil {
		return err
	}
	// No public URL, seal or client-certificate policy in the environment: a value set there is
	// pinned, and the portal shows it locked. The owner sets the public URL in Settings, as the
	// guide says, and the rest stays at the node's defaults.
	node, err := topology.Serve(ctx, w.Fab, fabric.Spec{
		Name: "node", Image: images.Node, Network: net, Cmd: []string{"serve"},
		Env:   map[string]string{"HDTP_PUBLIC_BIND": fmt.Sprintf("0.0.0.0:%d", topology.PublicPort), "HDTP_INTERNAL_BIND": fmt.Sprintf("127.0.0.1:%d", topology.InternalPort)},
		Ports: []string{ownerPort + ":" + fmt.Sprint(scenario.BridgePort), publicPort + ":" + fmt.Sprint(topology.PublicPort)},
	})
	if err != nil {
		return err
	}
	if err := topology.WaitHealthy(ctx, w.Fab, node); err != nil {
		return err
	}
	if _, err := w.Bridge(ctx, node); err != nil {
		return err
	}
	if err := scenario.WaitPortal(ctx, ownerPort); err != nil {
		return err
	}
	tok, err := scenario.SetupToken(ctx, w.Fab, node)
	if err != nil {
		return err
	}
	base := "http://localhost:" + ownerPort
	br, err := portal.Open(ctx)
	if err != nil {
		return fmt.Errorf("chrome: %w", err)
	}
	defer br.Close()
	sh := &shooter{ctx: ctx, br: br, base: base, dir: dir}

	// The wizard, as the setup link opens it; then the ceremony, which signs the browser in.
	if err := sh.shoot("/setup?token="+tok, "setup"); err != nil {
		return err
	}
	if msg, err := br.RegisterFirstPasskey(ctx, base+"/setup?token="+tok, "Alex's laptop"); err != nil {
		return fmt.Errorf("the wizard: %w (page said %q)", err, msg)
	}
	cookies, err := br.Cookies(ctx, base+"/")
	if err != nil {
		return err
	}
	session := scenario.NewOwnerSession(base, cookies)
	if err := sh.shoot("/", "overview-first"); err != nil {
		return err
	}

	// Settings: the public URL, typed into the form.
	if err := session.PostForm(ctx, "/settings", "", map[string]string{"public_url": "https://alex.example.com"}); err != nil {
		return err
	}
	if err := sh.shoot("/settings", "settings"); err != nil {
		return err
	}

	// The identity, before its wallet has certified it.
	if out, err := w.Fab.Exec(ctx, node, "/hdtp-gateway", "account", "create", "--slug", "alex", "--name", "Alex Example"); err != nil {
		return fmt.Errorf("account create: %w (%s)", err, out)
	}
	accountID, err := accountID(ctx, session)
	if err != nil {
		return err
	}
	for _, p := range [][2]string{{"/identity", "identity-new"}, {"/card?account=" + accountID, "card-none"}} {
		if err := sh.shoot(p[0], p[1]); err != nil {
			return err
		}
	}

	// The chain, from the owner's wallet.
	wal, err := wallet.New("Alex Example")
	if err != nil {
		return err
	}
	pin, err := wal.Certify(ctx, topology.NodeOf(w.Fab, node), "alex", "", "")
	if err != nil {
		return err
	}
	for _, p := range [][2]string{{"/identity", "identity"}, {"/card?account=" + accountID, "card"}} {
		if err := sh.shoot(p[0], p[1]); err != nil {
			return err
		}
	}

	// An invite, made in the browser: the link is shown once, on the page that made it.
	if err := sh.open("/invites?account=" + accountID); err != nil {
		return err
	}
	var link string
	if err := br.Do(ctx,
		chromedp.SendKeys(`input[placeholder="dinner group"]`, "Sam", chromedp.ByQuery),
		chromedp.Click(`//button[normalize-space(.)="Create"]`, chromedp.BySearch),
		chromedp.WaitVisible(`pre`, chromedp.ByQuery),
		chromedp.Text(`pre`, &link, chromedp.ByQuery),
	); err != nil {
		return fmt.Errorf("creating an invite on the page: %w", err)
	}
	if err := sh.save("invites"); err != nil {
		return err
	}
	i := strings.LastIndex(link, "/i/")
	if i < 0 || strings.TrimSpace(link[i+3:]) == "" {
		return fmt.Errorf("the page showed no invite link: %q", link)
	}
	token := strings.TrimSpace(link[i+3:])

	// A second party redeems it over mTLS, sealed (the node's default), is approved as a friend,
	// and sends one message.
	sam, err := peer.NewAgent("sam")
	if err != nil {
		return err
	}
	target := peer.Target{Endpoint: pin.Endpoint, Dial: "127.0.0.1:" + publicPort, Seal: "required", Root: pin.Root, Leaf: pin.Leaf}
	if _, err := sam.Call(ctx, target, "redeem_invite", map[string]any{"token": token, "card": sam.Card("required")}, "docs-redeem-1"); err != nil {
		return fmt.Errorf("redeem_invite: %w", err)
	}
	if err := session.PostForm(ctx, "/requests/"+sam.Fingerprint()+"/approve", accountID, map[string]string{"preset": "friend"}); err != nil {
		return err
	}
	if _, err := sam.Call(ctx, target, "send_message", map[string]any{
		"text": "Hi Alex — are you free on Thursday evening?", "sender": "agent", "msg_id": "docs-msg-1",
	}, "docs-msg-1"); err != nil {
		return fmt.Errorf("send_message: %w", err)
	}
	for _, p := range [][2]string{
		{"/contacts?account=" + accountID, "contacts"},
		{"/messages?account=" + accountID + "&contact=" + sam.Fingerprint(), "inbox"},
	} {
		if err := sh.shoot(p[0], p[1]); err != nil {
			return err
		}
	}

	// The owner's agent: a bearer token for the owner MCP, listed beside the passkey.
	if _, err := scenario.OwnerToken(ctx, w.Fab, node, "my agent"); err != nil {
		return err
	}
	for _, p := range [][2]string{
		{"/owners", "owners"}, {"/integrations?account=" + accountID, "integrations"},
		{"/", "dashboard"}, {"/audit", "audit"},
	} {
		if err := sh.shoot(p[0], p[1]); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d screenshots to %s\n", sh.n, dir)
	return nil
}

// shooter opens pages as the signed-in owner and saves what Chrome draws.
type shooter struct {
	ctx  context.Context
	br   *portal.Session
	base string
	dir  string
	n    int
}

// open navigates to path and waits for the view to draw.
func (s *shooter) open(path string) error {
	if err := s.br.Do(s.ctx, chromedp.Navigate(s.base+path), chromedp.WaitVisible("main", chromedp.ByQuery)); err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	return nil
}

// shoot opens path and saves it as name.
func (s *shooter) shoot(path, name string) error {
	if err := s.open(path); err != nil {
		return err
	}
	return s.save(name)
}

// save writes the page this browser is on as <name>.png, re-encoded at the smallest size Go's
// encoder gives (lossless: the pixels are Chrome's).
func (s *shooter) save(name string) error {
	shot, err := s.br.Screenshot(s.ctx, portal.Light, width)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	img, err := png.Decode(bytes.NewReader(shot))
	if err != nil {
		return fmt.Errorf("%s: Chrome's PNG does not decode: %w", name, err)
	}
	var out bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&out, img); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.dir, name+".png"), out.Bytes(), 0o644); err != nil { //nolint:gosec // a picture for the docs
		return err
	}
	s.n++
	fmt.Printf("%s.png: %dx%d, %d bytes\n", name, img.Bounds().Dx(), img.Bounds().Dy(), out.Len())
	return nil
}

// accountID is the one identity the signed-in owner administers, as the page reads it.
func accountID(ctx context.Context, session *scenario.OwnerSession) (string, error) {
	_, body, err := session.Get(ctx, "/api/session")
	if err != nil {
		return "", err
	}
	var out struct {
		Accounts []struct {
			ID string `json:"id"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Accounts) != 1 {
		return "", fmt.Errorf("/api/session lists %d accounts (%v): %.300s", len(out.Accounts), err, body)
	}
	return out.Accounts[0].ID, nil
}
