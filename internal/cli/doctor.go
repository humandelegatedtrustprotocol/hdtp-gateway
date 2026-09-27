package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/services/settings"
	"github.com/pact-cloud/pact-gateway/internal/tunnel"
)

func doctor(args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("doctor", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := 0
	report := func(name string, err error) {
		if err != nil {
			fmt.Fprintf(stdout, "FAIL %-12s %v\n", name, err)
			fail = 1
			return
		}
		fmt.Fprintf(stdout, "ok   %s\n", name)
	}

	cfg, err := loadConfig(cfgPath)
	report("config", err)
	if cfg == nil {
		return 1
	}
	_, statErr := os.Stat(cfg.DataDir)
	report("data-dir", statErr)

	if lock, err := core.AcquireLock(cfg.DataDir); err != nil {
		// A held lock means a node is serving — report, don't fail.
		fmt.Fprintln(stdout, "ok   lock         held (node appears to be running)")
		var pong map[string]string
		report("admin-sock", core.AdminCall(core.AdminSocketPath(cfg.DataDir), "ping", nil, &pong))
	} else {
		lock.Release()
		fmt.Fprintln(stdout, "ok   lock         free (node not running)")
	}

	var served []tunnel.Served
	if statErr == nil {
		s, err := openStore(cfg)
		report("store-open", err)
		if err == nil {
			if accts, err := s.ListAccounts(context.Background()); err == nil && len(accts) > 0 {
				served = settings.ServedIdentities(cfg.PublicURL, accts)
				// PACT 2.0 (PACT §2): a host asks for renewal thirty days ahead;
				// doctor is where an operator without the portal hears it.
				idm := &identity.Manager{Store: s}
				for _, a := range accts {
					if !a.HasRoot() {
						continue
					}
					info, cerr := idm.Certificate(context.Background(), a.ID, time.Now())
					switch {
					case cerr != nil:
						fmt.Fprintf(stdout, "FAIL leaf         %s: %v\n", a.Slug, cerr)
						fail = 1
					case info.Kid == "":
						// A root and no current leaf (an import, or a leaf that expired): not served,
						// and there is no date to give.
						fmt.Fprintf(stdout, "warn leaf         %s has no current leaf on this host (root %s): it is not served until the wallet signs one\n", a.Slug, info.RootFingerprint)
					case info.RenewalDue:
						fmt.Fprintf(stdout, "warn leaf         %s expires %s: renewal due (run `account csr -slug %s -purpose renew`)\n", a.Slug, info.NotAfter.Format("2006-01-02"), a.Slug)
					default:
						fmt.Fprintf(stdout, "ok   leaf         %s valid until %s (root %s)\n", a.Slug, info.NotAfter.Format("2006-01-02"), info.RootFingerprint)
					}
					if line := addressDriftLine(cfg.PublicURL, a.Slug, info.Endpoint); line != "" {
						fmt.Fprintf(stdout, "warn address      %s\n", line)
					}
					if n, herr := idm.HandshakesOwed(context.Background(), a.ID); herr != nil {
						fmt.Fprintf(stdout, "FAIL handshake    %s: %v\n", a.Slug, herr)
						fail = 1
					} else if line := handshakesOwedLine(a.Slug, n, info.Kid != ""); line != "" {
						fmt.Fprintf(stdout, "warn handshake    %s\n", line)
					}
				}
			}
			s.Close()
		}
	}

	// tunnel + reachability (SPEC §10.4): mode is derived, so say what it derived
	name := cfg.Tunnel
	if name == "" {
		name = "direct"
	}
	fmt.Fprintf(stdout, "ok   tunnel       %s (mode %s, seal %s, client_cert %s)\n", name, cfg.Mode, cfg.Seal, cfg.ClientCert)
	if cfg.PublicURL == "" {
		fmt.Fprintln(stdout, "warn probe        skipped: public_url not configured")
		return fail
	}
	if cfg.Mode == core.ModeEdge {
		served = nil // the edge's WebPKI certificate is what peers see
	}
	res := tunnel.Probe(context.Background(), cfg.PublicURL, tunnel.ProbeOptions{
		Identities: served, Timeout: 5 * time.Second, SelfOriginated: true,
	})
	switch res.Verdict {
	case tunnel.VerdictReachable:
		fmt.Fprintf(stdout, "ok   probe        %s reachable (%s)\n", cfg.PublicURL, res.Caveat)
	default:
		fmt.Fprintf(stdout, "FAIL probe        %s %s: %s\n", cfg.PublicURL, res.Verdict, res.Detail)
		fail = 1
	}
	return fail
}
