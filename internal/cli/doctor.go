package cli

import (
	"context"
	"fmt"
	pactidentity "github.com/pact-cloud/pact-identity/go"
	"io"
	"os"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/limits"
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
					case !info.Served():
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
					if line := handshakesOwedLine(a.Slug, info.HandshakesOwed, info.HandshakesUnderWay, info.Served()); line != "" {
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
	// The limits sidecar decides every call budget (SPEC §5.7); while it does not answer, a serving
	// node refuses every sealed call `unavailable`.
	lctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if _, err := limits.New(cfg.LimitsSocketPath()).Probe(lctx); err != nil {
		fmt.Fprintf(stdout, "FAIL limits       %s: %v; until it answers, every sealed call is refused unavailable\n", cfg.LimitsSocketPath(), err)
		fail = 1
	} else {
		fmt.Fprintf(stdout, "ok   limits       %s answering\n", cfg.LimitsSocketPath())
	}
	cancel()
	if cfg.PublicURL == "" {
		fmt.Fprintln(stdout, "warn probe        skipped: public_url not configured")
		return fail
	}
	// An address a wallet will not certify: every signing request under it is refused
	// (identity.IssueCSR applies the same rule, pactidentity.AddressGuard).
	if ok, why := pactidentity.AddressGuard(identity.EndpointFor(cfg.PublicURL, "x"), "", false); !ok {
		fmt.Fprintf(stdout, "FAIL public_url   %s: %s; a wallet certifies no address under it, so no identity here can get a leaf\n", cfg.PublicURL, why)
		fail = 1
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
