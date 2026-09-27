package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/internalui"
)

// healthcheck probes the internal listener's /healthz; the container HEALTHCHECK
// runs this (distroless has no shell or curl). Exit 0 iff healthy.
func healthcheck(args []string, stderr io.Writer) int {
	var cfgPath string
	fs := commonFlags("healthcheck", &cfgPath, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	client, url, err := healthClient(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "healthcheck: status", resp.Status)
		return 1
	}
	return 0
}

// healthClient is how the healthcheck reaches the internal listener: the way `serve` serves it.
// With internal TLS configured it speaks https and accepts exactly the certificate `serve` loaded
// from the same files — the listener it is asking about is its own, whatever name the certificate
// carries — and without it, plain http. It used to dial http:// whatever the config said.
func healthClient(cfg *core.Config) (*http.Client, string, error) {
	tlsCfg, err := internalui.LoadTLS(cfg.InternalTLSCert, cfg.InternalTLSKey)
	if err != nil {
		return nil, "", err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	if tlsCfg == nil {
		return client, "http://" + cfg.InternalBind + "/healthz", nil
	}
	want := tlsCfg.Certificates[0].Certificate[0]
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is replaced, not skipped: the one leaf accepted is the configured one.
		InsecureSkipVerify: true, // #nosec G402 -- VerifyPeerCertificate below pins the configured leaf
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || !bytes.Equal(raw[0], want) {
				return errors.New("the internal listener presented a certificate other than internal_tls_cert")
			}
			return nil
		},
	}}
	return client, "https://" + cfg.InternalBind + "/healthz", nil
}
