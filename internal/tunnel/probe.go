package tunnel

// Reachability probe (SPEC §10.4): dial the advertised endpoint, validate the
// served certificate the way a peer would (identity-fingerprint pin on a
// self-signed listener, WebPKI on a domain / the edge's certificate in edge
// mode), and confirm the connection lands on THIS instance by round-tripping
// a fresh nonce through the probe handler. Hairpin NAT can make a
// self-originated probe unrepresentative: that is reported as a caveat, never
// as a clean pass.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// ProbePath is where the node answers probes (no auth: it only echoes a nonce
// and the instance id, and reveals nothing about contacts or accounts).
const ProbePath = "/.well-known/pact-probe"

// Verdict is the probe's one-word diagnosis.
type Verdict string

const (
	VerdictReachable     Verdict = "reachable"
	VerdictUnreachable   Verdict = "unreachable"
	VerdictWrongCert     Verdict = "wrong_cert"
	VerdictWrongInstance Verdict = "wrong_instance"
)

// Result is the probe report the portal and doctor surface.
type Result struct {
	Verdict  Verdict `json:"verdict"`
	Endpoint string  `json:"endpoint"`
	Detail   string  `json:"detail,omitempty"`
	// Caveat is set when the probe originated from the node itself (hairpin
	// NAT may make the result unrepresentative).
	Caveat string `json:"caveat,omitempty"`
}

// Options select how the served certificate is validated.
type ProbeOptions struct {
	// PinnedFingerprint validates a self-signed listener by identity
	// fingerprint (PACT §2); "" means WebPKI validation of the hostname.
	PinnedFingerprint string
	// InstanceID is this node's id; the handler echoes its own and a mismatch
	// means the endpoint reaches some OTHER instance.
	InstanceID string
	Timeout    time.Duration
	// SelfOriginated marks a probe dialed from the node itself (hairpin caveat).
	SelfOriginated bool
}

// ProbeHandler answers ProbePath: {"nonce": <echo>, "instance": <id>}.
func ProbeHandler(instanceID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if len(nonce) > 64 {
			nonce = nonce[:64]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce, "instance": instanceID})
	})
}

// Probe runs one reachability check against endpoint (scheme://host[:port]).
func Probe(ctx context.Context, endpoint string, o ProbeOptions) Result {
	res := Result{Endpoint: endpoint}
	if o.SelfOriginated {
		res.Caveat = "probe originated from the node itself: hairpin NAT can make this pass or fail unrepresentatively"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		res.Verdict = VerdictUnreachable
		res.Detail = "endpoint is not a URL"
		return res
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	host := u.Hostname()
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if o.PinnedFingerprint != "" {
		// pinned: the served leaf MUST carry the identity key; chains are irrelevant
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate served")
			}
			fpr, err := identity.Fingerprint(cs.PeerCertificates[0].PublicKey)
			if err != nil {
				return err
			}
			if fpr != o.PinnedFingerprint {
				return fmt.Errorf("served key %s is not the pinned %s", fpr, o.PinnedFingerprint)
			}
			return nil
		}
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialContext:     (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}
	nonceB := make([]byte, 16)
	_, _ = rand.Read(nonceB)
	nonce := hex.EncodeToString(nonceB)
	probeURL := u.Scheme + "://" + u.Host + ProbePath + "?nonce=" + nonce
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		var unknownAuth x509.UnknownAuthorityError
		var hostErr x509.HostnameError
		switch {
		case errors.As(err, &certErr), errors.As(err, &unknownAuth), errors.As(err, &hostErr),
			strings.Contains(err.Error(), "not the pinned"), strings.Contains(err.Error(), "no certificate served"),
			strings.Contains(err.Error(), "x509:"):
			res.Verdict = VerdictWrongCert
		default:
			res.Verdict = VerdictUnreachable
		}
		res.Detail = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var echo struct {
		Nonce    string `json:"nonce"`
		Instance string `json:"instance"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &echo) != nil || echo.Nonce != nonce {
		res.Verdict = VerdictWrongInstance
		res.Detail = fmt.Sprintf("endpoint answered %d without echoing the probe nonce: something else is serving there", resp.StatusCode)
		return res
	}
	if o.InstanceID != "" && echo.Instance != o.InstanceID {
		res.Verdict = VerdictWrongInstance
		res.Detail = "endpoint reaches a different pact-gateway instance (" + echo.Instance + ")"
		return res
	}
	res.Verdict = VerdictReachable
	return res
}
