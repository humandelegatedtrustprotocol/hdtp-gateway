package tunnel

// Reachability probe (SPEC §10.4): dial the advertised endpoint, validate what is served there
// THE WAY A PEER DOES, and confirm the connection lands on THIS instance by round-tripping a
// fresh nonce through the probe handler. Hairpin NAT can make a self-originated probe
// unrepresentative: that is reported as a caveat, never as a clean pass.
//
// "The way a peer does" is the point of it, and for a day after pre-HDTP 1.x went it was not true.
// A peer recognises a node by the CHAIN it presents — leaf then root — validated to the root it
// pinned, AT THE ADDRESS IT DIALLED (HDTP §2, §14.2 rule 5). This compared the fingerprint of the
// served certificate's KEY with a pinned key instead, which was 1.x's rule, and it has a failure
// mode that matters: a node whose leaf names some other address than the one it is reached at
// serves "the right key", passes its own probe, and is refused by every peer there is. With no
// identity to validate against — behind a terminating edge — what a peer sees is the edge's
// WebPKI certificate, and that is what is checked.

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

	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// ProbePath is where the node answers probes (no auth: it only echoes a nonce
// and the instance id, and reveals nothing about contacts or accounts).
const ProbePath = "/.well-known/hdtp-probe"

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

// Served is one identity this node serves, as a peer holds it: the root it pins, and the address
// the leaf under that root has to name.
type Served struct {
	Root     string
	Endpoint string
}

// Options select how what is served is validated.
type ProbeOptions struct {
	// Identities are the identities this node serves. The chain presented at the endpoint must
	// validate to ONE of them at its own address (a listener presents one chain however many
	// accounts share it). Empty means WebPKI validation of the hostname: a terminating edge.
	Identities []Served
	// InstanceID is this node's id; the handler echoes its own and a mismatch
	// means the endpoint reaches some OTHER instance.
	InstanceID string
	Timeout    time.Duration
	// SelfOriginated marks a probe dialed from the node itself (hairpin caveat).
	SelfOriginated bool
	// Now is the clock the chain is judged by, and DialContext how the endpoint's host is
	// reached; nil means time.Now and the ordinary dialer.
	Now         func() time.Time
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
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
	if len(o.Identities) > 0 {
		now := time.Now
		if o.Now != nil {
			now = o.Now
		}
		// The chain is the authority, so Go's WebPKI verification is off and ours is on.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) != 2 {
				return fmt.Errorf("served %d certificate(s): a node presents its chain, leaf then root (HDTP §14.2)", len(cs.PeerCertificates))
			}
			chain := [][]byte{cs.PeerCertificates[0].Raw, cs.PeerCertificates[1].Raw}
			why := ""
			for _, id := range o.Identities {
				vr := hdtpidentity.ValidateChain(chain, hdtpidentity.ChainOpts{Now: now(), ExpectedRoot: id.Root, ExpectedEndpoint: id.Endpoint})
				if vr.OK {
					return nil
				}
				// The refusal worth reading is the one about OUR root: a chain under it that
				// fails is a leaf naming the wrong address, or an expired one.
				if why == "" || vr.Rule > 1 {
					why = fmt.Sprintf("for %s at %s: rule %d, %s", id.Root, id.Endpoint, vr.Rule, vr.Reason)
				}
			}
			return fmt.Errorf("the chain served there is not one a peer would accept (%s)", why)
		}
	}
	dial := (&net.Dialer{Timeout: timeout}).DialContext
	if o.DialContext != nil {
		dial = o.DialContext
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialContext:     dial,
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
			strings.Contains(err.Error(), "not one a peer would accept"), strings.Contains(err.Error(), "a node presents its chain"),
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
		res.Detail = "endpoint reaches a different hdtp-gateway instance (" + echo.Instance + ")"
		return res
	}
	res.Verdict = VerdictReachable
	return res
}
