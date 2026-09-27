package ingress

// Pairing (SPEC §10.6): the owner mints a one-time token on the ingress and
// enters it on the node; the node connects OUTBOUND over TLS presenting its
// identity certificate, authenticates with the token once, and registers its
// subdomain and mode. Both sides pin each other's keys from this exchange —
// the node learns the ingress fingerprint from the served certificate, the
// ingress pins the node's SPKI from the client certificate — and the node
// receives its data-plane credentials.

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/identity"
)

// PairRequest is the node's one-shot registration.
type PairRequest struct {
	Token     string `json:"token"`
	Subdomain string `json:"subdomain"`
	Mode      Mode   `json:"mode"`
}

// PairResponse hands the node everything it needs for the data plane.
type PairResponse struct {
	IngressFingerprint string `json:"ingress_fingerprint"`
	Domain             string `json:"domain"` // base domain; public name is <subdomain>.<domain>
	PublicName         string `json:"public_name"`
	DataPlaneAddr      string `json:"data_plane_addr"` // frps host
	DataPlanePort      int    `json:"data_plane_port"`
	DataPlaneToken     string `json:"data_plane_token"` // shared frps token (transport auth)
	NodeSecret         string `json:"node_secret"`      // per-node login metadata the plugin verifies
}

// PairingServer serves POST /pair on a TLS listener that REQUESTS client certs.
type PairingServer struct {
	Registry           Registry
	Domain             string
	IngressFingerprint string
	DataPlaneAddr      string
	DataPlanePort      int
	DataPlaneToken     string
	Audit              func(action, resource, outcome string)
	// OnPaired fires after a node is recorded. Terminate-mode pairings need a
	// certificate for their name before the ingress can answer for it at all
	// (§10.6); nothing was hooked here, so a newly paired terminate subdomain
	// failed every handshake until the next restart — and after one too.
	OnPaired func(n Node)
}

func (p *PairingServer) audit(action, resource, outcome string) {
	if p.Audit != nil {
		p.Audit(action, resource, outcome)
	}
}

// Handler is the pairing endpoint; mount under a TLS server with
// ClientAuth >= RequestClientCert so the node's identity cert is visible.
func (p *PairingServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pair", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, `{"code":"identity_required"}`, http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		fpr, err := identity.Fingerprint(leaf.PublicKey)
		if err != nil {
			http.Error(w, `{"code":"identity_required"}`, http.StatusUnauthorized)
			return
		}
		var req PairRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		}
		if !ValidSubdomain(req.Subdomain) || (req.Mode != ModePassthrough && req.Mode != ModeTerminate) {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		}
		// exactly one pairing per token
		if !p.Registry.ConsumeToken(req.Token) {
			p.audit("ingress_pair", "subdomain:"+req.Subdomain, "invite_invalid")
			http.Error(w, `{"code":"invite_invalid"}`, http.StatusForbidden)
			return
		}
		spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			http.Error(w, `{"code":"identity_required"}`, http.StatusUnauthorized)
			return
		}
		secretB := make([]byte, 16)
		_, _ = rand.Read(secretB)
		node := Node{
			Fingerprint: fpr, SPKI: spki, Subdomain: req.Subdomain, Mode: req.Mode,
			Secret: hex.EncodeToString(secretB), PairedAt: time.Now(),
		}
		if err := p.Registry.Put(node); err != nil {
			p.audit("ingress_pair", "subdomain:"+req.Subdomain, "error")
			http.Error(w, `{"code":"conflict","detail":"`+err.Error()+`"}`, http.StatusConflict)
			return
		}
		if p.OnPaired != nil {
			p.OnPaired(node)
		}
		p.audit("ingress_pair", "subdomain:"+req.Subdomain+":"+fpr, "ok")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PairResponse{
			IngressFingerprint: p.IngressFingerprint, Domain: p.Domain,
			PublicName:    req.Subdomain + "." + p.Domain,
			DataPlaneAddr: p.DataPlaneAddr, DataPlanePort: p.DataPlanePort,
			DataPlaneToken: p.DataPlaneToken, NodeSecret: node.Secret,
		})
	})
	return mux
}

// Pair is the node side: connect outbound with the node's identity cert, pin
// the ingress by the fingerprint the owner typed alongside the token (or trust
// on first use when empty — the response carries the fingerprint to record).
func Pair(ctx_ *http.Client, pairURL string, nodeCert tls.Certificate, expectIngressFpr string, req PairRequest) (PairResponse, string, error) {
	var seenFpr string
	client := ctx_
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		Certificates:       []tls.Certificate{nodeCert},
		InsecureSkipVerify: true, // #nosec G402 -- pinned below, never chain-validated (PACT §2)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errIngressNoCert
			}
			f, err := identity.Fingerprint(cs.PeerCertificates[0].PublicKey)
			if err != nil {
				return err
			}
			seenFpr = f
			if expectIngressFpr != "" && f != expectIngressFpr {
				return errIngressPin
			}
			return nil
		},
		MinVersion: tls.VersionTLS12,
	}}
	body, _ := json.Marshal(req)
	resp, err := client.Post(pairURL, "application/json", bytesReader(body))
	if err != nil {
		return PairResponse{}, seenFpr, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return PairResponse{}, seenFpr, &PairError{Status: resp.StatusCode, Body: string(b)}
	}
	var out PairResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return PairResponse{}, seenFpr, err
	}
	return out, seenFpr, nil
}

// PairError is a non-200 pairing answer (the body carries the PACT code).
type PairError struct {
	Status int
	Body   string
}

func (e *PairError) Error() string { return "ingress: pairing refused: " + e.Body }

var (
	errIngressNoCert = errors.New("ingress: served no certificate")
	errIngressPin    = errors.New("ingress: served certificate does not match the pinned ingress fingerprint")
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
