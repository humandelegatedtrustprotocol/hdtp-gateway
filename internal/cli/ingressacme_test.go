package cli

// The ingress role could only ever talk to Let's Encrypt PRODUCTION: ingressServe
// built its issuer as `ACMEOptions{StorageDir, Email, HTTP01Port: 80}` and never
// set CA, though the library has carried that field — and TrustedRoots — since
// P5-02, where the in-process tests use both against Pebble.
//
// That is a live hazard, not a test inconvenience. Let's Encrypt rate-limits
// FAILED validations (5 per account/hostname/hour) and issuance per registered
// domain per week. A first ingress is exactly when validation fails repeatedly:
// DNS has not propagated, port 80 is filtered by the VPS provider, the subdomain
// points at the wrong host. With no way to rehearse against staging, an owner
// spends production limits on setup mistakes and is then locked out for an hour
// during the very debugging that would fix it.
//
// These tests run the real argv through the real flag set into the real options,
// because a flag that is registered and then dropped looks identical from -h.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// parseIngress runs argv through the same flag set ingressServe uses.
func parseIngress(t *testing.T, args ...string) ingressFlags {
	t.Helper()
	var f ingressFlags
	var errb bytes.Buffer
	if err := ingressFlagSet(&f, &errb).Parse(args); err != nil {
		t.Fatalf("parsing %v: %v %s", args, err, errb.String())
	}
	return f
}

const stagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"

func TestIngressCanBeAimedAtANonDefaultACMEDirectory(t *testing.T) {
	o, err := acmeOptions(parseIngress(t, "-domain", "x.test", "-acme-ca", stagingDir))
	if err != nil {
		t.Fatal(err)
	}
	if o.CA != stagingDir {
		t.Errorf("-acme-ca did not reach the issuer: CA=%q; an owner cannot rehearse "+
			"against staging and burns Let's Encrypt production rate limits on setup mistakes", o.CA)
	}
	// Unset must still mean the default CA, so the flag cannot change production.
	o, err = acmeOptions(parseIngress(t, "-domain", "x.test"))
	if err != nil {
		t.Fatal(err)
	}
	if o.CA != "" {
		t.Errorf("with no -acme-ca the directory must stay certmagic's default, got %q", o.CA)
	}
	if o.StorageDir == "" {
		t.Error("storage dir must default, or NewACME refuses to build at all")
	}
}

func TestIngressTrustsAPrivateACMECARoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ca.pem")
	writeTestCA(t, root)

	o, err := acmeOptions(parseIngress(t, "-domain", "x.test", "-acme-ca", "https://ca.internal/dir",
		"-acme-ca-root", root))
	if err != nil {
		t.Fatal(err)
	}
	if o.TrustedRoots == nil {
		t.Fatal("-acme-ca-root did not reach the issuer, so a private or test CA " +
			"(step-ca, Pebble) cannot be used at all: its own HTTPS is untrusted")
	}
	// lint:ignore SA1019 Subjects() is only unreliable for the SYSTEM pool; this
	// pool is one we built from the -acme-ca-root file, so counting it is exact.
	//lint:ignore SA1019 counting a pool we constructed ourselves
	if n := len(o.TrustedRoots.Subjects()); n != 1 {
		t.Errorf("expected exactly the one root we supplied, got %d", n)
	}
}

// A root that cannot be read must stop startup. Silently continuing with the
// system pool would make the ingress reach for the PUBLIC CA while the owner
// believes they are pointed at a private one.
func TestIngressRefusesAnUnusableACMECARoot(t *testing.T) {
	for _, tc := range []struct{ name, path, want string }{
		{"missing", filepath.Join(t.TempDir(), "absent.pem"), "acme ca root"},
		{"not a certificate", writeJunk(t), "no PEM certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := acmeOptions(parseIngress(t, "-domain", "x.test", "-acme-ca-root", tc.path))
			if err == nil {
				t.Fatal("an unusable CA root was accepted; the ingress would silently " +
					"fall back to the system trust store")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not say what is wrong: %v", err)
			}
		})
	}
}

func writeJunk(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(p, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeTestCA(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "harness test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The `-acme-ca-root` help says it "does not affect peer or contact
// verification". That is a security claim, and until this test it was unverified
// — the same shape as four earlier defects here: correct where written, unchecked
// where reached. A pool that leaked into a peer TLS config would make an operator
// -supplied CA able to vouch for CONTACTS, and HDTP §2 says identity is the pinned
// SPKI and nothing else.
//
// It is pinned at the source level because there is no runtime seam to observe:
// the pool is handed to certmagic and never surfaces again. If a future change
// wires ACME trust into another TLS path, this fails and asks for a justification.
func TestACMECARootCannotReachPeerVerification(t *testing.T) {
	allowed := map[string]bool{
		// declares the field and hands it to certmagic's ACME issuer
		filepath.Join("internal", "ingress", "acme.go"): true,
		// builds the pool from -acme-ca-root (acmeOptions, above)
		filepath.Join("internal", "cli", "ingresscmd.go"): true,
	}
	root := cliRepoRoot(t)
	var found []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			if bytes.Contains(b, []byte("TrustedRoots")) {
				rel, _ := filepath.Rel(root, p)
				found = append(found, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range found {
		if !allowed[f] {
			t.Errorf("%s uses TrustedRoots. The ACME CA pool exists only for the CA's own "+
				"HTTPS; anywhere else it would let an operator-supplied root vouch for a "+
				"PEER, and HDTP §2 makes identity the pinned SPKI and nothing else. If this "+
				"is a different pool, name it differently or add it here with a reason.", f)
		}
	}
	if len(found) == 0 {
		t.Error("no production use of TrustedRoots at all — the flag is dead, or this lint " +
			"is looking in the wrong place and would never catch a leak")
	}
}

// cliRepoRoot walks up to the directory holding go.mod.
func cliRepoRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatal("no go.mod above the test's working directory")
		}
		d = parent
	}
}

// Splitting the flag set out of ingressServe silently DROPPED
// -internal-vhost-port, and nothing noticed: `make check` stayed green, doclint
// only checks that flags quoted in docs are accepted, and relaywiring_test only
// exercises arguments the command refuses. The ingress came up with the
// passthrough route pointed at 127.0.0.1:0 and the failure appeared four minutes
// later as "no certificate for bob".
//
// A default that reaches zero is the dangerous kind: port 0 binds something, and
// an empty address string dials nothing, so both fail far from here.
func TestIngressFlagDefaultsSurviveTheFlagSet(t *testing.T) {
	f := parseIngress(t, "-domain", "x.test")
	for _, tc := range []struct {
		flag string
		got  any
		want any
	}{
		{"-pair-bind", f.pairBind, "127.0.0.1:8444"},
		{"-vhost-port", f.vhostPort, 443},
		{"-data-plane-port", f.dataPlanePort, 7000},
		{"-internal-vhost-port", f.internalVhostPort, 7443},
		{"-domain", f.domain, "x.test"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s defaulted to %v, want %v — the flag is missing from the flag set "+
				"or its default changed; the ingress will misroute rather than refuse to start",
				tc.flag, tc.got, tc.want)
		}
	}
}
