package core

// Configuration per SPEC §12.2: precedence environment > file > defaults. The file is
// JSON (stdlib, no dependency); secrets never live here — they sit encrypted in the
// store under the keyring master key (§3.7), which is itself only referenced by path.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Knob and mode values (SPEC §2.5, §4.6, §5.1).
type Mode string
type Seal string
type ClientCert string

const (
	ModeDirect Mode = "direct"
	ModeEdge   Mode = "edge"

	SealNone     Seal = "none"
	SealOptional Seal = "optional"
	SealRequired Seal = "required"

	ClientCertRequired  ClientCert = "required"
	ClientCertPreferred ClientCert = "preferred"
	ClientCertOff       ClientCert = "off"
)

// Named validation rules: a rejected config names the exact rule violated (PLAN P0-02).
const (
	RuleInternalBindAuth = "internal_bind_requires_auth_and_tls"  // SPEC §2.2, §8.3
	RuleInternalHost     = "internal_bind_requires_internal_host" // SPEC §8.3, §12.2
	// RuleInternalHostIsRPID is applied where the config is LOADED for a command (internal/cli), not
	// in Validate: the judgement is the passkey library's own, and this package imports no library.
	RuleInternalHostIsRPID = "internal_host_is_a_passkey_relying_party" // SPEC §12.2
	RulePostgresDSN        = "postgres_dsn_required"                    // SPEC §11.1
	RuleEdgeSeal           = "edge_mode_forces_seal_required"           // SPEC §2.5
	RuleEdgeClientCert     = "edge_mode_forces_client_cert_off"         // SPEC §2.5
	RuleEnum               = "invalid_enum_value"
	RuleRange              = "value_out_of_range"
	RuleWalletURL          = "wallet_url_is_an_https_origin" // SPEC §12.2, HDTP §9.1
	RuleProxyAddress       = "proxy_address_is_an_ip"        // SPEC §5.1, §12.2
)

// DefaultLimitContacts is the contact cap of an account on a node nobody configured.
const DefaultLimitContacts = 500

// ErrContactCap: adding the contact would take the account past the number it may hold
// (limit.contacts). The owner's doors answer it `payment_required`, the code the cloud gives the
// same refusal; a peer is answered `unavailable`, bare (contacts.Manager.RedeemAs).
var ErrContactCap = errors.New("payment_required")

// ContactCapRefusal is the owner's refusal, with the count and the cap: for the owner, never a peer.
func ContactCapRefusal(held int64, cap int) error {
	return fmt.Errorf("%w: this identity holds %d contacts and sent requests, and this node allows %d (limit.contacts). Remove one, or raise the limit", ErrContactCap, held, cap)
}

// ContactCap is the number of contacts each account may hold: LimitContacts, or the default.
func (c *Config) ContactCap() int {
	if c.LimitContacts > 0 {
		return c.LimitContacts
	}
	return DefaultLimitContacts
}

type Config struct {
	// LimitContacts is how many contacts each account on this node may hold: active contacts plus
	// the requests it sent. It is enforced wherever a contact is added, and it sizes the account's
	// call budget — every contact calling at once, one call a second each (HDTP §12). Zero means
	// DefaultLimitContacts. Read per call, so a change takes effect without a restart.
	LimitContacts int `json:"limit_contacts,omitempty"`

	DataDir    string `json:"data_dir"`
	PublicBind string `json:"public_bind"`
	// PublicURL is the externally reachable base (scheme://host[:port]) used to
	// assemble card endpoints and invite links (SPEC §9.3); "" until configured.
	PublicURL    string `json:"public_url"`
	InternalBind string `json:"internal_bind"`

	// InternalHost is the hostname the portal is served at, and the ONLY
	// non-loopback name a WebAuthn ceremony may bind a credential to. It is
	// bootstrap, never owner-settable (SPEC §12.2): it gates authentication, so
	// it must not come from data the authenticated surface can write.
	InternalHost string `json:"internal_host"`

	// WalletURL is the ORIGIN of the web wallet the portal sends a signing request to (HDTP §9.1):
	// the page POSTs to WalletURL + "/sign" and the wallet answers at the portal's /wallet/return.
	// It is bootstrap, never owner-settable: it is the one foreign origin the portal's form-action
	// admits, so it cannot come from data the authenticated surface writes. Defaults to
	// DefaultWalletURL.
	WalletURL string `json:"wallet_url"`

	InternalAuthEnabled bool   `json:"internal_auth_enabled"`
	InternalTLSCert     string `json:"internal_tls_cert"`
	InternalTLSKey      string `json:"internal_tls_key"`

	// Tunnel names the inbound adapter ("" or "direct" = the node's own
	// listener). The deployment MODE is derived from the adapter's
	// TerminatesAtEdge flag (SPEC §10.1) — never declared. There are two: direct
	// and edge.
	Tunnel     string     `json:"tunnel"`
	Mode       Mode       `json:"mode"`
	Seal       Seal       `json:"seal"`
	ClientCert ClientCert `json:"client_cert"`

	// LANConnections: SPEC §5.1/§10.1 — defaults derived from mode (direct: on,
	// edge: off). Pointer in the wire forms so "unset" is
	// distinguishable from "explicit false"; resolved to a plain bool here.
	LANConnections bool `json:"-"`

	// EnvPinned names the owner-settable knobs the environment fixed, so the
	// portal can lock them instead of pretending they are editable.
	EnvPinned map[string]bool `json:"-"`

	// FilePinned names the owner-settable knobs the configuration FILE set.
	// SPEC §12.2 orders the layers `environment > file > store > defaults`, so
	// these outrank anything the portal writes; the settings page renders them
	// locked with the reason rather than offering a control that cannot work.
	FilePinned map[string]bool `json:"-"`
	// lanExplicit remembers whether the LAN flag was set explicitly (as opposed
	// to derived from the mode); Derive re-reads it on every re-resolution.
	lanExplicit *bool

	StoreEngine   string `json:"store_engine"`
	PostgresDSN   string `json:"postgres_dsn"`
	MasterKeyFile string `json:"master_key_file"`
	// BlobDir is where inline media is stored (SPEC §7.4): <data_dir>/blobs when unset. Node
	// processes that share a Postgres store from different hosts point it at storage every host
	// mounts (SPEC §11.1); processes sharing one data dir share its blobs already.
	BlobDir string `json:"blob_dir"`

	// ProxyAddress is the IP address of the proxy in front of the public listener, Envoy
	// (deploy/envoy, SPEC §5.1): it terminates the caller's TLS, asks for the caller's certificate
	// chain and forwards it in X-Forwarded-Client-Cert, and the caller's address in
	// X-HDTP-Client-Address. The node reads those two headers from a connection whose source
	// is this address and from no other; "" is no proxy, and neither header is ever read.
	// Bootstrap: it decides who may assert a caller's identity, so it cannot come from data the
	// authenticated surface writes.
	ProxyAddress string `json:"proxy_address"`

	// LimitsSocket is the unix socket of the limits sidecar (cmd/hdtp-limitd), which decides every
	// HDTP §12 budget (SPEC §5.7); "" is <data_dir>/limits.sock. Bootstrap, never owner-settable: it
	// decides who may refuse every caller, so it cannot come from data the authenticated surface
	// writes. Every node process on a host names the same one, which is what makes one counter.
	LimitsSocket string `json:"limits_socket"`

	// AuditArchiveAfter is how long the audit rows that name an identity that left this node stay
	// in the live trail before the hourly sweep moves them to the identity's archive file (SPEC
	// §3.11, §11.6): a whole number of days ("90d"), or a Go duration ("36h", "0s"). Bootstrap,
	// never owner-settable: it decides what the node keeps of a person who has gone.
	AuditArchiveAfter string `json:"audit_archive_after"`
}

// LimitsSocketPath is where the limits sidecar listens: LimitsSocket, or <data_dir>/limits.sock.
func (c *Config) LimitsSocketPath() string {
	if c.LimitsSocket != "" {
		return c.LimitsSocket
	}
	return filepath.Join(c.DataDir, "limits.sock")
}

// DefaultAuditArchiveAfter is the period the node keeps a departed identity's audit rows live
// (SPEC §3.11): a quarter, long enough for the owner to review the leave and whatever led to it
// in the portal, and short against HDTP §9's "keep nothing beyond what law compels".
const DefaultAuditArchiveAfter = "90d"

// ParseAuditArchiveAfter reads AuditArchiveAfter: a whole number of days with a `d`, or a Go
// duration, never negative.
func ParseAuditArchiveAfter(v string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 || n > 100000 {
			return 0, fmt.Errorf("%q is not a whole number of days", v)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(v); err != nil {
			return 0, fmt.Errorf("%q is neither a number of days (90d) nor a duration (36h)", v)
		}
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is negative", v)
	}
	return d, nil
}

// Tunnel adapter registry (filled by internal/tunnel at init): name → whether
// the adapter terminates TLS at an edge. Kept here so config resolution can
// derive the mode without importing the adapters.
var (
	tunnelMu    sync.RWMutex
	tunnelEdges = map[string]bool{"direct": false}
)

// RegisterTunnel records an adapter's TerminatesAtEdge flag for derivation.
func RegisterTunnel(name string, terminatesAtEdge bool) {
	tunnelMu.Lock()
	tunnelEdges[name] = terminatesAtEdge
	tunnelMu.Unlock()
}

func tunnelTerminatesAtEdge(name string) (edge, known bool) {
	tunnelMu.RLock()
	defer tunnelMu.RUnlock()
	edge, known = tunnelEdges[name]
	return
}

// fileConfig / envConfig carry optionality for the LAN flag.
type fileConfig struct {
	Config
	LANConnectionsOpt *bool `json:"lan_connections"`
}

// Load reads path (optional, "" = no file) and environment via lookup (injectable for
// tests; production passes os.LookupEnv). Precedence: env > file > defaults.
func Load(path string, lookup func(string) (string, bool)) (*Config, error) {
	// defaults (SPEC §2.2, §2.5, §11.1, §12.2)
	c := Config{
		DataDir:      "./data",
		PublicBind:   ":8443",
		InternalBind: "127.0.0.1:8080",
		Mode:         ModeDirect,
		Seal:         SealRequired,
		ClientCert:   ClientCertPreferred,
		StoreEngine:  "sqlite",
		WalletURL:    DefaultWalletURL,

		AuditArchiveAfter: DefaultAuditArchiveAfter,
	}
	var lanOpt *bool
	var filePinned map[string]bool

	// file layer
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config file: %w", err)
		}
		var fc fileConfig
		fc.Config = c
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fc); err != nil {
			return nil, fmt.Errorf("config file %s: %w", path, err)
		}
		c = fc.Config
		lanOpt = fc.LANConnectionsOpt

		// Remember which owner-settable knobs the FILE set. Decoding into the
		// struct cannot tell a value the operator wrote from a default, and
		// without that distinction a row in the database silently outranks a
		// compose file — the inversion SPEC §12.2 forbids. The setting keys and
		// the JSON field names are the same strings by construction.
		var present map[string]json.RawMessage
		if err := json.Unmarshal(raw, &present); err != nil {
			return nil, fmt.Errorf("config file %s: %w", path, err)
		}
		filePinned = map[string]bool{}
		for _, k := range ownerSettableEnv {
			if _, ok := present[k.key]; ok {
				filePinned[k.key] = true
			}
		}
	}

	// env layer (HDTP_* — SPEC §12.2)
	envStr := func(key string, dst *string) {
		if v, ok := lookup(key); ok {
			*dst = v
		}
	}
	envStr("HDTP_DATA_DIR", &c.DataDir)
	envStr("HDTP_PUBLIC_BIND", &c.PublicBind)
	envStr("HDTP_PUBLIC_URL", &c.PublicURL)
	envStr("HDTP_INTERNAL_BIND", &c.InternalBind)
	envStr("HDTP_INTERNAL_HOST", &c.InternalHost)
	envStr("HDTP_INTERNAL_TLS_CERT", &c.InternalTLSCert)
	envStr("HDTP_INTERNAL_TLS_KEY", &c.InternalTLSKey)
	envStr("HDTP_STORE_ENGINE", &c.StoreEngine)
	envStr("HDTP_POSTGRES_DSN", &c.PostgresDSN)
	envStr("HDTP_MASTER_KEY_FILE", &c.MasterKeyFile)
	envStr("HDTP_BLOB_DIR", &c.BlobDir)
	envStr("HDTP_TUNNEL", &c.Tunnel)
	envStr("HDTP_WALLET_URL", &c.WalletURL)
	envStr("HDTP_AUDIT_ARCHIVE_AFTER", &c.AuditArchiveAfter)
	envStr("HDTP_LIMITS_SOCKET", &c.LimitsSocket)
	envStr("HDTP_PROXY_ADDRESS", &c.ProxyAddress)
	if v, ok := lookup("HDTP_MODE"); ok {
		c.Mode = Mode(v)
	}
	if v, ok := lookup("HDTP_SEAL"); ok {
		c.Seal = Seal(v)
	}
	if v, ok := lookup("HDTP_CLIENT_CERT"); ok {
		c.ClientCert = ClientCert(v)
	}
	if v, ok := lookup("HDTP_INTERNAL_AUTH_ENABLED"); ok {
		c.InternalAuthEnabled = v == "true" || v == "1"
	}
	if v, ok := lookup("HDTP_LIMIT_CONTACTS"); ok {
		c.LimitContacts = atoiOrZero(v)
	}
	if v, ok := lookup("HDTP_LAN_CONNECTIONS"); ok {
		b := v == "true" || v == "1"
		lanOpt = &b
	}
	// Remember what the environment pinned. The portal may not change these —
	// environment beats everything below it (SPEC §12.2) — and the settings page
	// renders them locked WITH the reason rather than letting the owner save a
	// value that will not take effect.
	c.EnvPinned = map[string]bool{}
	for _, k := range ownerSettableEnv {
		if _, ok := lookup(k.env); ok {
			c.EnvPinned[k.key] = true
		}
	}
	c.FilePinned = filePinned
	if c.FilePinned == nil {
		c.FilePinned = map[string]bool{}
	}
	c.lanExplicit = lanOpt

	if err := c.Derive(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ownerSettableEnv is the map between a portal setting and the environment
// variable that would pin it.
var ownerSettableEnv = []struct{ key, env string }{
	{"public_url", "HDTP_PUBLIC_URL"},
	{"tunnel", "HDTP_TUNNEL"},
	{"seal", "HDTP_SEAL"},
	{"client_cert", "HDTP_CLIENT_CERT"},
	{"lan_connections", "HDTP_LAN_CONNECTIONS"},
	{"limit.contacts", "HDTP_LIMIT_CONTACTS"},
}

// OwnerSettableKeys are the knobs the portal may write (SPEC §8.2). Everything
// else — data dir, binds, store engine, master key — is bootstrap: it decides
// where the node's state lives, so it cannot come from that state.
func OwnerSettableKeys() []string {
	out := make([]string, 0, len(ownerSettableEnv))
	for _, k := range ownerSettableEnv {
		out = append(out, k.key)
	}
	return out
}

// Derive applies the rules that depend on the resolved values, and validates.
// It runs after every layer — file, environment, and the store overlay — so a
// knob set in the portal goes through exactly the same derivation an
// environment variable would (SPEC §10.1).
func (c *Config) Derive() error {
	lanOpt := c.lanExplicit

	// SPEC §10.1: an inbound tunnel adapter DERIVES the mode; an edge adapter
	// forces seal=required and client_cert=off (never merely validates them).
	if c.Tunnel != "" && c.Tunnel != "direct" {
		edge, ok := tunnelTerminatesAtEdge(c.Tunnel)
		if !ok {
			return fmt.Errorf("%s: tunnel %q is not a registered adapter", RuleEnum, c.Tunnel)
		}
		if edge {
			c.Mode = ModeEdge
			c.Seal = SealRequired
			c.ClientCert = ClientCertOff
		} else {
			c.Mode = ModeDirect
		}
	}

	if err := c.validate(); err != nil {
		return err
	}

	// derive the LAN flag default from the mode (SPEC §2.5, §10.1)
	if lanOpt != nil {
		c.LANConnections = *lanOpt
	} else {
		c.LANConnections = c.Mode == ModeDirect
	}
	return nil
}

func (c *Config) validate() error {
	switch c.Mode {
	case ModeDirect, ModeEdge:
	default:
		return fmt.Errorf("%s: mode %q (want direct|edge)", RuleEnum, c.Mode)
	}
	switch c.Seal {
	case SealNone, SealOptional, SealRequired:
	default:
		return fmt.Errorf("%s: seal %q (want none|optional|required)", RuleEnum, c.Seal)
	}
	switch c.ClientCert {
	case ClientCertRequired, ClientCertPreferred, ClientCertOff:
	default:
		return fmt.Errorf("%s: client_cert %q (want required|preferred|off)", RuleEnum, c.ClientCert)
	}

	// SPEC §2.2/§8.3: any non-loopback internal bind refuses to start unless passkey
	// auth AND TLS are configured. Startup invariant, not a per-request check.
	if !isLoopbackBind(c.InternalBind) {
		if !c.InternalAuthEnabled || c.InternalTLSCert == "" || c.InternalTLSKey == "" {
			return fmt.Errorf("%s: internal bind %q is not loopback; it requires internal_auth_enabled plus internal_tls_cert and internal_tls_key",
				RuleInternalBindAuth, c.InternalBind)
		}
	}

	if _, err := ParseAuditArchiveAfter(c.AuditArchiveAfter); err != nil {
		return fmt.Errorf("%s: audit_archive_after: %v", RuleRange, err)
	}

	if err := validWalletURL(c.WalletURL); err != nil {
		return fmt.Errorf("%s: wallet_url %q: %v", RuleWalletURL, c.WalletURL, err)
	}

	if c.ProxyAddress != "" && net.ParseIP(c.ProxyAddress) == nil {
		return fmt.Errorf("%s: proxy_address %q is not an IP address", RuleProxyAddress, c.ProxyAddress)
	}

	if c.StoreEngine == "postgres" && c.PostgresDSN == "" {
		return fmt.Errorf("%s: store_engine postgres needs postgres_dsn", RulePostgresDSN)
	}

	// SPEC §2.5: mode-forced knobs — a contradiction is a refused config, so the owner
	// can never run an edge with the seal down.
	if c.Mode == ModeEdge {
		if c.Seal != SealRequired {
			return fmt.Errorf("%s: edge mode forces seal=required, got %q", RuleEdgeSeal, c.Seal)
		}
		if c.ClientCert != ClientCertOff {
			return fmt.Errorf("%s: edge mode forces client_cert=off, got %q", RuleEdgeClientCert, c.ClientCert)
		}
	}
	// A non-loopback portal must name the host it is served at, or no WebAuthn
	// ceremony can ever succeed: the relying party is derived from the request's
	// host against an allow-list, and with no configured name every host is
	// refused. Without this the node starts cleanly and cannot be logged into.
	if !isLoopbackBind(c.InternalBind) && c.InternalHost == "" {
		return fmt.Errorf("%s: a non-loopback internal_bind needs internal_host — "+
			"the hostname the portal is served at, which passkeys are bound to", RuleInternalHost)
	}
	return nil
}

// isLoopbackBind reports whether a host:port bind address can only accept loopback
// traffic: an IP in a loopback range, or the literal "localhost". An empty host means
// every interface and is therefore NOT loopback.
// IsLoopbackBind reports whether a bind address is loopback-only. SPEC §8.3
// makes this the authentication decision, so it is exported: the portal captures
// it once at startup rather than re-deriving the rule.
func IsLoopbackBind(bind string) bool { return isLoopbackBind(bind) }

func isLoopbackBind(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// DefaultWalletURL is the web wallet a portal sends a signing request to when nothing else is
// configured: the ceremony host on the protocol's own domain. It is a fixed host, and is not
// derived from any hosting product's addresses.
const DefaultWalletURL = "https://ceremony.hdtp.io"

// validWalletURL holds wallet_url to an origin a form may be sent to: https, or http to a loopback
// host (a wallet under test on this machine). It is written into the portal's Content-Security-Policy
// as the signing page's form-action origin, so it is held to a strict grammar and not only to what
// url.Parse accepts: a lower-case scheme, "://", a host that is a DNS name (letters, digits, hyphens
// and dots), a dotted quad or a bracketed IPv6 literal, an optional port of 1 to 65535, and at most a
// trailing slash. Nothing that could end a CSP source or start another (`;`, `'`, a space, `*`)
// gets through.
func validWalletURL(raw string) error {
	m := walletOrigin.FindStringSubmatch(raw)
	if m == nil {
		return fmt.Errorf("want an origin, scheme://host[:port], and nothing after it")
	}
	scheme, host, port := m[1], m[2], m[3]
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || port[0] == '0' {
			return fmt.Errorf("the port %q is not 1 to 65535", port)
		}
	}
	if strings.HasPrefix(host, "[") && net.ParseIP(strings.Trim(host, "[]")) == nil {
		return fmt.Errorf("the host %q is not an IPv6 literal", host)
	}
	switch scheme {
	case "https":
		return nil
	default: // http
		h := strings.Trim(host, "[]")
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("http is for a wallet on this machine only; use https")
	}
}

// walletOrigin is the grammar validWalletURL holds wallet_url to: scheme, host, port.
var walletOrigin = regexp.MustCompile(`^(https|http)://([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[[0-9a-fA-F:.]+\])(?::([0-9]{1,5}))?/?$`)

// WalletOrigin is wallet_url as the origin a browser writes (no trailing slash).
func (c *Config) WalletOrigin() string { return strings.TrimRight(c.WalletURL, "/") }

// Blobs is the directory inline media is stored in: BlobDir, or <data_dir>/blobs.
func (c *Config) Blobs() string {
	if c.BlobDir != "" {
		return c.BlobDir
	}
	return filepath.Join(c.DataDir, "blobs")
}
