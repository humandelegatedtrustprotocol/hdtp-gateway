package core

// Owner-set configuration (SPEC §8.2, §12.2). The portal writes here; the node
// reads it once at startup, layers it UNDER the environment, and re-derives.
//
// Precedence is unchanged from §12.2 — environment > file > defaults — with the
// store slotted in as a fourth layer between file and defaults for the knobs an
// owner can set. That ordering is deliberate: an operator who pins `PACT_SEAL`
// in a compose file must not have it silently overridden by a row in a database,
// and the portal must not offer a switch that does nothing. A knob the
// environment pinned is reported through Config.EnvPinned so the page can render
// it locked, with the reason.

import (
	"fmt"
	"strconv"
	"strings"
)

// ApplyStoreSettings layers owner-set values under the environment and
// re-derives. Values the environment pinned are skipped, not overwritten.
func (c *Config) ApplyStoreSettings(values map[string]string) error {
	if c.EnvPinned == nil {
		c.EnvPinned = map[string]bool{}
	}
	for key, raw := range values {
		if c.EnvPinned[key] {
			continue // the environment wins (SPEC §12.2)
		}
		if c.FilePinned[key] {
			continue // the configuration file wins over the store (SPEC §12.2)
		}
		v := strings.TrimSpace(raw)
		switch key {
		case "public_url":
			c.PublicURL = v
		case "tunnel":
			c.Tunnel = v
		case "seal":
			c.Seal = Seal(v)
		case "client_cert":
			c.ClientCert = ClientCert(v)
		case "lan_connections":
			b := v == "true" || v == "1"
			c.lanExplicit = &b
		case "limit.contact_per_hour":
			c.LimitContactPerHour = atoiOrZero(v)
		case "limit.guest_per_hour":
			c.LimitGuestPerHour = atoiOrZero(v)
		default:
			// Adapter settings (`tunnel.<adapter>.<key>`) and anything else are
			// not config fields; they are read by whoever needs them.
			if !strings.Contains(key, ".") {
				return fmt.Errorf("settings: unknown key %q", key)
			}
		}
	}
	return c.Derive()
}

// Effective reports the resolved value of one owner-settable knob, together
// with whether it can still be changed and why not. The settings page renders
// exactly this — no second opinion about what is locked.
type Effective struct {
	Key    string
	Value  string
	Locked bool
	Reason string
}

// EffectiveSettings resolves every owner-settable knob against the environment
// and the mode the active adapter derived.
func (c *Config) EffectiveSettings() []Effective {
	edge := c.Mode == ModeEdge
	lock := func(cond bool, reason string) (bool, string) {
		if cond {
			return true, reason
		}
		return false, ""
	}
	out := []Effective{}
	add := func(key, value string, locked bool, reason string) {
		switch {
		case c.EnvPinned[key]:
			locked, reason = true, "pinned by the environment ("+envFor(key)+"); the environment wins over the portal (SPEC §12.2)"
		case c.FilePinned[key]:
			locked, reason = true, "pinned by the configuration file; the file wins over the portal (SPEC §12.2)"
		}
		out = append(out, Effective{Key: key, Value: value, Locked: locked, Reason: reason})
	}
	add("public_url", c.PublicURL, false, "")
	add("tunnel", c.Tunnel, false, "")

	sealLocked, sealReason := lock(edge,
		"forced to `required` in edge mode: caller identity can only arrive as an envelope signature (SPEC §2.5)")
	add("seal", string(c.Seal), sealLocked, sealReason)

	certLocked, certReason := lock(edge,
		"forced to `off` in edge mode: a terminating edge never delivers the caller's certificate (SPEC §2.5)")
	add("client_cert", string(c.ClientCert), certLocked, certReason)

	lanLocked, lanReason := lock(c.Tunnel == "" || c.Tunnel == "direct",
		"inert without an active tunnel adapter: with no tunnel there is no non-tunnel source to refuse (SPEC §5.1)")
	add("lan_connections", boolStr(c.LANConnections), lanLocked, lanReason)

	add("limit.contact_per_hour", intStr(c.LimitContactPerHour), false, "")
	add("limit.guest_per_hour", intStr(c.LimitGuestPerHour), false, "")
	return out
}

// RestartScoped names the knobs that own a socket or a goroutine and therefore
// take effect on the next start. The page says so next to them rather than
// implying a change is live.
func RestartScoped(key string) bool {
	switch key {
	case "tunnel", "relay", "gateway_url", "gateway_fingerprint", "client_cert":
		return true
	}
	return false
}

func envFor(key string) string {
	for _, k := range ownerSettableEnv {
		if k.key == key {
			return k.env
		}
	}
	return ""
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ValidateSetting rejects a value the resolver would refuse later, so the page
// can say why instead of saving something that breaks the next start.
func ValidateSetting(key, value string) error {
	switch key {
	case "seal":
		switch Seal(value) {
		case SealNone, SealOptional, SealRequired:
		default:
			return fmt.Errorf("%s: seal must be none|optional|required", RuleEnum)
		}
	case "client_cert":
		switch ClientCert(value) {
		case ClientCertRequired, ClientCertPreferred, ClientCertOff:
		default:
			return fmt.Errorf("%s: client_cert must be required|preferred|off", RuleEnum)
		}
	case "tunnel":
		if value == "" || value == "direct" {
			return nil
		}
		if _, ok := tunnelTerminatesAtEdge(value); !ok {
			return fmt.Errorf("%s: %q is not a registered tunnel adapter", RuleEnum, value)
		}
	case "public_url", "gateway_url":
		if value != "" && !strings.HasPrefix(value, "https://") {
			return fmt.Errorf("%s: %s must be an https:// URL", RuleEnum, key)
		}
	case "gateway_fingerprint":
		if value != "" && !strings.HasPrefix(value, "sha256:") {
			return fmt.Errorf("%s: a fingerprint looks like sha256:…", RuleEnum)
		}
	case "lan_connections", "relay":
		if value != "true" && value != "false" {
			return fmt.Errorf("%s: %s is true or false", RuleEnum, key)
		}
	case "limit.contact_per_hour", "limit.guest_per_hour":
		// PACT §12's caps are the defaults, not a ceiling: a pair of busy agents
		// can legitimately exceed 60 calls an hour, and an operator who cannot
		// raise the number has to choose between recompiling and being throttled.
		// Empty restores the documented value.
		if value == "" {
			return nil
		}
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			return fmt.Errorf("%s: %s is a positive number of calls per hour", RuleRange, key)
		}
	}
	return nil
}

// EffectiveSeal is the ONE answer to "does this account require sealing?".
//
// It exists because there are two places the policy could be read from — the
// account row, which the card advertises as `X-PACT-SEAL`, and the node config,
// which the gate used to enforce — and a card advertising `required` while the
// gate accepts plaintext is a wire-visible lie. Both now call this.
//
// The policy is node-wide: one setting, mirrored into every account row so the
// card advertises what the gate enforces. A deployment mode that cannot carry
// certificate identity overrides it (SPEC §2.5). Per-account divergence is not
// v1 — the schema keeps the column, and nothing here reads it, so the two can
// never drift.
func EffectiveSeal(mode Mode, nodeSeal Seal) Seal {
	if mode == ModeEdge {
		return SealRequired
	}
	switch nodeSeal {
	case SealNone, SealOptional, SealRequired:
		return nodeSeal
	}
	return SealRequired
}

// ParseCount is atoiOrZero's exported name, for the wiring layer that has to
// apply the same knob to the running node.
func ParseCount(v string) int { return atoiOrZero(v) }

// atoiOrZero reads a count, treating anything unreadable as "unset". A knob that
// cannot be parsed must fall back to the documented default, never to zero
// meaning "no limit" — a typo in a budget must not remove the budget.
func atoiOrZero(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// intStr renders a count for the settings page; zero shows as empty, which is
// what "the documented default is in force" looks like to an owner.
func intStr(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}
