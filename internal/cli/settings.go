package cli

// The owner-set configuration layer (SPEC §8.2, §12.2): read from the store at
// startup, layered UNDER the environment, and written back by the portal.
//
// Two properties are worth stating because they are easy to lose:
//
//   - A saved knob either takes effect now or says it does not. `seal`,
//     `public_url` and the LAN flag are pushed into the running node; the rest
//     own a socket or a goroutine and are marked restart-scoped in the page.
//   - A secret goes in and never comes back out. Adapter credentials are sealed
//     with the node's keyring before they touch the database, and the read path
//     that renders settings never decrypts them.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/internalui"
	"github.com/tech-sumit/pact-gateway/internal/node"
	"github.com/tech-sumit/pact-gateway/internal/public"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
)

// settingAAD binds a sealed setting to its column, per the keyring AAD rule.
const settingAAD = "settings.value"

// relayRecipients reports the recipient list the relay should honour right now.
func (s *settingsService) relayRecipients() []string {
	var out []string
	s.readCfg(func(c *core.Config) { out = append([]string(nil), c.RelayRecipients...) })
	return out
}

// settingsAAD is the same value for callers outside this package. Anything that
// writes a secret row in the `settings` table MUST seal it with this: the one
// decrypting reader opens every secret row there with it, and a mismatch fails
// startup rather than the read.
func settingsAAD() []byte { return []byte(settingAAD) }

// isSecretKey decides what gets encrypted at rest. It errs toward secrecy: a
// key that merely LOOKS like a credential is sealed, because the cost of
// sealing something harmless is nothing and the cost of the reverse is a
// credential in a database dump.
func isSecretKey(key string) bool {
	last := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		last = key[i+1:]
	}
	// Case-INSENSITIVE, and it has to be: a supervised child's credentials are
	// stored as `integration.<slug>.env.<NAME>` and environment variable names are
	// uppercase by universal convention — CALDAV_PASSWORD, GITHUB_TOKEN, API_KEY.
	// Against lowercase markers a case-sensitive match found none of them, so every
	// one was written to the settings table in the clear, and into every backup of
	// it, while this comment claimed the opposite.
	last = strings.ToLower(last)
	for _, marker := range []string{"token", "key", "secret", "password", "auth",
		// `credential` and `passwd` are common enough to be worth naming; the cost
		// of sealing something harmless is still nothing.
		"credential", "passwd", "apikey", "pat"} {
		if strings.Contains(last, marker) {
			return true
		}
	}
	return false
}

// encodeSealed is how a sealed value is stored: base64 of the keyring ciphertext.
func encodeSealed(sealed []byte) string { return base64.StdEncoding.EncodeToString(sealed) }

// settingsService owns the read and write paths for owner-set configuration.
type settingsService struct {
	store store.Store
	kr    *core.Keyring
	// cfg is SHARED with every portal handler: one goroutine saves while others
	// render. The node guards its own live knobs; this copy needs the same
	// treatment, or a save concurrent with a render is a torn string read.
	cfgMu sync.RWMutex
	cfg   *core.Config
	node  *node.Node
	audit func(action, resource, outcome string)
	now   func() time.Time
}

// withCfg runs fn under the read lock and returns what it produced.
func (s *settingsService) readCfg(fn func(c *core.Config)) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	fn(s.cfg)
}

// writeCfg mutates the shared config under the write lock.
func (s *settingsService) writeCfg(fn func(c *core.Config)) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	fn(s.cfg)
}

func (s *settingsService) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// values returns every stored setting with secrets decrypted — the startup
// path, and the only place that decrypts.
func (s *settingsService) values(ctx context.Context) (map[string]string, error) {
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		if !r.Secret {
			out[r.Key] = r.Value
			continue
		}
		sealed, err := base64.StdEncoding.DecodeString(r.Value)
		if err != nil {
			return nil, fmt.Errorf("settings: %s is corrupt", r.Key)
		}
		plain, err := s.kr.Decrypt(sealed, []byte(settingAAD))
		if err != nil {
			// A dotted key is adapter or integration data: one unreadable row
			// must not stop the node from starting, because the portal is the
			// only place an owner can repair it and the portal needs the node.
			// A TOP-LEVEL knob is different — those decide seal policy, client
			// certificates and reachability, and starting while unable to read
			// one would mean serving under a posture nobody chose.
			if strings.Contains(r.Key, ".") {
				s.audit("settings_unreadable", "key:"+r.Key, "skipped")
				continue
			}
			return nil, fmt.Errorf("settings: %s cannot be opened with this keyring", r.Key)
		}
		out[r.Key] = string(plain)
	}
	return out, nil
}

// resealLegacySecrets re-encrypts settings rows that SHOULD be sealed but are not.
//
// isSecretKey was case-sensitive, so credentials stored under uppercase names —
// which is every environment variable a supervised child takes, CALDAV_PASSWORD
// and GITHUB_TOKEN and the rest — were written in the clear. Fixing the predicate
// only helps the next write; a credential already in the table stays exposed
// until something rewrites it, and expecting an owner to notice and re-enter it
// is not a security control.
//
// Idempotent, and quiet when there is nothing to do. A row that cannot be
// re-sealed is left exactly as it was and reported: a half-converted settings
// table would be worse than an unconverted one.
func (s *settingsService) resealLegacySecrets(ctx context.Context) (int, error) {
	if s.kr == nil {
		return 0, nil
	}
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return 0, err
	}
	sealed := 0
	for _, r := range rows {
		if r.Secret || !isSecretKey(r.Key) || r.Value == "" {
			continue
		}
		blob, err := s.kr.Encrypt([]byte(r.Value), []byte(settingAAD))
		if err != nil {
			s.audit("settings_reseal", "key:"+r.Key, "error")
			return sealed, fmt.Errorf("settings: could not seal %s: %w", r.Key, err)
		}
		if err := s.store.PutSetting(ctx, store.Setting{
			Key: r.Key, Value: encodeSealed(blob), Secret: true, UpdatedAt: s.clock().Unix(),
		}); err != nil {
			s.audit("settings_reseal", "key:"+r.Key, "error")
			return sealed, err
		}
		// The key is audited; the value never is.
		s.audit("settings_reseal", "key:"+r.Key, "sealed")
		sealed++
	}
	return sealed, nil
}

// plainValues returns the stored NON-secret settings. It is the render path:
// it never decrypts, so a secret cannot reach a template through it.
func (s *settingsService) plainValues(ctx context.Context) (map[string]string, error) {
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		if r.Secret || strings.Contains(r.Key, ".") {
			continue
		}
		out[r.Key] = r.Value
	}
	return out, nil
}

// MaxRetentionDays bounds a retention window at 100 years — far past any real
// policy, and safely inside what a time.Duration can represent.
const MaxRetentionDays = 36500

// StorageKeyQuota and StorageKeyRetention are the dotted per-account keys.
// `core.Config` has no account dimension, and dotted keys are ignored by
// ApplyStoreSettings by design — the same seam adapter settings use.
func StorageKeyQuota(accountID string) string     { return "storage.quota." + accountID }
func StorageKeyRetention(accountID string) string { return "storage.retention." + accountID }

// storageFor reads one account's quota (bytes) and retention window. Zero means
// the default quota and unlimited retention respectively (SPEC §7.4, §7.9).
func (s *settingsService) storageFor(ctx context.Context, accountID string) (quota int64, retention time.Duration) {
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return 0, 0
	}
	for _, r := range rows {
		switch r.Key {
		case StorageKeyQuota(accountID):
			if v, err := strconv.ParseInt(r.Value, 10, 64); err == nil {
				quota = v
			}
		case StorageKeyRetention(accountID):
			// Bounded deliberately: `time.Duration(days) * 24h` overflows past
			// ~106751 days, and some large values wrap to a SMALL POSITIVE
			// duration — a typo of 213504 would have meant "delete everything
			// older than 25 minutes" while the page said 213504 days.
			if v, err := strconv.Atoi(r.Value); err == nil && v > 0 && v <= MaxRetentionDays {
				retention = time.Duration(v) * 24 * time.Hour
			}
		}
	}
	return quota, retention
}

// adapterSettings lists stored adapter keys WITHOUT their values.
func (s *settingsService) adapterSettings(ctx context.Context) ([]internalui.AdapterSetting, error) {
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	var out []internalui.AdapterSetting
	for _, r := range rows {
		if !strings.HasPrefix(r.Key, "tunnel.") {
			continue
		}
		out = append(out, internalui.AdapterSetting{Key: r.Key, Secret: r.Secret, Set: r.Value != ""})
	}
	return out, nil
}

// save persists one knob and applies whatever part of it can take effect now.
func (s *settingsService) save(ctx context.Context, key, value string) error {
	if err := core.ValidateSetting(key, value); err != nil {
		return err
	}
	stored, secret := value, isSecretKey(key)
	if secret {
		sealed, err := s.kr.Encrypt([]byte(value), []byte(settingAAD))
		if err != nil {
			return err
		}
		stored = encodeSealed(sealed)
	}
	if err := s.store.PutSetting(ctx, store.Setting{
		Key: key, Value: stored, Secret: secret, UpdatedAt: s.clock().Unix(),
	}); err != nil {
		return err
	}
	return s.applyLive(ctx, key, value)
}

// applyLive pushes a saved knob into the running node where that is possible.
// Anything not handled here is restart-scoped, and the page says so.
func (s *settingsService) applyLive(ctx context.Context, key, value string) error {
	if s.node == nil {
		return nil
	}
	switch key {
	case "limit.contact_per_hour":
		// The limiter asks for the budget on every call, so writing the resolved
		// config is the whole of applying it.
		s.writeCfg(func(c *core.Config) { c.LimitContactPerHour = core.ParseCount(value) })
	case "limit.guest_per_hour":
		s.writeCfg(func(c *core.Config) { c.LimitGuestPerHour = core.ParseCount(value) })
	case "seal":
		// The node config holds the default; every account carries the value
		// its card advertises, so both move together and the card can never
		// disagree with the gate (SPEC §4.6).
		s.writeCfg(func(c *core.Config) { c.Seal = core.Seal(value) })
		accounts, err := s.store.ListAccounts(ctx)
		if err != nil {
			return err
		}
		for _, a := range accounts {
			if err := s.node.SetSeal(ctx, a.ID, core.Seal(value)); err != nil {
				return err
			}
		}
	case "relay_recipients":
		// Applies LIVE. The relay reads this through a function rather than a
		// snapshot, so narrowing the list takes effect on the next registration
		// AND the next relay_call — which is what makes it safe to narrow at all
		// (P13-01), and is the whole point of it being a portal knob rather than
		// a config-file edit (P14-13).
		list := core.SplitRecipients(value)
		for _, f := range list {
			if !strings.HasPrefix(f, "sha256:") {
				return fmt.Errorf("settings: %q is not a PACT §2 fingerprint", f)
			}
		}
		s.writeCfg(func(c *core.Config) { c.RelayRecipients = list })
	case "lan_connections":
		allow := value == "true"
		s.writeCfg(func(c *core.Config) { c.LANConnections = allow })
		s.node.SetLANConnections(allow)
	case "public_url":
		same := false
		s.readCfg(func(c *core.Config) { same = value == c.PublicURL })
		if same {
			return nil
		}
		s.writeCfg(func(c *core.Config) { c.PublicURL = value })
		s.node.SetPublicURL(value)
		// Contacts pinned the old endpoint; tell them (SPEC §9.4).
		//
		// This runs in the background on purpose. The change is already true
		// locally, some contacts will be offline, and a portal save that blocks
		// until every peer answers would hang on the first unreachable one. The
		// outcome goes to the audit chain, which is where a partial fan-out
		// belongs — the owner can see who was not reached.
		nd := s.node
		go func() {
			announceCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			done, failed, err := nd.AnnounceEndpointChange(announceCtx, nil)
			// The counts and the reason describe what happened, so they belong on
			// the resource; the outcome stays a verdict the portal can colour,
			// count and filter by.
			resource := fmt.Sprintf("public_url done:%d failed:%d", done, failed)
			outcome := "ok"
			if err != nil {
				resource += " why:" + core.Redact(err.Error())
				outcome = "error"
			} else if failed > 0 {
				outcome = "failed"
			}
			// A distinct action from the per-contact rows announce.go writes: this one
			// is the sweep across every account, caused by the node's own address
			// changing, and belongs to no single identity.
			s.audit("endpoint_announce_all", resource, outcome)
		}()
	}
	return nil
}

// settingsDeps builds what the page needs.
func (s *settingsService) deps() internalui.SettingsDeps {
	return internalui.SettingsDeps{
		Effective: func() []core.Effective {
			var out []core.Effective
			s.readCfg(func(c *core.Config) { out = c.EffectiveSettings() })
			return out
		},
		Save:            s.save,
		AdapterSettings: s.adapterSettings,
		Pair: func(ctx context.Context, in internalui.PairInput) (internalui.PairResult, error) {
			accts, err := s.store.ListAccounts(ctx)
			if err != nil || len(accts) == 0 {
				return internalui.PairResult{}, fmt.Errorf("create an account before pairing")
			}
			if in.Account != "" {
				for _, a := range accts {
					if a.ID == in.Account {
						return s.pair(ctx, a.ID, in)
					}
				}
				return internalui.PairResult{}, fmt.Errorf("unknown account")
			}
			if len(accts) > 1 {
				return internalui.PairResult{}, fmt.Errorf("this node has several identities — choose which one to pair")
			}
			return s.pair(ctx, accts[0].ID, in)
		},
		Accounts: func(ctx context.Context) ([]internalui.AccountChoice, error) {
			accts, err := s.store.ListAccounts(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]internalui.AccountChoice, 0, len(accts))
			for _, a := range accts {
				out = append(out, internalui.AccountChoice{ID: a.ID, Label: a.DisplayName + " (" + a.Slug + ")"})
			}
			return out, nil
		},
		Unpair: s.unpair,
		Storage: func(ctx context.Context) ([]internalui.StorageRow, error) {
			accts, err := s.store.ListAccounts(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]internalui.StorageRow, 0, len(accts))
			for _, a := range accts {
				quota, retention := s.storageFor(ctx, a.ID)
				out = append(out, internalui.StorageRow{
					AccountID: a.ID, Label: a.DisplayName + " (" + a.Slug + ")",
					QuotaGiB: quota / (1 << 30), RetentionDays: int(retention / (24 * time.Hour)),
				})
			}
			return out, nil
		},
		Presets:      s.presets,
		SavePreset:   s.savePreset,
		DeletePreset: s.deletePreset,
		SaveStorage: func(ctx context.Context, accountID string, quotaGiB int64, retentionDays int) error {
			if _, err := s.store.GetAccountByID(ctx, accountID); err != nil {
				return fmt.Errorf("unknown account")
			}
			if err := s.saveRaw(ctx, StorageKeyQuota(accountID), strconv.FormatInt(quotaGiB<<30, 10)); err != nil {
				return err
			}
			return s.saveRaw(ctx, StorageKeyRetention(accountID), strconv.Itoa(retentionDays))
		},
		Paired: s.pairedAdapters,
		Pending: func(ctx context.Context) (map[string]string, error) {
			// Only non-secret owner knobs; adapter credentials are never read
			// back for rendering.
			all, err := s.plainValues(ctx)
			if err != nil {
				return nil, err
			}
			return all, nil
		},
		Adapters: tunnel.Names(),
		Probe: func(ctx context.Context) (string, string) {
			var publicURL string
			var mode core.Mode
			s.readCfg(func(c *core.Config) { publicURL, mode = c.PublicURL, c.Mode })
			if publicURL == "" {
				return "skipped", "no public URL is configured yet"
			}
			pin := ""
			if accts, err := s.store.ListAccounts(ctx); err == nil && len(accts) > 0 && mode != core.ModeEdge {
				pin = accts[0].Fingerprint
			}
			res := tunnel.Probe(ctx, publicURL, tunnel.ProbeOptions{
				PinnedFingerprint: pin, Timeout: 5 * time.Second, SelfOriginated: true,
			})
			return string(res.Verdict), strings.TrimSpace(res.Detail + " " + res.Caveat)
		},
		Audit: s.audit,
	}
}

// rateBudget reads the per-hour call caps. Zero means PACT §12's documented
// numbers, which is what an unset knob leaves in force; the limiter treats any
// answer at or below zero as "use the default", so a bad row cannot open the
// gate.
func (s *settingsService) rateBudget(kind public.LimitKind) int {
	var n int
	s.readCfg(func(c *core.Config) {
		if kind == public.KindGuest {
			n = c.LimitGuestPerHour
			return
		}
		n = c.LimitContactPerHour
	})
	return n
}

// presets returns the owner's bundles as the editor shows them — the resolved
// set, defaults included, so the page always has something to edit.
func (s *settingsService) presets(ctx context.Context) (map[string][]string, error) {
	return contacts.LoadPresets(ctx, s.store), nil
}

// savePreset writes one bundle. The FIRST write seeds every currently-resolved
// bundle as rows, so "edit work" cannot silently delete family: from then on
// the rows are the complete set.
func (s *settingsService) savePreset(ctx context.Context, name string, perms []string) error {
	if err := contacts.ValidatePreset(name, perms); err != nil {
		return err
	}
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return err
	}
	seeded := false
	for _, r := range rows {
		if strings.HasPrefix(r.Key, contacts.PresetKeyPrefix) {
			seeded = true
			break
		}
	}
	put := func(n string, p []string) error {
		return s.store.PutSetting(ctx, store.Setting{
			Key: contacts.PresetKeyPrefix + n, Value: strings.Join(p, ","),
			UpdatedAt: s.clock().Unix(),
		})
	}
	if !seeded {
		for n, p := range contacts.LoadPresets(ctx, s.store) {
			if n == name {
				continue // the edited bundle is written below, once
			}
			if err := put(n, p); err != nil {
				return err
			}
		}
	}
	return put(name, perms)
}

// deletePreset removes one bundle. Deleting the last row restores the
// documented defaults — LoadPresets resolves an empty set that way.
func (s *settingsService) deletePreset(ctx context.Context, name string) error {
	return s.store.DeleteSetting(ctx, contacts.PresetKeyPrefix+name)
}
