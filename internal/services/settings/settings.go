// Package settings is the owner-set configuration layer (SPEC §8.2, §12.2): read from the store at
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
package settings

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/tunnel"
)

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

// Service owns the read and write paths for owner-set configuration.
type Service struct {
	store store.Store
	kr    *core.Keyring
	// cfg is SHARED with every portal handler: one goroutine saves while others
	// render. The node guards its own live knobs; this copy needs the same
	// treatment, or a save concurrent with a render is a torn string read.
	cfgMu sync.RWMutex
	cfg   *core.Config
	node  *node.Node
	bus   *messaging.Bus
	// follow is Follow's subscription, made when the bus is attached so a setting saved elsewhere
	// before Follow starts is not missed.
	follow   <-chan messaging.Event
	unfollow func()
	audit    func(action, resource, outcome string)
	now      func() time.Time
}

// New is the settings service over the store, sealing secret rows with kr, sharing cfg with the
// portal, and auditing what the owner saves through audit.
func New(st store.Store, kr *core.Keyring, cfg *core.Config, audit func(action, resource, outcome string)) *Service {
	return &Service{store: st, kr: kr, cfg: cfg, audit: audit}
}

// AttachNode gives the service the running node, so a saved knob that can take effect live does.
// Until it is attached, a save is stored and applied at the next start.
func (s *Service) AttachNode(nd *node.Node) { s.node = nd }

// AttachBus gives the service the node's events: a knob saved here is announced to every other
// node process on the store (SPEC §11.1), and Follow applies what they save.
func (s *Service) AttachBus(bus *messaging.Bus) {
	s.bus = bus
	s.follow, s.unfollow = bus.SubscribeSized("", 256)
}

// SealPolicy is the seal the owner set for the node, as this process has it now: what an account
// is built with (node.Options.SealPolicy).
func (s *Service) SealPolicy() core.Seal {
	var seal core.Seal
	s.readCfg(func(c *core.Config) { seal = c.Seal })
	return seal
}

// Follow applies the settings other node processes on the store save, until ctx ends: each is
// read back from the store and applied as the process that saved it applied it, except for what
// that process already did for every process — its audit rows, and each account's seal, which
// every process reloads from the account's row. serve runs it in its joined background group.
func (s *Service) Follow(ctx context.Context) {
	if s.follow == nil {
		return
	}
	evs := s.follow
	defer s.unfollow()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-evs:
			if e.Local || e.Kind != messaging.EventSettings {
				continue
			}
			values, err := s.Values(ctx)
			if err != nil {
				continue // the next save, or a restart, applies it
			}
			if v, ok := values[e.Ref]; ok {
				_ = s.apply(ctx, e.Ref, v, false)
			}
		}
	}
}

// readCfg runs fn under the read lock.
func (s *Service) readCfg(fn func(c *core.Config)) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	fn(s.cfg)
}

// writeCfg mutates the shared config under the write lock.
func (s *Service) writeCfg(fn func(c *core.Config)) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	fn(s.cfg)
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Values returns every stored setting with secrets decrypted — the startup
// path, and the only place that decrypts.
func (s *Service) Values(ctx context.Context) (map[string]string, error) {
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
		plain, err := s.kr.Decrypt(sealed, core.SettingsAAD())
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

// plainValues returns the stored NON-secret settings. It is the render path:
// it never decrypts, so a secret cannot reach a template through it.
func (s *Service) plainValues(ctx context.Context) (map[string]string, error) {
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

// ContactsKeyRequestExpiry is the per-account key for how long an unanswered request waits.
func ContactsKeyRequestExpiry(accountID string) string { return "contacts.request_expiry." + accountID }

// AccountKeys is every settings key that belongs to one account: what an identity leaving this
// host erases with it (identity.Manager.Leave). A new per-account key function belongs here too;
// TestAccountKeysNamesEveryPerAccountKey holds the two to each other.
func AccountKeys(accountID string) []string {
	return []string{StorageKeyQuota(accountID), StorageKeyRetention(accountID), ContactsKeyRequestExpiry(accountID)}
}

// RequestExpiryFor is how long an unanswered request of this account waits before it expires
// (SPEC §9.1): the owner's setting when it is within bounds, else the default thirty days.
func (s *Service) RequestExpiryFor(ctx context.Context, accountID string) time.Duration {
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return contacts.DefaultRequestExpiry
	}
	for _, r := range rows {
		if r.Key != ContactsKeyRequestExpiry(accountID) {
			continue
		}
		if v, err := strconv.Atoi(r.Value); err == nil && v >= 1 && v <= internalui.MaxRequestExpiryDays {
			return time.Duration(v) * 24 * time.Hour
		}
	}
	return contacts.DefaultRequestExpiry
}

// StorageFor reads one account's quota (bytes) and retention window. Zero means
// the default quota and unlimited retention respectively (SPEC §7.4, §7.9).
func (s *Service) StorageFor(ctx context.Context, accountID string) (quota int64, retention time.Duration) {
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
func (s *Service) adapterSettings(ctx context.Context) ([]internalui.AdapterSetting, error) {
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
func (s *Service) save(ctx context.Context, key, value string) error {
	if err := core.ValidateSetting(key, value); err != nil {
		return err
	}
	stored, secret := value, isSecretKey(key)
	if secret {
		sealed, err := s.kr.Encrypt([]byte(value), core.SettingsAAD())
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
	if err := s.apply(ctx, key, value, true); err != nil {
		return err
	}
	if s.bus != nil {
		s.bus.Publish(messaging.Event{Kind: messaging.EventSettings, Ref: key})
	}
	return nil
}

// apply pushes a saved knob into the running node where that is possible. Anything not handled
// here is restart-scoped, and the page says so. here says whether this process saved it: one that
// did audits and re-seals every account; one that learned of it from another process (Follow)
// takes the value alone, since the saving process did the rest for every process.
func (s *Service) apply(ctx context.Context, key, value string, here bool) error {
	if s.node == nil {
		return nil
	}
	switch key {
	case "limit.contacts":
		// The cap and the limiter ask for it on every use, so writing the resolved config is the
		// whole of applying it.
		s.writeCfg(func(c *core.Config) { c.LimitContacts = core.ParseCount(value) })
	case "seal":
		// The node config holds the default; every account carries the value
		// its card advertises, so both move together and the card can never
		// disagree with the gate (SPEC §4.6).
		s.writeCfg(func(c *core.Config) { c.Seal = core.Seal(value) })
		if !here {
			return nil
		}
		accounts, err := s.store.ListAccounts(ctx)
		if err != nil {
			return err
		}
		for _, a := range accounts {
			if err := s.node.SetSeal(ctx, a.ID, core.Seal(value)); err != nil {
				return err
			}
		}
	case "lan_connections":
		allow := value == "true"
		s.writeCfg(func(c *core.Config) { c.LANConnections = allow })
		if !here {
			s.node.UseLANConnections(allow)
			return nil
		}
		s.node.SetLANConnections(allow)
	case "public_url":
		old := ""
		s.readCfg(func(c *core.Config) { old = c.PublicURL })
		if value == old {
			return nil
		}
		s.writeCfg(func(c *core.Config) { c.PublicURL = value })
		if !here {
			s.node.UsePublicURL(value)
			return nil
		}
		s.node.SetPublicURL(value)
		// Nobody is told, because nothing has moved. An address is inside a leaf: every account
		// still answers at the endpoint its wallet signed, and goes on doing so until the wallet
		// signs a leaf for the new one. What HAS changed is that the accounts certified for the
		// old derived address are now certified for an address this node no longer advertises,
		// and each needs a move — so they are named, here and on `doctor` and the `serve` banner.
		//
		// This used to fan `update_contact{card, sig}` out to every contact of every account,
		// with a signature over the account's own fingerprint as "proof". That was the retired
		// generation's endpoint announcement (node/announce.go says what became of it): under HDTP it sent each contact
		// the card it already held, and started nothing that moves an address.
		accounts, err := s.store.ListAccounts(ctx)
		if err != nil {
			return err
		}
		for _, a := range accounts {
			at := LeafAddress(ctx, s.store, a.ID)
			to := identity.EndpointFor(value, a.Slug)
			if at == "" || at == to || at != identity.EndpointFor(old, a.Slug) {
				continue // no leaf; already there; or certified for an address of its own, not the node's
			}
			s.audit("account_move_needed", "account:"+a.ID+" slug:"+a.Slug+" from:"+at+" to:"+to, "ok")
		}
	}
	return nil
}

// Deps builds what the settings page needs.
func (s *Service) Deps() internalui.SettingsDeps {
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
				quota, retention := s.StorageFor(ctx, a.ID)
				out = append(out, internalui.StorageRow{
					AccountID: a.ID, Label: a.DisplayName + " (" + a.Slug + ")",
					QuotaGiB: quota / (1 << 30), RetentionDays: int(retention / (24 * time.Hour)),
					RequestExpiryDays: int(s.RequestExpiryFor(ctx, a.ID) / (24 * time.Hour)),
				})
			}
			return out, nil
		},
		Presets:      s.presets,
		SavePreset:   s.savePreset,
		DeletePreset: s.deletePreset,
		SaveStorage: func(ctx context.Context, accountID string, quotaGiB int64, retentionDays, requestExpiryDays int) error {
			if _, err := s.store.GetAccountByID(ctx, accountID); err != nil {
				return fmt.Errorf("unknown account")
			}
			if err := s.saveRaw(ctx, StorageKeyQuota(accountID), strconv.FormatInt(quotaGiB<<30, 10)); err != nil {
				return err
			}
			if err := s.saveRaw(ctx, StorageKeyRetention(accountID), strconv.Itoa(retentionDays)); err != nil {
				return err
			}
			return s.saveRaw(ctx, ContactsKeyRequestExpiry(accountID), strconv.Itoa(requestExpiryDays))
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
			// What a peer validates: the chain, to a root this node serves, at that account's
			// address. Behind a terminating edge a peer sees the edge's WebPKI certificate instead.
			var served []tunnel.Served
			if accts, err := s.store.ListAccounts(ctx); err == nil && mode != core.ModeEdge {
				served = ServedIdentities(publicURL, accts)
			}
			res := tunnel.Probe(ctx, publicURL, tunnel.ProbeOptions{
				Identities: served, Timeout: 5 * time.Second, SelfOriginated: true,
			})
			return string(res.Verdict), strings.TrimSpace(res.Detail + " " + res.Caveat)
		},
		Audit: s.audit,
	}
}

// ContactCap reads the number of contacts each account may hold (limit.contacts), the default
// when unset: what the contact managers enforce and what sizes every account's call budget.
func (s *Service) ContactCap() int {
	var n int
	s.readCfg(func(c *core.Config) { n = c.ContactCap() })
	return n
}

// presets returns the owner's bundles as the editor shows them — the resolved
// set, defaults included, so the page always has something to edit.
func (s *Service) presets(ctx context.Context) (map[string][]string, error) {
	return contacts.LoadPresets(ctx, s.store), nil
}

// savePreset writes one bundle. The FIRST write seeds every currently-resolved
// bundle as rows, so "edit work" cannot silently delete family: from then on
// the rows are the complete set.
func (s *Service) savePreset(ctx context.Context, name string, perms []string) error {
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
func (s *Service) deletePreset(ctx context.Context, name string) error {
	return s.store.DeleteSetting(ctx, contacts.PresetKeyPrefix+name)
}

// LeafAddress is the endpoint an account's current leaf names, or "" when it holds none. It is the
// address the account ANSWERS at, which is a fact about a certificate and not about a setting.
func LeafAddress(ctx context.Context, st store.AccountStore, accountID string) string {
	leaves, err := st.ListLeaves(ctx, accountID)
	if err != nil {
		return ""
	}
	for _, l := range leaves {
		if l.State == identity.LeafCurrent {
			return l.Endpoint
		}
	}
	return ""
}

// ServedIdentities is what the reachability probe validates against: each CERTIFIED account as a
// peer holds it — its owner's root, and the address a leaf under that root has to name here. An
// account no wallet has certified is nobody, and serves nothing to validate.
func ServedIdentities(publicURL string, accts []store.Account) []tunnel.Served {
	out := make([]tunnel.Served, 0, len(accts))
	for _, a := range accts {
		if a.HasRoot() {
			out = append(out, tunnel.Served{Root: a.RootFingerprint, Endpoint: identity.EndpointFor(publicURL, a.Slug)})
		}
	}
	return out
}
