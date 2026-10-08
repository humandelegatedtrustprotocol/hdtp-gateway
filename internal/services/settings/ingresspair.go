package settings

// Pairing this node with an ingress (SPEC §10.6), from the portal.
//
// The node half of pairing already existed and was tested, but nothing called
// it — so the `ingress-passthrough` and `ingress-terminate` adapters were
// selectable in Settings and passed validation while being impossible to start:
// the next boot died on `tunnel: ingress pairing needs subdomain`. This file is
// the caller, and the reason selecting those adapters unpaired is now refused at
// save time instead of at the next start.
//
// What pairing produces is adapter configuration, so it is stored exactly like
// any other adapter setting — `tunnel.<adapter>.<key>` rows, which `startTunnel`
// already reads and which the keyring already seals for the two secret fields.

import (
	"context"
	"fmt"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/ingress"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
)

// ingressAdapters are the two adapters that require a completed pairing.
var ingressAdapters = map[string]ingress.Mode{
	"ingress-passthrough": ingress.ModePassthrough,
	"ingress-terminate":   ingress.ModeTerminate,
}

// adapterFor names the adapter that serves a pairing mode.
func adapterFor(mode ingress.Mode) string {
	if mode == ingress.ModeTerminate {
		return "ingress-terminate"
	}
	return "ingress-passthrough"
}

// pairedAdapters reports which ingress adapters have a stored pairing. The
// marker is `subdomain`: the adapter refuses to start without it, so its
// presence is exactly the condition that makes the adapter selectable.
func (s *Service) pairedAdapters(ctx context.Context) (map[string]bool, error) {
	rows, err := s.store.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		for adapter := range ingressAdapters {
			if r.Key == "tunnel."+adapter+".subdomain" && r.Value != "" {
				out[adapter] = true
			}
		}
	}
	return out, nil
}

// pair runs the one-time-token exchange and stores the result.
//
// Two properties matter more than the happy path. The ingress is authenticated
// by the fingerprint the owner was given out of band — an empty one is
// trust-on-first-use and the fingerprint actually seen is reported back so they
// can check it. And nothing is stored unless the exchange succeeded: a refused
// pairing must not leave half a configuration behind for the next boot to trip
// over.
func (s *Service) pair(ctx context.Context, accountID string, in internalui.PairInput) (internalui.PairResult, error) {
	if s.node == nil {
		return internalui.PairResult{}, fmt.Errorf("the node is not serving yet")
	}
	mode := ingress.ModePassthrough
	if in.Mode == string(ingress.ModeTerminate) {
		mode = ingress.ModeTerminate
	}
	cert, err := s.node.Certificate(accountID)
	if err != nil {
		return internalui.PairResult{}, err
	}
	acct, err := s.store.GetAccountByID(ctx, accountID)
	if err != nil {
		return internalui.PairResult{}, err
	}

	// Pair overwrites the transport on whatever client it is handed, so it gets
	// its own.
	res, seen, err := ingress.Pair(nil, in.PairURL, cert, strings.TrimSpace(in.IngressFingerprint),
		ingress.PairRequest{Token: in.Token, Subdomain: in.Subdomain, Mode: mode})
	if err != nil {
		s.audit("ingress_pair", "url:"+in.PairURL, "refused")
		return internalui.PairResult{Fingerprint: seen}, err
	}

	adapter := adapterFor(mode)
	if err := s.storePairing(ctx, adapter, res, acct.Fingerprint); err != nil {
		return internalui.PairResult{}, err
	}
	s.audit("ingress_pair", "ingress:"+res.IngressFingerprint+" name:"+res.PublicName, "paired")
	return internalui.PairResult{
		PublicName:  res.PublicName,
		Fingerprint: res.IngressFingerprint,
		Adapter:     adapter,
	}, nil
}

// pairingKeys are the rows a pairing writes under `tunnel.<adapter>.`, in the order storePairing
// writes them, and the rows unpair deletes.
var pairingKeys = []string{"domain", "data_plane_addr", "data_plane_port", "data_plane_token",
	"node_fpr", "node_secret", "ingress_fpr", "subdomain"}

// storePairing writes what a completed pairing produced: the adapter's rows, then the adapter as
// the selected tunnel and the public URL under the name the ingress assigned (the subdomain is
// not echoed back; it is derived from that name, so what is stored is what the ingress routes).
// There is no cross-row transaction — store.SettingStore writes one row at a time — so the order
// carries the invariant: `subdomain`, the marker pairedAdapters reads, is the last of the
// adapter's rows, and a write that fails before it leaves the pairing incomplete and not
// selectable. The rows a failed pairing leaves are overwritten by the next pairing and deleted by
// unpair. `ingress_fpr` is the ingress's identity, which the node pins on the onward leg (§10.6).
func (s *Service) storePairing(ctx context.Context, adapter string, res ingress.PairResponse, nodeFpr string) error {
	values := map[string]string{
		"domain":           res.Domain,
		"data_plane_addr":  res.DataPlaneAddr,
		"data_plane_port":  fmt.Sprintf("%d", res.DataPlanePort),
		"data_plane_token": res.DataPlaneToken,
		"node_fpr":         nodeFpr,
		"node_secret":      res.NodeSecret,
		"ingress_fpr":      res.IngressFingerprint,
		"subdomain":        strings.TrimSuffix(res.PublicName, "."+res.Domain),
	}
	for _, k := range pairingKeys {
		if err := s.saveRaw(ctx, "tunnel."+adapter+"."+k, values[k]); err != nil {
			return err
		}
	}
	// Only now is the adapter selectable; both of these are restart-scoped.
	if err := s.saveRaw(ctx, "tunnel", adapter); err != nil {
		return err
	}
	return s.save(ctx, "public_url", "https://"+res.PublicName)
}

// unpair forgets a pairing. It refuses while that adapter is the selected one,
// because the alternative is a node that cannot start.
func (s *Service) unpair(ctx context.Context, adapter string) error {
	if _, ok := ingressAdapters[adapter]; !ok {
		return fmt.Errorf("%q is not an ingress adapter", adapter)
	}
	// Both the running selection and the STORED one matter: pairing selects the
	// adapter for the next start, so forgetting the pairing while that selection
	// stands would leave a node that cannot boot.
	selected := false
	s.readCfg(func(c *core.Config) { selected = c.Tunnel == adapter })
	if !selected {
		if rows, err := s.store.ListSettings(ctx); err == nil {
			for _, r := range rows {
				if r.Key == "tunnel" && r.Value == adapter {
					selected = true
				}
			}
		}
	}
	if selected {
		return fmt.Errorf("%s is the selected tunnel — choose another adapter first, "+
			"otherwise the node would have no way to start", adapter)
	}
	for _, k := range pairingKeys {
		if err := s.store.DeleteSetting(ctx, "tunnel."+adapter+"."+k); err != nil {
			return err
		}
	}
	s.audit("ingress_unpair", "adapter:"+adapter, "ok")
	return nil
}

// saveRaw persists a value without the owner-knob validation `save` applies —
// adapter settings are not owner knobs, and their shape is the adapter's rule,
// not `core.ValidateSetting`'s. Secrets are still sealed.
func (s *Service) saveRaw(ctx context.Context, key, value string) error {
	stored, secret := value, isSecretKey(key)
	if secret {
		sealed, err := s.kr.Encrypt([]byte(value), core.SettingsAAD())
		if err != nil {
			return err
		}
		stored = encodeSealed(sealed)
	}
	return s.store.PutSetting(ctx, store.Setting{
		Key: key, Value: stored, Secret: secret, UpdatedAt: s.clock().Unix(),
	})
}

// PinnedIngress returns the paired ingress's fingerprint when this node sits
// behind a TERMINATING one, else "".
//
// Only terminate mode opens an onward leg with a certificate of its own: a
// passthrough ingress forwards raw TLS by SNI and never terminates, so there is
// nothing to pin and requiring a certificate would break every caller.
func PinnedIngress(adapter string, stored map[string]string) string {
	if adapter != "ingress-terminate" {
		return ""
	}
	return stored["tunnel."+adapter+".ingress_fpr"]
}
