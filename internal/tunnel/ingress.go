package tunnel

// Ingress-fronted adapters (SPEC §10.6): a node paired with a hdtp-gateway
// ingress reaches it over the embedded frp client, but WHICH deployment mode
// it derives depends on the subdomain's serving mode — so pairing yields one
// of two adapter names, each with a fixed TerminatesAtEdge:
//
//   ingress-passthrough  the ingress forwards raw TLS on SNI → direct mode
//   ingress-terminate    the ingress terminates public TLS and re-originates
//                        pinned mTLS to the node → edge mode
//
// Both wrap the frp adapter with the settings the pairing response carries.

import "fmt"

func init() {
	Register("ingress-passthrough", false, func(o Options) (Adapter, error) {
		return ingressFRP(o, false)
	})
	Register("ingress-terminate", true, func(o Options) (Adapter, error) {
		return ingressFRP(o, true)
	})
}

// ingressInternalName mirrors ingress.InternalName (kept local: the ingress
// package's tests import tunnel, so tunnel must not import ingress).
func ingressInternalName(sub, domain string) string { return sub + ".internal." + domain }

// ingressFRP builds the frp adapter from pairing data. Extra keys: subdomain,
// domain, data_plane_addr, data_plane_port, data_plane_token, node_fpr,
// node_secret (all from the PairResponse).
func ingressFRP(o Options, terminate bool) (Adapter, error) {
	get := func(k string) string {
		if o.Extra == nil {
			return ""
		}
		return o.Extra[k]
	}
	for _, k := range []string{"subdomain", "domain", "data_plane_addr", "node_fpr", "node_secret"} {
		if get(k) == "" {
			return nil, fmt.Errorf("tunnel: ingress pairing needs %s", k)
		}
	}
	sni := get("subdomain") + "." + get("domain")
	if terminate {
		sni = ingressInternalName(get("subdomain"), get("domain"))
	}
	port := get("data_plane_port")
	if port == "" {
		port = "7000"
	}
	return New("frp", Options{PublicBind: o.PublicBind, Extra: map[string]string{
		"server_addr": get("data_plane_addr"), "server_port": port, "token": get("data_plane_token"),
		"proxy_type": "https", "custom_domain": sni, "name": get("subdomain"),
		"meta_hdtp_node": get("node_fpr"), "meta_hdtp_secret": get("node_secret"),
	}})
}
