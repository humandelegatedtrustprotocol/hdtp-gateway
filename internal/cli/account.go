package cli

import (
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/identity"
)

func account(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pact-gateway account <create|list|csr|install-leaf|certificate|address|announce|leave> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var cfgPath, slug, name, algo, purpose, endpoint, chainPath, root, decision, policy string
	var yes, forceCurrent bool
	fs := commonFlags("account "+sub, &cfgPath, stderr)
	fs.StringVar(&slug, "slug", "", "account slug (endpoint path segment)")
	fs.StringVar(&name, "name", "", "display name")
	fs.StringVar(&algo, "algo", "p256", "key algorithm: p256|ed25519")
	fs.StringVar(&purpose, "purpose", "", "csr: signup|renew|move (default: signup before the first leaf, renew after)")
	fs.StringVar(&endpoint, "endpoint", "", "csr: the https URL the leaf names (default: the node's public URL for the slug)")
	fs.StringVar(&chainPath, "chain", "", "install-leaf: file holding the wallet's answer, two PEM CERTIFICATE blocks, leaf then root")
	fs.StringVar(&root, "root", "", "address: the root fingerprint waiting at a new address")
	fs.StringVar(&decision, "decision", "", "address: approve|reject; omitted lists what is pending")
	fs.StringVar(&policy, "policy", "", "address: auto|ask — what happens when a pinned contact turns up at a new address (PACT §5.3)")
	fs.BoolVar(&yes, "yes", false, "leave: erase what the review shows (without it, the review and nothing else)")
	fs.BoolVar(&forceCurrent, "force-current", false, "leave: erase the identity even though its current leaf is at this node's own address for it")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "account:", err)
		return 1
	}
	sock := core.AdminSocketPath(cfg.DataDir)
	switch sub {
	case "create":
		var out map[string]any
		if err := core.AdminCall(sock, "account.create", map[string]string{"slug": slug, "name": name, "algo": algo, "endpoint": endpoint}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "created %v  fingerprint %v\n", out["Slug"], out["Fingerprint"])
		if csr, ok := out["CSR"].(string); ok {
			fmt.Fprintf(stdout, "certificate signing request for %v (hand it to the wallet, then `account install-leaf`):\n%s", out["Endpoint"], csr)
		}
		return 0
	case "csr":
		var out map[string]any
		if err := core.AdminCall(sock, "account.csr", map[string]string{"slug": slug, "purpose": purpose, "endpoint": endpoint}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stderr, "%v request for %v, key %v; suggested notAfter %v\n", out["Purpose"], out["Endpoint"], out["Kid"], out["SuggestedNotAfter"])
		printWarnings(stderr, out)
		fmt.Fprint(stdout, out["CSR"])
		return 0
	case "install-leaf":
		if chainPath == "" {
			fmt.Fprintln(stderr, "account: install-leaf needs -chain FILE")
			return 2
		}
		chain, err := os.ReadFile(chainPath)
		if err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		var out map[string]any
		if err := core.AdminCall(sock, "account.install", map[string]string{"slug": slug, "chain": string(chain)}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "installed leaf %v for %v under root %v, valid until %v\n", out["Kid"], out["Endpoint"], out["Root"], out["NotAfter"])
		if r, ok := out["Retired"]; ok {
			fmt.Fprintf(stdout, "retired %v: this node could not open the superseded key (it was sealed under another master key), so an envelope still sealed to it is answered certificate_renewed\n", r)
		}
		if c, ok := out["Campaigns"]; ok {
			fmt.Fprintf(stdout, "telling contacts of the new address: %v\n", c)
		}
		if n, ok := out["Notice"].(string); ok && n != "" {
			fmt.Fprintln(stdout, n)
		}
		printWarnings(stderr, out)
		return 0
	case "announce":
		var out map[string]any
		if err := core.AdminCall(sock, "account.announce", map[string]string{"slug": slug}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "contacts told of the address: told=%v waiting=%v\n", out["Told"], out["Waiting"])
		if n, _ := out["NoLeaf"].(float64); n > 0 {
			fmt.Fprintf(stdout, "unreached=%v: contacts whose leaf this host does not hold, imported or not; they stay pinned by their root and are not tried again for this leaf\n", out["NoLeaf"])
		}
		if n, _ := out["Refused"].(float64); n > 0 {
			fmt.Fprintf(stdout, "refused=%v: imported contacts that refused the handshake; they are not asked again for this leaf\n", out["Refused"])
		}
		if unreached, _ := out["Unreached"].([]any); len(unreached) > 0 {
			for _, u := range unreached {
				if m, ok := u.(map[string]any); ok {
					fmt.Fprintf(stdout, "  not reached: %v (tried %v): %v\n", m["contact"], m["attempts"], m["last_error"])
				}
			}
		}
		// Two different facts, said differently: a walk that was already running is reported, and
		// one this command has just started is said to have been started by it.
		switch resumed, _ := out["Resumed"].(bool); {
		case resumed:
			fmt.Fprintln(stdout, "resumed: trying the contacts still waiting; run `account announce` again to see how far it has got")
		case out["Walking"] == true:
			fmt.Fprintln(stdout, "a walk is under way; run `account announce` again to see how far it has got")
		}
		return 0
	case "leave":
		var out map[string]any
		call := map[string]string{"slug": slug}
		if yes {
			call["yes"] = "1"
		}
		if forceCurrent {
			call["force_current"] = "1"
		}
		if err := core.AdminCall(sock, "account.leave", call, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		if r, ok := out["Review"].(map[string]any); ok {
			fmt.Fprintf(stdout, "leaving would erase %v (root %v) from this node: %v leaf key(s), %v contact(s), %v conversation(s) and %v media record(s) (a file goes only when no other identity here uses it)\n",
				r["Slug"], r["Root"], r["Leaves"], r["Contacts"], r["Threads"], r["MediaFiles"])
			if c, _ := r["Current"].(string); c != "" {
				fmt.Fprintf(stdout, "  its current leaf names %v\n", c)
			}
			fmt.Fprintf(stdout, "nothing was erased, and there is no undo. If this is what you mean, run it again with -yes\n")
			return 0
		}
		fmt.Fprintf(stdout, "%v has left this node: its records and its %v leaf key(s) are erased, and %v media file(s) no other identity used\n", out["Slug"], out["Leaves"], out["MediaRemoved"])
		reserved, _ := out["Reserved"].([]any)
		for _, r := range reserved {
			if m, ok := r.(map[string]any); ok {
				fmt.Fprintf(stdout, "  %v stays reserved until %v, when the last leaf issued for it expires; no identity can be given it before then\n", m["Endpoint"], m["Until"])
			}
		}
		if len(reserved) == 0 {
			fmt.Fprintln(stdout, "  no live leaf named an address here, so none is reserved")
		}
		if w, ok := out["Warning"].(string); ok {
			fmt.Fprintln(stderr, "account:", w)
			return 1
		}
		return 0
	case "certificate":
		var out map[string]any
		if err := core.AdminCall(sock, "account.certificate", map[string]string{"slug": slug}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		// Owed handshakes are said first, whatever the leaf's state: an import leaves them waiting
		// for the next leaf, and this is where the owner looks (PACT §9.2).
		if line := handshakesOwedLine(fmt.Sprint(out["Slug"]), out["HandshakesOwed"], out["HandshakesUnderWay"], fmt.Sprint(out["Kid"]) != ""); line != "" {
			fmt.Fprintln(stdout, line)
		}
		if certified, _ := out["Certified"].(bool); !certified {
			fmt.Fprintf(stdout, "%v has no leaf yet; `account csr -slug %v` prints the request for the wallet\n", out["Slug"], out["Slug"])
			return 0
		}
		if kid, _ := out["Kid"].(string); kid == "" {
			// A root and no current leaf: what an import leaves, and what an expired leaf leaves. The
			// leaf fields are zero here, and printing them described a leaf that does not exist.
			fmt.Fprintf(stdout, "%v: root %v\n  no current leaf on this host: it is not served until the wallet signs one\n", out["Slug"], out["Root"])
		} else {
			fmt.Fprintf(stdout, "%v: root %v\n  leaf %v for %v, %v to %v\n  renewal due: %v\n", out["Slug"], out["Root"], out["Kid"], out["Endpoint"], out["NotBefore"], out["NotAfter"], out["RenewalDue"])
		}
		if p, _ := out["PendingCSR"].(string); p != "" {
			fmt.Fprintf(stdout, "  a request for key %v awaits the wallet\n", p)
		}
		fmt.Fprint(stdout, out["Chain"])
		return 0
	case "address":
		if policy != "" {
			var out map[string]any
			if err := core.AdminCall(sock, "account.host_policy", map[string]string{"slug": slug, "policy": policy}, &out); err != nil {
				fmt.Fprintln(stderr, "account:", err)
				return 1
			}
			fmt.Fprintf(stdout, "%v: a contact at a new address is now %v\n", out["Slug"], hostPolicyWords(fmt.Sprint(out["Policy"])))
			return 0
		}
		if decision == "" {
			var out []map[string]any
			if err := core.AdminCall(sock, "account.addresses", map[string]string{"slug": slug}, &out); err != nil {
				fmt.Fprintln(stderr, "account:", err)
				return 1
			}
			for _, p := range out {
				fmt.Fprintf(stdout, "%v\t%v\t%v\n", p["Root"], p["Endpoint"], p["Why"])
			}
			return 0
		}
		var out map[string]any
		if err := core.AdminCall(sock, "account.address", map[string]string{"slug": slug, "root": root, "decision": decision}, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "%v: %v at %v\n", out["Decision"], out["Root"], out["Endpoint"])
		return 0
	case "list":
		var out []map[string]any
		if err := core.AdminCall(sock, "account.list", nil, &out); err != nil {
			fmt.Fprintln(stderr, "account:", err)
			return 1
		}
		for _, a := range out {
			fmt.Fprintf(stdout, "%v\t%v\t%v\t%v\n", a["Slug"], a["DisplayName"], a["Algo"], a["Fingerprint"])
		}
		return 0
	default:
		fmt.Fprintln(stderr, "usage: pact-gateway account <create|list|csr|install-leaf|certificate|address|announce|leave> [flags]")
		return 2
	}
}

// parseChainPEM reads the wallet's answer: two CERTIFICATE blocks, leaf then root.
func parseChainPEM(text string) ([][]byte, error) {
	var chain [][]byte
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("chain: unexpected PEM block %q (want CERTIFICATE)", block.Type)
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) != 2 {
		return nil, fmt.Errorf("chain: want exactly two certificates, leaf then root; got %d", len(chain))
	}
	return chain, nil
}

// hostPolicyWords says what a §5.3 policy does, for the line the CLI prints back.
func hostPolicyWords(policy string) string {
	if policy == "ask" {
		return "held until you decide (`account address -decision approve|reject`)"
	}
	return "followed automatically when their own root signed the new leaf"
}

// addressDriftLine says, for one account, that its leaf names another address than the one this
// node advertises for it — or "" when they agree, or when either is unknown.
//
// It is worded as a condition and not as a fault, because it is not always one: an account may be
// certified for a hostname of its own (a multi-account node wants one host per account for direct
// TLS). It is a fault when the node's `public_url` was changed, and then the cure is a move — a
// leaf the wallet issues for the new address. Saving the setting moves nobody.
func addressDriftLine(publicURL, slug, leafEndpoint string) string {
	if publicURL == "" || leafEndpoint == "" {
		return ""
	}
	advertised := identity.EndpointFor(publicURL, slug)
	if advertised == "" || advertised == leafEndpoint {
		return ""
	}
	return fmt.Sprintf("%s answers at %s (the address in its certificate) and this node advertises %s. If the node's address changed, "+
		"run `pact-gateway account csr -slug %s -purpose move`, have the wallet sign it, then `account install-leaf`: that is what moves an identity and tells its contacts",
		slug, leafEndpoint, advertised, slug)
}

// handshakesOwedLine is what `account certificate` and `doctor` say of contacts an import left
// owed this host's handshake, or "" when there are none. The counts arrive as whatever the caller
// holds: ints from the manager, JSON numbers over the admin socket. Contacts the current leaf's
// campaign owes (imported before it was requested) are that walk's, which `account announce`
// reports and resumes; the rest wait for a leaf: an identity with no leaf here yet (it arrived in
// an import) asks for a move, one that is served asks for a renewal.
func handshakesOwedLine(slug string, owed, underWay any, hasLeaf bool) string {
	count, walking := asCount(owed), asCount(underWay)
	var parts []string
	if walking > 0 {
		parts = append(parts, fmt.Sprintf("%d imported contact(s) of %s are owed this leaf's handshake: `account announce -slug %s` reports and resumes it", walking, slug, slug))
	}
	if waiting := count - walking; waiting > 0 {
		purpose := "renew"
		if !hasLeaf {
			purpose = "move"
		}
		parts = append(parts, fmt.Sprintf("%d imported contact(s) of %s wait for a new leaf: run `account csr -slug %s -purpose %s`, have the wallet sign it, then `account install-leaf -slug %s -chain <file>`", waiting, slug, slug, purpose, slug))
	}
	return strings.Join(parts, "; ")
}

func asCount(n any) int {
	switch v := n.(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// printWarnings writes what a request or an install did not finish, one line each.
func printWarnings(w io.Writer, out map[string]any) {
	ws, _ := out["Warnings"].([]any)
	for _, x := range ws {
		fmt.Fprintf(w, "warning: %v\n", x)
	}
}
