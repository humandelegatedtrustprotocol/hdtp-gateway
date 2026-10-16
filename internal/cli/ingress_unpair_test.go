package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/ingress"
)

// `ingress unpair -subdomain` forgets one pairing in the running ingress, over its admin socket,
// and the ingress audits it with the subdomain: there was no way to remove a pairing at all, short
// of editing the book on disk beside a process that would overwrite it at its next pairing. The
// refusals: a subdomain no pairing holds (not_found, exit 1), no -subdomain or one that is not a DNS
// label (exit 2, before the socket is called), no ingress listening (exit 1).
func TestIngressUnpairForgetsOnePairingInTheRunningIngress(t *testing.T) {
	dir := t.TempDir()
	reg := ingress.NewMemoryRegistry(nil)
	for _, sub := range []string{"alice", "bob"} {
		if err := reg.Put(ingress.Node{Fingerprint: "sha256:" + sub, Subdomain: sub, Mode: ingress.ModePassthrough, Secret: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	var rows []string
	admin := core.NewAdminServer(core.AdminSocketPath(dir))
	admin.Handle("ingress.unpair", unpairHandler(&ingress.DataPlane{Registry: reg}, func(action, resource, outcome string) {
		rows = append(rows, action+" "+resource+" "+outcome)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := admin.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := ingressCmd(append([]string{"unpair"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := run("-data-dir", dir, "-subdomain", "bob"); code != 0 || !strings.Contains(out, "unpaired bob") {
		t.Fatalf("unpair bob: exit %d: %s", code, out)
	}
	if _, ok := reg.BySubdomain("bob"); ok {
		t.Error("bob is still paired")
	}
	if _, ok := reg.BySubdomain("alice"); !ok {
		t.Error("unpairing bob lost alice")
	}
	if code, out := run("-data-dir", dir, "-subdomain", "bob"); code != 1 || !strings.Contains(out, `no pairing holds "bob"`) {
		t.Errorf("unpair bob again: exit %d: %s", code, out)
	}
	if code, _ := run("-data-dir", dir); code != 2 {
		t.Errorf("no -subdomain: exit %d, want 2", code)
	}
	for _, bad := range []string{"Bob", "bob.example.test", "-bob", "b_b"} {
		if code, out := run("-data-dir", dir, "-subdomain", bad); code != 2 || !strings.Contains(out, "is not one DNS label") {
			t.Errorf("-subdomain %q: exit %d: %s", bad, code, out)
		}
	}
	if code, out := run("-data-dir", t.TempDir(), "-subdomain", "alice"); code != 1 || !strings.Contains(out, "is the node running?") {
		t.Errorf("no ingress listening: exit %d: %s", code, out)
	}
	want := []string{"ingress_unpair subdomain:bob ok", "ingress_unpair subdomain:bob not_found"}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit rows %q, want %q", rows, want)
	}
}
