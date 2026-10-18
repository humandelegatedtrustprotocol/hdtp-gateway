package cli

import (
	"bytes"
	"strings"
	"testing"
)

// Build rule 1's divergence, named where a test holds it: the portal is the one door to webhooks
// (ruling A of docs/release/webhooks-2026-10-18.md). No command of the binary registers, rotates,
// pauses, resumes or removes one, and the usage names none. A command that does takes this entry
// out, and the webhooks README's with it.
func TestNoCommandTouchesAWebhook(t *testing.T) {
	var usageOut bytes.Buffer
	usage(&usageOut)
	if strings.Contains(strings.ToLower(usageOut.String()), "webhook") {
		t.Fatalf("the usage names a webhook command:\n%s", usageOut.String())
	}
	for _, name := range []string{"webhook", "webhooks"} {
		var stdout, stderr bytes.Buffer
		if code := Run([]string{name, "create"}, "test", &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "unknown command") {
			t.Fatalf("%s: exit %d, %q; want an unknown command", name, code, stderr.String())
		}
	}
	// The control: a command the binary has is run, not called unknown.
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version"}, "test", &stdout, &stderr); code != 0 {
		t.Fatalf("version: exit %d, %q", code, stderr.String())
	}
}
