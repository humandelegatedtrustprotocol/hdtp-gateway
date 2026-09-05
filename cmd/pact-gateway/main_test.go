package main

import "testing"

func TestVersionString(t *testing.T) {
	v := versionString()
	if v == "" {
		t.Fatal("versionString() returned empty")
	}
	if v != "pact-gateway "+version {
		t.Fatalf("versionString() = %q, want %q", v, "pact-gateway "+version)
	}
}
