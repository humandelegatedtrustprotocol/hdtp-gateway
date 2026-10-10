package core

import "testing"

// Two nodes on one host share a cookie jar, because cookies are not scoped by
// port. The tag is what keeps their cookie names apart, so the property that
// matters is that realistically-adjacent nodes differ.
func TestNodeTagSeparatesNodesAPersonWouldRunTogether(t *testing.T) {
	cases := []struct {
		name         string
		a, b         [3]string // dataDir, publicURL, internalBind
		wantDistinct bool
	}{
		{
			name:         "two containers, identical layout, different public URLs (the demo pair)",
			a:            [3]string{"/data", "https://alice.example.com", "127.0.0.1:8080"},
			b:            [3]string{"/data", "https://bob.example.com", "127.0.0.1:8080"},
			wantDistinct: true,
		},
		{
			name:         "two local nodes, no public URL, different data dirs",
			a:            [3]string{"/var/lib/hdtp/nodeA", "", "127.0.0.1:8080"},
			b:            [3]string{"/var/lib/hdtp/nodeB", "", "127.0.0.1:8080"},
			wantDistinct: true,
		},
		{
			name:         "two local nodes distinguished only by bind",
			a:            [3]string{"/data", "", "127.0.0.1:8080"},
			b:            [3]string{"/data", "", "127.0.0.1:8081"},
			wantDistinct: true,
		},
		{
			name:         "the same node, restarted",
			a:            [3]string{"/data", "https://alice.example.com", "127.0.0.1:8080"},
			b:            [3]string{"/data", "https://alice.example.com", "127.0.0.1:8080"},
			wantDistinct: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ta := NodeTag(tc.a[0], tc.a[1], tc.a[2])
			tb := NodeTag(tc.b[0], tc.b[1], tc.b[2])
			if (ta != tb) != tc.wantDistinct {
				t.Errorf("tags %q and %q: distinct=%v, want %v", ta, tb, ta != tb, tc.wantDistinct)
			}
			if len(ta) != 8 {
				t.Errorf("tag %q is not 8 characters", ta)
			}
		})
	}
}

// A restart must not sign the owner out, so the tag has to be derived rather
// than generated.
func TestNodeTagIsStableAcrossCalls(t *testing.T) {
	a := NodeTag("/data", "https://x.example", "127.0.0.1:8080")
	for i := 0; i < 3; i++ {
		if got := NodeTag("/data", "https://x.example", "127.0.0.1:8080"); got != a {
			t.Fatalf("tag changed between calls: %q then %q", a, got)
		}
	}
}
