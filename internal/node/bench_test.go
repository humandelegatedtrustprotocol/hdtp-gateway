package node

// `state20` is read once per inbound envelope, on purpose: a setting the owner
// changes has to take effect without a restart. What that costs had never been
// measured.
//
// It reads the account row, the chain, the active leaf keypairs — unsealing each
// private key from the keyring — the former kids, and then EVERY OTHER ACCOUNT on
// the node plus that account's leaves, one query each. The last part is an N+1
// per request, and these benchmarks are what makes it visible: run them at one
// account and at eight, and the difference is the loop.

import (
	"context"
	"fmt"
	"testing"
)

func benchState20(b *testing.B, accounts int) {
	slugs := make([]string, accounts)
	for i := range slugs {
		slugs[i] = fmt.Sprintf("acct%d", i)
	}
	e, accts := newEnv(b, slugs...)
	n, _ := e.start(e.options())
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := n.state20(ctx, accts[0].ID, accts[0].Slug); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkState20OneAccount(b *testing.B)    { benchState20(b, 1) }
func BenchmarkState20FourAccounts(b *testing.B)  { benchState20(b, 4) }
func BenchmarkState20EightAccounts(b *testing.B) { benchState20(b, 8) }
