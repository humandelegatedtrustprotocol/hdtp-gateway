package public

import "time"

// The clock these tests decide against.
//
// This file was the shared environment for the retired generation's open-order tests — a store, one account
// and an Identifier wired to them: `idEnv`, `newIdEnv`, `sender` and `spkiOf`. Those tests went
// with the reader they were about, and staticcheck named the helpers as unused rather than
// letting them sit here looking load-bearing. What the tests still share is the instant, so
// that is all this holds; `decide_test.go` builds its own world, from a root and a leaf.
var fixedNow = time.Unix(1756000000, 0)
