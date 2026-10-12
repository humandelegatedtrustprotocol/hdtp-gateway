package identity

import (
	"context"
	"errors"
	"testing"
)

// An identity asked for under a slug another holds is ErrSlugTaken, in the node's words, before a
// key is made for it: the portal and the CLI showed the store's refusal of a second row. The
// control, another slug, is created.
func TestASlugInUseIsRefusedByCode(t *testing.T) {
	m, _ := leafEnv(t) // holds "alina"
	_, err := m.CreateAccount(context.Background(), "alina", "Alina Again", AlgoEd25519)
	if !errors.Is(err, ErrSlugTaken) || err.Error() != `identity: the slug "alina" is another identity's` {
		t.Errorf("a slug in use: %v", err)
	}
	if _, err := m.CreateAccount(context.Background(), "bharat", "Bharat", AlgoEd25519); err != nil {
		t.Errorf("the control: %v", err)
	}
}
