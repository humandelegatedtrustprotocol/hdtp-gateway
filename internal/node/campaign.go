package node

// Running a move campaign, and saying how far it has got (PACT §5.3, §9).
//
// `AnnounceMove` walks every contact, one after another, and waits for each. A contact that is
// simply GONE — a host that is off, a network that drops the packets — holds the walk until the
// call gives up. `account announce`, the command an operator runs BECAUSE a contact could not be
// reached, used to run the walk and answer when it ended: measured on the container harness, 17
// seconds with one contact behind a partition and 21 with two, against the thirty the admin socket
// gives any command — and it ran BESIDE the walk the install had already started, so the two
// called the same contacts and counted each attempt twice.
//
// So a campaign runs detached, one per identity at a time, and what a command reports is the
// ledger (`move_fanout`): what is recorded, which is what a re-run resumes from.

import (
	"context"
	"fmt"
	"sort"

	"github.com/pact-cloud/pact-gateway/internal/identity"
)

// MoveUnreached is one contact the current campaign has tried and not yet told.
type MoveUnreached struct {
	Contact   string `json:"contact"`
	Attempts  int64  `json:"attempts"`
	LastError string `json:"last_error"`
}

// MoveProgress is a campaign as the ledger has it.
type MoveProgress struct {
	// Told is how many contacts the campaign walks (identity.InCampaign) have been told of the
	// current leaf's address.
	Told int `json:"told"`
	// Waiting is how many have not: tried and unreached, or not tried yet.
	Waiting int `json:"waiting"`
	// Walking says a walk is in progress, so Waiting is still falling.
	Walking bool `json:"walking"`
	// Unreached names the contacts a walk has tried and failed to tell, worst first.
	Unreached []MoveUnreached `json:"unreached,omitempty"`
}

// MoveProgress reads the ledger for the identity's current leaf.
func (n *Node) MoveProgress(ctx context.Context, accountID, kid string) (MoveProgress, error) {
	st := n.idm.Store
	contacts, err := st.ListContacts(ctx, accountID)
	if err != nil {
		return MoveProgress{}, err
	}
	rows, err := st.ListMoveFanout(ctx, accountID)
	if err != nil {
		return MoveProgress{}, err
	}
	told := map[string]bool{}
	var out MoveProgress
	for _, r := range rows {
		if r.LeafKid != kid {
			continue // progress of an earlier leaf's campaign: not this address
		}
		if r.Status == "done" {
			told[r.ContactFpr] = true
			continue
		}
		out.Unreached = append(out.Unreached, MoveUnreached{Contact: r.ContactFpr, Attempts: r.Attempts, LastError: r.LastError})
	}
	for _, c := range contacts {
		if !identity.InCampaign(c) {
			continue
		}
		if told[c.Fingerprint] && !c.HandshakeDue {
			out.Told++
		} else {
			out.Waiting++
		}
	}
	sort.Slice(out.Unreached, func(i, j int) bool { return out.Unreached[i].Attempts > out.Unreached[j].Attempts })
	_, out.Walking = n.campaigns.Load(accountID)
	return out, nil
}

// ResumeMove starts the walk for the identity's current leaf unless one is already walking, and
// returns at once. It reports whether it started one.
//
// The walk outlives the caller on purpose: it takes as long as its slowest contact, and its
// progress is what makes it resumable, so it must not be abandoned half way because a command's
// connection closed. One at a time, because two walks over one ledger would each call the
// contacts the other had not yet recorded.
func (n *Node) ResumeMove(ctx context.Context, accountID, kid string) bool {
	if _, walking := n.campaigns.LoadOrStore(accountID, struct{}{}); walking {
		return false
	}
	bg := context.WithoutCancel(ctx)
	go func() {
		defer n.campaigns.Delete(accountID)
		done, failed, err := n.AnnounceMove(bg, accountID, kid)
		switch {
		case err != nil:
			n.opts.audit("account_move_campaign", "account:"+accountID, "error")
		case failed > 0:
			n.opts.audit("account_move_campaign", fmt.Sprintf("account:%s done:%d failed:%d", accountID, done, failed), "failed")
		default:
			n.opts.audit("account_move_campaign", fmt.Sprintf("account:%s done:%d failed:%d", accountID, done, failed), "ok")
		}
	}()
	return true
}
