package claims

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ForgetBelow drops one lease's past terms from the ballot bookkeeping, and
// nothing else.
//
// Mutation: make ForgetBelow a no-op — this goes red.
func TestProposer_ForgetBelow(t *testing.T) {
	p := NewProposer("a", nil)
	keys := []corrosion.ClaimKey{
		corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 3),
		corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 7),
		corrosion.LeaseTermClaimKey(corrosion.LeaseKeyRebalancer, 3),
		{TargetKind: corrosion.ClaimKindVM, TargetName: corrosion.LeaseKeyFailover, OwnerEpoch: 3},
	}
	for _, k := range keys {
		p.ballot(k, 1, false)
		p.bind(k, 1, "d")
	}
	p.ForgetBelow(corrosion.ClaimKindLeaseTerm, corrosion.LeaseKeyFailover, 7)
	for i, k := range keys {
		_, used := p.used[k]
		_, bound := p.bound[k]
		want := i != 0
		if used != want || bound != want {
			t.Errorf("%s: used=%v bound=%v, want %v", k, used, bound, want)
		}
	}
}
