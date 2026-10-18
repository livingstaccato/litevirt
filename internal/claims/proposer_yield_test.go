package claims

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// slowAccepts is memTransport with every Accept taking acceptDelay to land:
// a voter's durable write. A proposer that has its promises is then exposed
// for that long to a rival outbidding it before its accepts land.
type slowAccepts struct {
	*memTransport
	acceptDelay time.Duration
}

func (s slowAccepts) Accept(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error) {
	select {
	case <-time.After(s.acceptDelay):
	case <-ctx.Done():
		return corrosion.AcceptResult{}, ctx.Err()
	}
	return s.memTransport.Accept(ctx, voter, key, b, v, gen)
}

// fiveClaimantDuel runs five proposers for one key at once against five
// voters, each Accept taking 40ms, and returns the highest round any voter
// promised and whether every proposer returned the one decided value.
func fiveClaimantDuel(t *testing.T, yield func(self string) func(int, corrosion.Ballot) time.Duration) (uint64, error) {
	t.Helper()
	tr, voters := newMemCluster(t, "v1", "v2", "v3", "v4", "v5")
	all := names(voters)
	slow := slowAccepts{memTransport: tr, acceptDelay: 40 * time.Millisecond}
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-five", OwnerEpoch: 1}
	digests := make([]string, len(all))
	errs := make([]error, len(all))
	var wg sync.WaitGroup
	for i, self := range all {
		wg.Add(1)
		go func(i int, self string) {
			defer wg.Done()
			spec := workloadSpec(key, all, self)
			spec.ReturnAtQuorum = true
			spec.MaxRounds = 8
			if yield != nil {
				spec.Yield = yield(self)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, err := NewProposer(self, slow).Decide(ctx, spec)
			digests[i], errs[i] = out.Digest, err
		}(i, self)
	}
	wg.Wait()
	maxRound := uint64(0)
	for _, v := range voters {
		st, found, err := v.db.ClaimState(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		if found && st.Promised.Round > maxRound {
			maxRound = st.Promised.Round
		}
	}
	for i := range all {
		if errs[i] != nil {
			return maxRound, fmt.Errorf("%s: %w", all[i], errs[i])
		}
		if digests[i] != digests[0] {
			return maxRound, fmt.Errorf("%s decided another value", all[i])
		}
	}
	return maxRound, nil
}

// TestProposer_YieldLetsTheLeaderFinish: five proposers of one key start at
// once and every accept takes a moment to land. Outbidding a rival at once
// pre-empts it between its phases, so each retry knocks out the proposer
// ahead of it and the rounds climb — the lab's five-claimant duel reached
// round 39. With Yield, an outbid proposer lets the leader finish and then
// completes its value one round up: every proposer returns the one decided
// value within a few rounds.
//
// Mutation: ignore spec.Yield in Decide — the rounds climb past the bound
// (or the proposers run out of rounds) and this goes red.
func TestProposer_YieldLetsTheLeaderFinish(t *testing.T) {
	yield := func(string) func(int, corrosion.Ballot) time.Duration {
		return func(int, corrosion.Ballot) time.Duration {
			return 150*time.Millisecond + time.Duration(rand.Int64N(int64(150*time.Millisecond)))
		}
	}
	for run := 0; run < 3; run++ {
		maxRound, err := fiveClaimantDuel(t, yield)
		if err != nil {
			t.Fatalf("run %d: %v (round %d)", run, err, maxRound)
		}
		// Without Yield the voters reach rounds 13-16 here and proposers run
		// out of rounds; with it a few late retries still collide.
		if maxRound > 6 {
			t.Fatalf("run %d: five proposers that yield to each other reached round %d", run, maxRound)
		}
	}
}
