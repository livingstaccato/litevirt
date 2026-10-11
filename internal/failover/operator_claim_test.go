package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// decideOperatorAt0 decides, at attempt 0, an operator's promotion of vm1 to
// host — one that failed before it started the VM, or a value a minority
// accepted for a refused claim — and the coordinator's own proposal at any
// later attempt.
func decideOperatorAt0(host string) func(corrosion.ClaimKey, corrosion.ClaimValue) (claims.Outcome, error) {
	return func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		if key.Attempt > 0 {
			return decideOurs(key, v)
		}
		p := *v.Proof
		p.ID, p.Action, p.DestHost, p.Coordinator = "op-proof", corrosion.ActionPromote, host, corrosion.OperatorClaimPrefix+host
		p.LeaseHolder, p.LeaseExpiresAt, p.QuorumLive, p.QuorumNeeded, p.FenceEpoch = host, "", 0, 0, ""
		out, err := decideOurs(key, corrosion.ClaimValue{Proof: &p, SourceHost: v.SourceHost})
		out.Ours = false
		return out, err
	}
}

// Review I2: a decided operator's promotion that never started the VM no
// longer holds the claim forever. The coordinator asks its host to abandon it
// (that host signs only if its start fence is not recorded), and on the
// signature moves to the next attempt and recovers the VM. While the host
// refuses — it started the VM — the value stands and nothing is minted.
//
// Mutation "no operator branch" in supersedeEvidence — red: the coordinator
// stands down, nothing asked, nothing minted. Mutation "return on a failed
// request" (round 1's shape, review I-2) — red on "its host removed for good".
func TestReschedule_MovesPastAnOperatorPromotionThatNeverStarted(t *testing.T) {
	for _, c := range []struct {
		name     string
		dest     string
		abandons bool
		moves    bool
	}{
		{"never started: abandoned", "other", true, true},
		{"started: refused", "other", false, false},
		// Review I-2: the host cannot be asked, and it has been removed for
		// good: the removal is the evidence, as for any other decided value.
		{"refused, its host removed for good", "gone-for-good", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := &fakeClaimer{decide: decideOperatorAt0(c.dest)}
			if c.abandons {
				cl.abandon = func(string, corrosion.ClaimKey, string) (string, error) { return "signed-abandonment", nil }
			}
			db, coord := claimFixture(t, cl)
			coord.run(context.Background())

			if len(cl.abandonAsked) == 0 || cl.abandonAsked[0] != c.dest+"/op-proof" {
				t.Fatalf("abandonment asked of %v, want %s/op-proof", cl.abandonAsked, c.dest)
			}
			ps := vmProofs(t, db)
			if !c.moves {
				if len(ps) != 0 {
					t.Fatalf("a started operator promotion was moved past: %+v", ps)
				}
				return
			}
			if len(ps) != 1 || ps[0].Action != corrosion.ActionReschedule {
				t.Fatalf("want vm1 rescheduled at the next attempt, got %+v", ps)
			}
			last := cl.evidence[len(cl.evidence)-1]
			want := ""
			if c.abandons {
				want = "signed-abandonment"
			}
			if last == nil || last.Abandonment != want || cl.calls[len(cl.calls)-1].Attempt != 1 {
				t.Fatalf("attempt 1 was not claimed on the operator host's abandonment: calls %v evidence %+v", cl.calls, last)
			}
		})
	}
}
