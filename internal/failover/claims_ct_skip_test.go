package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A decided container relocation whose destination already runs another
// container of the same name is not written and left live: its destination
// abandons it and the claim moves to the next attempt, decided for a host the
// container can go to (recovery-claims.md §3.12, §10 item 39).
//
// Before, the adopted value was written and deferred to, and once carried out
// the image-recreate's collision check turned it away without marking the
// container: every tick then re-claimed, learned the same value and was turned
// away again, with a certified proof for the unusable destination left live.
//
// Mutation: pass no container check to the relocation claim (claimRecovery
// instead of claimRecoveryFor) — the proof naming "other" is written, nothing
// is abandoned, and the test goes red.
func TestImageRecreate_ADecidedDestinationHoldingTheNameMovesOn(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{
		decide: func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
			if key.Attempt == 0 {
				return decideTheirs(corrosion.ActionRelocate, "other")(key, v)
			}
			return decideOurs(key, v)
		},
		abandon: func(string, corrosion.ClaimKey, string) (string, error) { return "signed-abandonment", nil },
	}
	db, c := claimFixture(t, cl)
	for _, ct := range []corrosion.ContainerRecord{
		{HostName: "dead", Name: "ct1", State: "running", Image: "alpine:3.19", OnHostFailure: "image-recreate"},
		// An unrelated container that happens to share the name.
		{HostName: "other", Name: "ct1", State: "running", Image: "busybox:1"},
	} {
		if err := corrosion.UpsertContainer(ctx, db, ct); err != nil {
			t.Fatal(err)
		}
	}
	ct, _ := corrosion.GetContainer(ctx, db, "dead", "ct1")

	c.imageRecreateOrSkip(ctx, &corrosion.HostRecord{Name: "dead"}, *ct, "live", nil)

	if _, ok, _ := corrosion.GetActionProof(ctx, db, "their-proof"); ok {
		t.Fatal("the decided relocation to a host already running a container of that name was written")
	}
	if len(cl.abandonAsked) != 1 || cl.abandonAsked[0] != "other/their-proof" {
		t.Fatalf("abandonment asked of %v, want other/their-proof", cl.abandonAsked)
	}
	if n := len(cl.calls); n != 2 || cl.calls[1].Attempt != 1 || cl.evidence[1] == nil ||
		cl.evidence[1].Abandonment != "signed-abandonment" {
		t.Fatalf("claims = %v; want attempt 1 claimed on other's abandonment", cl.calls)
	}
	moved, _ := corrosion.GetContainer(ctx, db, "live", "ct1")
	if moved == nil || moved.RelocateToken == "" {
		t.Fatalf("ct1 was not relocated to live at attempt 1: %+v", moved)
	}
	if unrelated, _ := corrosion.GetContainer(ctx, db, "other", "ct1"); unrelated == nil || unrelated.Image != "busybox:1" {
		t.Fatalf("the unrelated container on other changed: %+v", unrelated)
	}
}
