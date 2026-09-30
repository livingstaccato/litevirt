package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestContainerCheck_RelocateRecreate_RecoveryClaimGateRefuses: a
// relocate-recreate row is only ever written by the failover coordinator, and
// its proof is claimed here off the replicated row, so the certificate check
// runs here before the claim (docs/design/recovery-claims.md §3.10). A refused
// proof is neither claimed nor executed.
//
// Mutation: drop the recoveryClaimGate call in claimRelocationProof — the
// container is recreated from an uncertified proof.
func TestContainerCheck_RelocateRecreate_RecoveryClaimGateRefuses(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail,
		Image:       "alpine:3.19", RelocateToken: "tok-1",
	})
	if err := corrosion.WriteActionProof(ctx, db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionRelocate, TargetKind: "container",
		TargetName: "ct1", DestHost: "node1", Coordinator: "coord", RelocationToken: "tok-1",
	}); err != nil {
		t.Fatalf("WriteActionProof: %v", err)
	}
	c := NewContainerChecker("node1", db, rt)
	c.SetContainersRoot(t.TempDir())
	c.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	var reason string
	c.SetGateRefusedObserver(func(_, r string) { reason = r })
	c.SetRecoveryClaimGate(func(context.Context, corrosion.ProofRecord) (string, error) {
		return ReasonClaimUnproven, errUnprovenForTest
	})
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	if rt.startCount("ct1") != 0 {
		t.Fatalf("an uncertified relocation recreated the container (%d starts)", rt.startCount("ct1"))
	}
	if reason != ReasonClaimUnproven {
		t.Errorf("refusal reason = %q, want %q", reason, ReasonClaimUnproven)
	}
	if pr, _, _ := corrosion.GetActionProof(ctx, db, "p1"); pr.Status != corrosion.ProofPrepared {
		t.Errorf("the refused proof was consumed: status %q", pr.Status)
	}
}
