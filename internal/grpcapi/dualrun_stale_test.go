package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// reasonGate is fakeServerGate whose execution gate refuses with a chosen
// reason.
type reasonGate struct {
	fakeServerGate
	reason string
}

func (g reasonGate) ExecutionGate(context.Context) health.GateResult {
	if g.reason == "" {
		return health.GateResult{OK: true}
	}
	return health.GateResult{OK: false, Reason: g.reason}
}

// TestResolveGateValid_WitnessOrDrainingLeaderResolves: a witness or a
// draining host holds the detector lease like any voter. Its execution gate
// refuses only because it is not an active worker, which says nothing about
// whether the cluster is clean. Every other refusal still blocks resolution.
//
// Mutation: drop the local_not_active_worker exception — the first check goes
// red.
func TestResolveGateValid_WitnessOrDrainingLeaderResolves(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	s.SetGate(reasonGate{reason: health.ReasonLocalNotActiveWorker})
	if !s.resolveGateValid(ctx) {
		t.Fatalf("a quorate leader that is not an active worker (a witness) could not resolve")
	}
	for _, r := range []string{health.ReasonNoQuorum, health.ReasonSelfFenced, health.ReasonWarmup} {
		s.SetGate(reasonGate{reason: r})
		if s.resolveGateValid(ctx) {
			t.Errorf("execution gate refused as %s, yet resolution was valid", r)
		}
	}
}

// TestDualRunResolve_DeletedVMOwnerMismatch: an owner mismatch is a claim that
// the VM's DB owner disagrees with its runtime. Once the VM row is deleted
// there is no owner left to disagree with, so the condition resolves once
// every host it names is completely probed and clean, even while an unrelated
// host keeps the scan partial. A deleted VM has no created_at to date that
// host against, which used to hold the condition open for as long as the
// host stayed unreachable — with admission to both named hosts.
//
// This replaces the "workload is no longer in the DB" case of
// TestDualRunResolve_HostThatCouldHoldTheCopy_StillBlocks. A copy of the
// deleted VM on a host the condition does not name is not an owner mismatch:
// with no row the detector can never raise one for it again, and admission to
// that host was never gated by this condition.
//
// Mutation: return false for a VM absent from the index again — the first
// arm goes red. Drop the involved-host check — the second arm goes red.
func TestDualRunResolve_DeletedVMOwnerMismatch(t *testing.T) {
	t.Run("involved hosts probed", func(t *testing.T) {
		s := dualRunTestServer(t, 3)
		ctx := context.Background()
		seedVM(t, s, "vmA", "h1", "running")
		confirmOwnerMismatchWithH3Dark(t, s)

		if err := corrosion.DeleteVM(ctx, s.db, "vmA"); err != nil {
			t.Fatalf("DeleteVM: %v", err)
		}
		s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}, "h2": {}}, "h3")
		s.detectDualRunPass(ctx)
		s.detectDualRunPass(ctx)
		if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionResolved {
			t.Fatalf("owner mismatch on deleted vmA = %q after two clean passes over both named hosts, want resolved", got)
		}
	})
	t.Run("involved host unreachable", func(t *testing.T) {
		s := dualRunTestServer(t, 3)
		ctx := context.Background()
		seedVM(t, s, "vmA", "h1", "running")
		confirmOwnerMismatchWithH3Dark(t, s)

		if err := corrosion.DeleteVM(ctx, s.db, "vmA"); err != nil {
			t.Fatalf("DeleteVM: %v", err)
		}
		// h2, the host the condition saw running vmA, is the one now dark.
		s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}, "h3": {}}, "h2")
		s.detectDualRunPass(ctx)
		s.detectDualRunPass(ctx)
		if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionConfirmed {
			t.Fatalf("owner mismatch on deleted vmA = %q while h2, which it saw running vmA, is unreachable; want confirmed", got)
		}
	})
}
