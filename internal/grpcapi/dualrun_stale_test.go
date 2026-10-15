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

// TestDualRunResolve_DeletedVMStillOnANamedHost: a deleted VM's mismatch can
// never be raised again (no row, no owner), so a clean scan of its named hosts
// proves nothing by itself. It resolves only on positive absence: every named
// host completely probed and holding no domain of that name in any state. A
// named host that still runs the domain, or keeps it defined, holds the
// condition open, even under complete coverage, and each such pass refreshes
// last_seen, so `lv health resolve` sees the detector still finds it.
//
// Mutations: drop the presence check — every "stays" arm goes red; apply it
// only after the complete-coverage short-circuit — the complete arms go red;
// drop the last_seen refresh — the refresh check goes red.
func TestDualRunResolve_DeletedVMStillOnANamedHost(t *testing.T) {
	for _, tc := range []struct {
		name  string
		h2    runtimeSnapshot
		dark  []string
		stays bool
	}{
		{"running on a named host, complete scan", runtimeSnapshot{diskHolderVMs: []string{"vmA"}}, nil, true},
		{"defined shut off on a named host, complete scan", runtimeSnapshot{definedVMs: []string{"vmA"}}, nil, true},
		{"defined on a named host, another host dark", runtimeSnapshot{definedVMs: []string{"vmA"}}, []string{"h3"}, true},
		{"gone from every named host", runtimeSnapshot{}, []string{"h3"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dualRunTestServer(t, 3)
			ctx := context.Background()
			seedVM(t, s, "vmA", "h1", "running")
			s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
				"h1": {}, "h2": {diskHolderVMs: []string{"vmA"}}, "h3": {},
			})
			s.detectDualRunPass(ctx)
			s.detectDualRunPass(ctx)
			if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionConfirmed {
				t.Fatalf("setup: %q", got)
			}
			backdateLastSeen(t, s, kindOwnerMismatch, "vmA")
			if err := corrosion.DeleteVM(ctx, s.db, "vmA"); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			snaps := map[string]runtimeSnapshot{"h1": {}, "h2": tc.h2}
			if len(tc.dark) == 0 {
				snaps["h3"] = runtimeSnapshot{}
			}
			s.gatherRuntimeOverride = fixedGather(snaps, tc.dark...)
			for i := 0; i < 3; i++ {
				s.detectDualRunPass(ctx)
			}
			got := readCond(t, s, kindOwnerMismatch, "vmA")
			if tc.stays {
				if got.Lifecycle != corrosion.ConditionConfirmed {
					t.Fatalf("lifecycle = %q, want confirmed while h2 still has vmA", got.Lifecycle)
				}
				if got.LastSeen == backdated {
					t.Errorf("last_seen not refreshed while h2 still has vmA")
				}
				return
			}
			if got.Lifecycle != corrosion.ConditionResolved {
				t.Fatalf("lifecycle = %q, want resolved once vmA is gone from h1 and h2", got.Lifecycle)
			}
		})
	}
}

const backdated = "2026-01-01T00:00:00Z"

// backdateLastSeen moves a condition's last_seen into the past, as if the
// detector last saw it well before the passes that follow.
func backdateLastSeen(t *testing.T, s *Server, kind, target string) {
	t.Helper()
	h := readCond(t, s, kind, target)
	h.LastSeen = backdated
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, h); err != nil {
		t.Fatal(err)
	}
}

// TestSnapshotFromInventory_DefinedVMsInAnyState: the deleted-VM rule needs
// every domain a host has, not only the running ones.
func TestSnapshotFromInventory_DefinedVMsInAnyState(t *testing.T) {
	snap := snapshotFromInventory(runtimeInventory{Complete: true, Workloads: []runtimeWorkload{
		{Kind: corrosion.WorkloadVM, Name: "off", State: health.RuntimeDefinedStopped},
		{Kind: corrosion.WorkloadVM, Name: "on", State: health.RuntimeRunning, DiskHolder: true},
		{Kind: corrosion.WorkloadContainer, Name: "ct", State: health.RuntimeRunning},
	}})
	if !containsString(snap.definedVMs, "off") || !containsString(snap.definedVMs, "on") || containsString(snap.definedVMs, "ct") {
		t.Fatalf("definedVMs = %v, want off and on only", snap.definedVMs)
	}
}

// TestCanResolve_DeletedVMNeedsPositiveAbsence pins the rule on its own,
// below the lifecycle's refresh: under COMPLETE coverage, a deleted VM's
// mismatch resolves only when no named host has a domain of that name.
//
// Mutations: drop the presence check, or move the rule after the
// complete-coverage short-circuit — the first check goes red.
func TestCanResolve_DeletedVMNeedsPositiveAbsence(t *testing.T) {
	f := finding{kind: kindOwnerMismatch, target: "vmA"}
	row := corrosion.HealthCondition{Hosts: []string{"h1", "h2"}}
	rc := resolutionCoverage{complete: true, dbOK: true, vmCreated: map[string]string{},
		snaps: map[string]runtimeSnapshot{"h1": {}, "h2": {definedVMs: []string{"vmA"}}}}
	if rc.canResolve(f, row) {
		t.Fatal("resolved a deleted VM's mismatch while h2 still has the domain")
	}
	rc.snaps["h2"] = runtimeSnapshot{}
	if !rc.canResolve(f, row) {
		t.Fatal("did not resolve once no named host has the domain")
	}
}
