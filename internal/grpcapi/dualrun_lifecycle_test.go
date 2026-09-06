package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

// TestApplyConditionLifecycle_ObserveConfirmResolve pins the exact contract
// dualRunDebounce/conditionCleanScans encode: 2 consecutive positive scans to
// confirm, 2 consecutive COMPLETE clean scans to resolve, and an incomplete
// scan advances neither the confirm streak nor the resolve streak.
func TestApplyConditionLifecycle_ObserveConfirmResolve(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	f := finding{kind: kindDualRunVM, target: "vm1"}
	details := map[finding]string{f: "VM vm1 is an active disk-holder on 2 hosts"}
	hosts := map[finding][]string{f: {"host-a", "host-b"}}

	// Pass 1: observed, not yet confirmed.
	s.applyConditionLifecycle(ctx, map[finding]bool{f: true}, details, hosts, true, "", nil)
	cond, ok, err := corrosion.GetHealthCondition(ctx, s.db, "dual_run", "vm_dual_run", "vm", "vm1")
	if err != nil || !ok {
		t.Fatalf("get after pass 1: ok=%v err=%v", ok, err)
	}
	if cond.Lifecycle != corrosion.ConditionObserved || cond.ObserveCount != 1 {
		t.Fatalf("after pass 1 = %#v, want observed/1", cond)
	}

	// Pass 2: confirms.
	s.applyConditionLifecycle(ctx, map[finding]bool{f: true}, details, hosts, true, "", nil)
	cond, ok, err = corrosion.GetHealthCondition(ctx, s.db, "dual_run", "vm_dual_run", "vm", "vm1")
	if err != nil || !ok || cond.Lifecycle != corrosion.ConditionConfirmed || cond.Severity != corrosion.SeverityCritical {
		t.Fatalf("after pass 2 = %#v (ok=%v err=%v), want confirmed/critical", cond, ok, err)
	}

	// Pass 3: absent, but coverage INCOMPLETE — must not advance the clean streak.
	s.applyConditionLifecycle(ctx, map[finding]bool{}, nil, nil, false, "host-c unreachable", []string{"host-c"})
	cond, ok, err = corrosion.GetHealthCondition(ctx, s.db, "dual_run", "vm_dual_run", "vm", "vm1")
	if err != nil || !ok || cond.Lifecycle != corrosion.ConditionConfirmed || cond.CleanCount != 0 {
		t.Fatalf("after incomplete-coverage absent pass = %#v (ok=%v err=%v), want STILL confirmed, clean_count=0", cond, ok, err)
	}

	// Pass 4 & 5: absent with COMPLETE coverage — two clean passes resolve it.
	s.applyConditionLifecycle(ctx, map[finding]bool{}, nil, nil, true, "", nil)
	cond, _, _ = corrosion.GetHealthCondition(ctx, s.db, "dual_run", "vm_dual_run", "vm", "vm1")
	if cond.Lifecycle != corrosion.ConditionConfirmed || cond.CleanCount != 1 {
		t.Fatalf("after 1st clean pass = %#v, want still confirmed, clean_count=1", cond)
	}
	s.applyConditionLifecycle(ctx, map[finding]bool{}, nil, nil, true, "", nil)
	cond, ok, err = corrosion.GetHealthCondition(ctx, s.db, "dual_run", "vm_dual_run", "vm", "vm1")
	if err != nil || !ok || cond.Lifecycle != corrosion.ConditionResolved || cond.ResolvedAt == "" {
		t.Fatalf("after 2nd clean pass = %#v (ok=%v err=%v), want resolved with ResolvedAt set", cond, ok, err)
	}
}

// TestApplyConditionLifecycle_HandoverPreservesCounts is the property the
// whole port exists for: a fresh *Server (simulating a new leader after
// handover) picks up the SAME condition where the old leader left it, because
// the state is a DB row, not an in-memory map.
func TestApplyConditionLifecycle_HandoverPreservesCounts(t *testing.T) {
	s1 := testServer(t)
	ctx := context.Background()
	f := finding{kind: kindDualRunVM, target: "vm1"}
	details := map[finding]string{f: "detail"}

	s1.applyConditionLifecycle(ctx, map[finding]bool{f: true}, details, nil, true, "", nil)

	// Simulate handover: a second Server sharing the same db, with its own
	// events bus (s.publish needs a non-nil *events.Bus; s.notify is safe with
	// a nil db check but this Server's db is the shared real one, so it will
	// actually query notification routes/targets — harmless with none configured).
	s2 := &Server{db: s1.db, hostName: "host-b", events: events.NewBus()}
	s2.applyConditionLifecycle(ctx, map[finding]bool{f: true}, details, nil, true, "", nil)

	cond, ok, err := corrosion.GetHealthCondition(ctx, s1.db, "dual_run", "vm_dual_run", "vm", "vm1")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if cond.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("after handover's 2nd pass, lifecycle = %q, want confirmed — the count must carry across leaders", cond.Lifecycle)
	}
	if cond.Reporter != "host-b" {
		t.Fatalf("reporter = %q, want host-b — the new leader's pass must be the one recorded", cond.Reporter)
	}
}
