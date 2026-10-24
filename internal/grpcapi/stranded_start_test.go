package grpcapi

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// NB-R1: a start an earlier daemon left created-paused (it died between the
// paused create and the resume) is finished at startup through the guard —
// its VLANs on, then resumed — and one that cannot be is named by
// vm_start_stranded_paused, which resolves once the domain no longer is.
// A paused domain whose row says it is not running here, and one a hand-over
// holds, are left alone.
//
// Mutations: ResumeStrandedStarts resuming without readyGuestHere — red (no
// VLAN before the resume); not raising the condition on a failure — red;
// JudgeStrandedStarts never resolving — red.
func TestResumeStrandedStarts(t *testing.T) {
	s, fake := vlanStartServer(t)
	ctx := adminCtx()
	cond := func() (corrosion.HealthCondition, bool) {
		c, ok, err := corrosion.GetHealthCondition(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", "vm1@"+s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		return c, ok
	}
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "starting", ""); err != nil {
		t.Fatal(err)
	}
	insertTestVMWithSpec(t, ctx, s.db, "stoppedrow", "test-host", "stopped", `{"name":"stoppedrow"}`)
	fake.SetState("stoppedrow", libvirtfake.StatePaused)

	// The tap cannot be configured: it stays paused, named.
	fake.SetState("vm1", libvirtfake.StatePaused)
	fake.FailConfigureVLANTap = func(string, string, int) error { return errors.New("no") }
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("vm1 is %v after a failed finish, want still paused", st)
	}
	if c, ok := cond(); !ok || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("the stranded start is not named: %+v (found %v)", c, ok)
	}

	// Next daemon start, the tap can be configured: readied, then resumed.
	fake.FailConfigureVLANTap = nil
	before := len(vlanDomainOps(fake, "vm1"))
	s.ResumeStrandedStarts(context.Background())
	ops := vlanDomainOps(fake, "vm1")[before:]
	tap, resume := opIndex(ops, "vlan-tap"), opIndex(ops, "resume")
	if tap < 0 || resume < tap {
		t.Fatalf("ops = %q: want the VLAN on, then the resume", ops)
	}
	if c, _ := cond(); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the condition after the finish: %s, want resolved", c.Lifecycle)
	}
	if st, _ := fake.RawState("stoppedrow"); st != libvirtfake.StatePaused {
		t.Fatal("a paused domain whose row is not running here was resumed")
	}
}

// JudgeStrandedStarts resolves the condition for a guest that was stopped or
// resumed by other means, and resumes nothing itself.
func TestJudgeStrandedStarts_ResolvesWithoutResuming(t *testing.T) {
	s, fake := vlanStartServer(t)
	ctx := adminCtx()
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "running", ""); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StatePaused)
	s.judgeStrandedStart(ctx, "vm1", errors.New("x"))
	s.JudgeStrandedStarts(ctx)
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatal("JudgeStrandedStarts resumed a guest")
	}
	if c, _, _ := corrosion.GetHealthCondition(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", "vm1@"+s.hostName); c.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("resolved while the guest is still a stranded start")
	}
	fake.SetState("vm1", libvirtfake.StateShutdown)
	s.JudgeStrandedStarts(ctx)
	if c, _, _ := corrosion.GetHealthCondition(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", "vm1@"+s.hostName); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("after the guest stopped: %s, want resolved", c.Lifecycle)
	}
}
