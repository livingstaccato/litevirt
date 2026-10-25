package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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
	for _, vm := range []string{"vm1", "stoppedrow"} {
		giveUUID(t, fake, vm)
		if err := s.markStartPaused(vm); err != nil {
			t.Fatal(err)
		}
	}

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
	// Its row is stopped, as an interrupted operator `lv start` leaves it:
	// not finished by the sweep (v1.10.0), but named, its record kept
	// (rc9 lab F1).
	if st, _ := fake.RawState("stoppedrow"); st != libvirtfake.StatePaused {
		t.Fatalf("the recorded start of a VM whose row is stopped: %v, want it left paused", st)
	}
	if c, ok, _ := corrosion.GetHealthCondition(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", "stoppedrow@"+s.hostName); !ok || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("the recorded start of a VM whose row is stopped is not named")
	}
	if marked, _ := s.startPausedMarked("stoppedrow"); !marked {
		t.Fatal("the record of a start kept unfinished was dropped")
	}
	if marked, _ := s.startPausedMarked("vm1"); marked {
		t.Fatal("the finished start's record outlived it")
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
	if err := s.markStartPaused("vm1"); err != nil {
		t.Fatal(err)
	}
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

// R2-B1 (the review's probe, kept, and widened): the sweep resumes only a
// domain whose paused start this daemon recorded, and never one that anything
// else holds. A guest partition pause suspended reports the same paused
// reason ("user"); with its record only in memory when the daemon died, there
// is no record left on disk — but its mark is on the live domain. Each case
// below must stay paused:
//
//   - no start record, whatever else (an operator's or a snapshot's pause), and
//     the probe: partition-paused, its record lost;
//   - a start record AND the partition pause mark;
//   - a start record AND a partition pause record in the reserve layer;
//   - a start record AND a mark that cannot be read.
//
// Mutations: act on any user-paused domain (ignore the start record) — red;
// ignore the partition pause mark — red; ignore the pause record layers — red.
func TestResumeStrandedStarts_NeverResumesAGuestSomethingElseHolds(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, s *Server, fake *libvirtfake.Fake){
		"no start record, nothing else holds it": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {},
		"no start record, partition-paused": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := fake.MarkPartitionPaused("vm1", "tok-1"); err != nil {
				t.Fatal(err)
			}
		},
		"start record and the partition pause mark": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := s.markStartPaused("vm1"); err != nil {
				t.Fatal(err)
			}
			if err := fake.MarkPartitionPaused("vm1", "tok-1"); err != nil {
				t.Fatal(err)
			}
		},
		"start record and a reserve pause record": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := s.markStartPaused("vm1"); err != nil {
				t.Fatal(err)
			}
			if err := health.WritePauseRecordToReserveForTests(s.dataDir, health.PauseRecord{Kind: health.PauseKindVM, Name: "vm1"}); err != nil {
				t.Fatal(err)
			}
		},
		"start record and an unreadable mark": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := s.markStartPaused("vm1"); err != nil {
				t.Fatal(err)
			}
			fake.FailPartitionPauseMark = func(string) error { return errors.New("metadata unreadable") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := vlanStartServer(t)
			ctx := adminCtx()
			if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "running", ""); err != nil {
				t.Fatal(err)
			}
			giveUUID(t, fake, "vm1") // so the record's incarnation matches, and only the hold keeps it paused
			fake.SetState("vm1", libvirtfake.StatePaused)
			setup(t, s, fake)
			s.ResumeStrandedStarts(context.Background())
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
				t.Fatalf("the sweep resumed a guest something else holds: state %v", st)
			}
		})
	}
}

// The guard records a paused start before the paused create, and drops the
// record once the start has ended — here refused while paused.
//
// Mutation: no markStartPaused in Before — red; no PausedDone — red.
func TestNICStartGuard_RecordsAPausedStartWhileItRuns(t *testing.T) {
	s, fake := vlanStartServer(t)
	var during bool
	fake.FailConfigureVLANTap = func(string, string, int) error {
		during, _ = s.startPausedMarked("vm1")
		return errors.New("no")
	}
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("the start ran")
	}
	if !during {
		t.Fatal("no record of the paused start while it was paused")
	}
	if marked, _ := s.startPausedMarked("vm1"); marked {
		t.Fatal("the record outlived the start")
	}
}

// giveUUID defines name in the fake with a uuid of its own, as libvirt always
// has one: a start record names it (NB-R14).
func giveUUID(t *testing.T, fake *libvirtfake.Fake, name string) {
	t.Helper()
	st, _ := fake.RawState(name)
	u := fmt.Sprintf("%08x-0000-4000-8000-000000000000", len(name)*7919)
	if err := fake.DefineDomain(`<domain type='kvm'><name>` + name + `</name><uuid>` + u + `</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if st != "" {
		fake.SetState(name, st)
	}
}
