package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// leftPaused sets vm1 up as a start an interrupted daemon left paused: its
// own incarnation (a uuid, recorded), its domain paused, its row in state.
func leftPaused(t *testing.T, state string) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, fake := vlanStartServer(t)
	if err := corrosion.UpdateVMState(adminCtx(), s.db, "vm1", state, ""); err != nil {
		t.Fatal(err)
	}
	giveUUID(t, fake, "vm1")
	if err := s.markStartPaused("vm1"); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StatePaused)
	return s, fake
}

func strandedCond(t *testing.T, s *Server) (corrosion.HealthCondition, bool) {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(adminCtx(), s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", "vm1@"+s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	return c, ok && c.Lifecycle != corrosion.ConditionResolved
}

// failShutdownPaused makes the fake answer a shutdown of a paused guest as
// libvirt does (rc9 lab F1).
func failShutdownPaused(fake *libvirtfake.Fake) {
	fake.FailShutdownDomain = func(name string) error {
		if st, _ := fake.RawState(name); st == libvirtfake.StatePaused {
			return errors.New("Requested operation is not valid: domain is not running")
		}
		return nil
	}
}

// assertNeverRanGuidance fails unless text tells the operator what to do
// with a start left paused whose guest never ran.
func assertNeverRanGuidance(t *testing.T, text string) {
	t.Helper()
	for _, want := range []string{"never ran", "`lv stop --force vm1` loses nothing", "`lv start vm1`"} {
		if !strings.Contains(text, want) {
			t.Fatalf("guidance %q does not say %q", text, want)
		}
	}
}

// F1, scoped down for v1.10.0: the sweep finishes only a recorded start whose
// row is running or starting (the reconciler's). An operator `lv start` (row
// still stopped) and a restart-policy start (row error or crashed) left
// paused are not finished — that needs the gates such a start passes, which
// is v1.10.1's — but named, telling the operator what to do. The row is not
// touched (review I1).
//
// Mutations: stopped/error/crashed finishable again — red (resumed); no
// condition on the refused branch — red; the never-ran guidance dropped from
// strandedRemedy — red.
func TestResumeStrandedStarts_NamesAnOperatorOrRestartPolicyStart(t *testing.T) {
	for _, state := range []string{"stopped", "error", "crashed"} {
		t.Run(state, func(t *testing.T) {
			s, fake := leftPaused(t, state)
			if state == "stopped" {
				if err := corrosion.UpdateVMState(adminCtx(), s.db, "vm1", "stopped", "operator-stop"); err != nil {
					t.Fatal(err)
				}
			}
			before := len(vlanDomainOps(fake, "vm1"))
			s.ResumeStrandedStarts(context.Background())
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
				t.Fatalf("row %s: the domain is %v, want it left paused", state, st)
			}
			if ops := vlanDomainOps(fake, "vm1")[before:]; opIndex(ops, "resume") >= 0 || opIndex(ops, "destroy") >= 0 {
				t.Fatalf("row %s: ops %q, want nothing done to the domain", state, ops)
			}
			if marked, _ := s.startPausedMarked("vm1"); !marked {
				t.Fatal("the record of a start kept unfinished was dropped")
			}
			c, named := strandedCond(t, s)
			if !named {
				t.Fatalf("row %s: the start left paused is not named", state)
			}
			assertNeverRanGuidance(t, c.Evidence)
			if row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1"); row == nil || row.State != state {
				t.Fatalf("row %+v, want it left %s", row, state)
			}
		})
	}
}

// Every recorded start the sweep keeps without finishing is named by
// vm_start_stranded_paused — never silence — but for one something else
// holds (partition pause, a hand-over), which reports itself (M3).
//
// Mutations: no condition on the refused branch — red; a condition on the
// held branch — red; no hand-over check in classifyStrandedStart — red (the
// held guest is resumed: review M6).
func TestResumeStrandedStarts_NamesEveryStartItKeeps(t *testing.T) {
	for name, tc := range map[string]struct {
		state string
		setup func(*testing.T, *Server, *libvirtfake.Fake)
		named bool
	}{
		"row in a state no unfinished start leaves": {state: "migrating", named: true},
		"domain state unreadable": {state: "running", named: true, setup: func(t *testing.T, s *Server, f *libvirtfake.Fake) {
			f.FailDomainStateReason = func(string) error { return errors.New("connection reset by peer") }
		}},
		"held by partition pause": {state: "running", named: false, setup: func(t *testing.T, s *Server, f *libvirtfake.Fake) {
			if err := f.MarkPartitionPaused("vm1", "tok-1"); err != nil {
				t.Fatal(err)
			}
		}},
		"held by a hand-over": {state: "running", named: false, setup: func(t *testing.T, s *Server, f *libvirtfake.Fake) {
			if err := s.putHeld(heldGuest{VM: "vm1", Source: "other-host", Since: time.Now().UTC().Format(time.RFC3339)}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := leftPaused(t, tc.state)
			if tc.setup != nil {
				tc.setup(t, s, fake)
			}
			s.ResumeStrandedStarts(context.Background())
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
				t.Fatalf("resumed: %v", st)
			}
			if _, named := strandedCond(t, s); named != tc.named {
				t.Fatalf("named = %v, want %v", named, tc.named)
			}
			if marked, _ := s.startPausedMarked("vm1"); !marked {
				t.Fatal("the record of a start kept unfinished was dropped")
			}
		})
	}
}

// Review m2: a start left paused here whose VM's row now names another host
// (failover moved it while this daemon was down) is a paused qemu here while
// another host may run the VM. One copy at every moment: it is neither
// resumed nor killed, its record is kept, and it is named, with both hosts.
//
// Mutation: drop the record on another host's row (the old rule) — red.
func TestResumeStrandedStarts_NamesAStartWhoseRowIsAnotherHosts(t *testing.T) {
	s, fake := leftPaused(t, "running")
	if err := corrosion.UpdateVMHost(adminCtx(), s.db, "vm1", "other-host", "running"); err != nil {
		t.Fatal(err)
	}
	before := len(vlanDomainOps(fake, "vm1"))
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("the domain is %v, want it left paused", st)
	}
	if ops := vlanDomainOps(fake, "vm1")[before:]; len(ops) != 0 {
		t.Fatalf("ops %q, want nothing done to the domain", ops)
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("the record was dropped")
	}
	c, named := strandedCond(t, s)
	if !named {
		t.Fatal("a paused qemu here, while the row names another host, is not named")
	}
	for _, want := range []string{"other-host", s.hostName, "`virsh destroy vm1`", "never ran"} {
		if !strings.Contains(c.Evidence, want) {
			t.Fatalf("condition %q does not name %q", c.Evidence, want)
		}
	}
	// The condition holds while the domain stays, and resolves once it goes.
	s.JudgeStrandedStarts(adminCtx())
	if _, named := strandedCond(t, s); !named {
		t.Fatal("resolved while the paused domain is still here")
	}
	fake.SetState("vm1", libvirtfake.StateShutdown)
	s.JudgeStrandedStarts(adminCtx())
	if _, named := strandedCond(t, s); named {
		t.Fatal("still named once the domain was stopped")
	}
}

// `lv start` of a VM a start of this host left paused does not finish that
// start, nor start the VM again over it: it is refused with the guidance the
// condition gives, nothing is done to the domain, and the record is kept
// (no start path deletes a record it did not finish; review I2, I3). The row
// running (the sweep's own case) is refused the same way.
//
// Mutations: no startLeftPausedRefusal in startVMLocked — red (the guard's
// refusal is not the guidance); finishing the start again — red.
func TestStartVM_RefusesAStartLeftPaused(t *testing.T) {
	for _, state := range []string{"stopped", "error", "running"} {
		t.Run(state, func(t *testing.T) {
			s, fake := leftPaused(t, state)
			before := len(vlanDomainOps(fake, "vm1"))
			_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"})
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("StartVM of a start left paused: %v, want FailedPrecondition", err)
			}
			assertNeverRanGuidance(t, status.Convert(err).Message())
			if ops := vlanDomainOps(fake, "vm1")[before:]; len(ops) != 0 {
				t.Fatalf("ops %q, want nothing done to the domain", ops)
			}
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
				t.Fatalf("domain %v, want still paused", st)
			}
			if marked, _ := s.startPausedMarked("vm1"); !marked {
				t.Fatal("the record of a start not finished was dropped")
			}
			if row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1"); row == nil || row.State != state {
				t.Fatalf("row %+v, want it left %s", row, state)
			}
		})
	}
}

func TestStartVM_NeverDropsTheRecordOfAStartItDoesNotFinish(t *testing.T) {
	s, fake := leftPaused(t, "stopped")
	if err := fake.MarkPartitionPaused("vm1", "tok-1"); err != nil {
		t.Fatal(err)
	}
	_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "partition pause") {
		t.Fatalf("StartVM of a held start left paused: %v, want FailedPrecondition naming the hold", err)
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("the record of a start not finished was dropped")
	}
	// Straight at the guard too (a start path that does not go through
	// StartVM): it refuses, and the record stays.
	if err := fake.StartDomain("vm1"); err == nil {
		t.Fatal("the guard started over a start left paused")
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("the guard dropped the record of a start not finished")
	}
}

// The guard's refusal of a start over a start left paused changes nothing:
// a hand-over record on the domain stays too (it is asked before endHeld).
//
// Mutation: ask after endHeld (the old order) — red.
func TestNICStartGuard_RefusalOverAStartLeftPausedKeepsAHandOver(t *testing.T) {
	s, fake := leftPaused(t, "running")
	if err := s.putHeld(heldGuest{VM: "vm1", Source: "other-host", Since: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain("vm1"); err == nil {
		t.Fatal("the guard started over a start left paused")
	}
	if _, held, _ := s.getHeld("vm1"); !held {
		t.Fatal("a refused start dropped the hand-over record")
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("a refused start dropped the start record")
	}
}

// A plain `lv stop` never kills a paused guest (review C1): whatever paused
// it — a start left paused, an I/O error, partition pause, with or without a
// start record — the stop is refused, saying why it is paused and that
// `lv stop --force` destroys it, and the guest is left as it is. `lv stop
// --force` then destroys it and removes its start record, so none is left
// behind to name a later run.
//
// Mutations: a plain stop kills a paused guest with a uuid-matched record
// (765201126's branch) — red; --force keeping the record — red.
func TestStopVM_APlainStopNeverKillsAPausedGuest(t *testing.T) {
	ioError := func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
		fake.SetState("vm1", libvirtfake.StateRunning)
		if err := fake.PauseOnIOError("vm1"); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		record bool // a uuid-matched start record (leftPaused)
		setup  func(t *testing.T, s *Server, fake *libvirtfake.Fake)
		want   string
	}{
		"a start left paused":       {record: true, want: "never ran"},
		"record and io-error pause": {record: true, setup: ioError, want: "io-error"},
		"record and partition pause": {record: true, want: "partition pause", setup: func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := fake.MarkPartitionPaused("vm1", "tok-1"); err != nil {
				t.Fatal(err)
			}
		}},
		"io-error pause, no record": {setup: ioError, want: "io-error"},
		"partition pause, no record": {want: "paused", setup: func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			fake.SetState("vm1", libvirtfake.StatePaused)
			if err := fake.MarkPartitionPaused("vm1", "tok-1"); err != nil {
				t.Fatal(err)
			}
		}},
		"a record of another incarnation": {want: "another incarnation", setup: func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := fake.DefineDomain(`<domain type='kvm'><name>vm1</name><uuid>11111111-1111-1111-1111-111111111111</uuid></domain>`); err != nil {
				t.Fatal(err)
			}
			if err := s.markStartPaused("vm1"); err != nil {
				t.Fatal(err)
			}
			if err := fake.UndefineDomain("vm1", false); err != nil {
				t.Fatal(err)
			}
			if err := fake.DefineDomain(`<domain type='kvm'><name>vm1</name><uuid>22222222-2222-2222-2222-222222222222</uuid></domain>`); err != nil {
				t.Fatal(err)
			}
			fake.SetState("vm1", libvirtfake.StatePaused)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			var s *Server
			var fake *libvirtfake.Fake
			if tc.record {
				s, fake = leftPaused(t, "running")
			} else {
				s, fake = vlanStartServer(t)
				if err := corrosion.UpdateVMState(adminCtx(), s.db, "vm1", "running", ""); err != nil {
					t.Fatal(err)
				}
			}
			if tc.setup != nil {
				tc.setup(t, s, fake)
			}
			failShutdownPaused(fake)
			markedBefore, _ := s.startPausedMarked("vm1")
			_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"})
			msg := status.Convert(err).Message()
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(msg, "is paused") ||
				!strings.Contains(msg, "graceful stop is impossible") || !strings.Contains(msg, "`lv stop --force vm1` destroys it") ||
				!strings.Contains(msg, tc.want) {
				t.Fatalf("a plain stop of a paused guest: %v, want FailedPrecondition naming the pause (%q) and --force", err, tc.want)
			}
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
				t.Fatalf("the refused stop changed the guest: %v", st)
			}
			if marked, _ := s.startPausedMarked("vm1"); marked != markedBefore {
				t.Fatalf("the refused stop changed the start record: %v, was %v", marked, markedBefore)
			}
			if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
				t.Fatalf("lv stop --force of a paused guest: %v", err)
			}
			if st, _ := fake.RawState("vm1"); st == libvirtfake.StatePaused || st == libvirtfake.StateRunning {
				t.Fatalf("after --force the guest is %v, want shut off", st)
			}
			if marked, _ := s.startPausedMarked("vm1"); marked {
				t.Fatal("lv stop --force left the start record behind")
			}
		})
	}
}

// The review's probe (C1), ported: `lv stop --force` of a start left paused
// leaves no record behind; the VM run again by a path that does not touch
// the record, then paused on an I/O error, is not killed by a plain stop.
//
// Mutation: --force keeping the record — red.
func TestStopVM_NoStaleRecordAfterForceStop(t *testing.T) {
	s, fake := leftPaused(t, "running")
	failShutdownPaused(fake)
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("force stop: %v", err)
	}
	if marked, _ := s.startPausedMarked("vm1"); marked {
		t.Fatal("lv stop --force left the start record behind")
	}
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := fake.PauseOnIOError("vm1"); err != nil {
		t.Fatal(err)
	}
	_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a plain stop of an io-error-paused guest: %v, want refused", err)
	}
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("a plain stop changed an io-error-paused guest that ran: %v", st)
	}
}
