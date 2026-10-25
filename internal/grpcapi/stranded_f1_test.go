package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

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

// F1 (a): an operator `lv start` writes running only once the domain is up,
// so its row is still stopped; a restart-policy start leaves error. A daemon
// killed in either's paused window leaves a recorded start of this
// incarnation that the sweep finishes — VLANs on, then the resume — as it
// does a reconciler start's.
//
// Mutation: only running/starting rows finishable (the old rule) — red.
func TestResumeStrandedStarts_FinishesAnOperatorOrRestartPolicyStart(t *testing.T) {
	for _, state := range []string{"stopped", "error"} {
		t.Run(state, func(t *testing.T) {
			s, fake := leftPaused(t, state)
			before := len(vlanDomainOps(fake, "vm1"))
			s.ResumeStrandedStarts(context.Background())
			ops := vlanDomainOps(fake, "vm1")[before:]
			tap, resume := opIndex(ops, "vlan-tap"), opIndex(ops, "resume")
			if tap < 0 || resume < tap {
				t.Fatalf("row %s: ops %q, want the VLAN on, then the resume", state, ops)
			}
			if marked, _ := s.startPausedMarked("vm1"); marked {
				t.Fatal("the finished start's record outlived it")
			}
		})
	}
}

// F1 (b): every recorded start the sweep keeps without finishing is named by
// vm_start_stranded_paused — never silence — but for one something else
// holds, which reports itself (M3).
//
// Mutations: no condition on the refused branch — red; a condition on the
// held branch — red.
func TestResumeStrandedStarts_NamesEveryStartItKeeps(t *testing.T) {
	for name, tc := range map[string]struct {
		state string
		setup func(*Server, *libvirtfake.Fake)
		named bool
	}{
		"row in a state no unfinished start leaves": {state: "migrating", named: true},
		"domain state unreadable": {state: "running", named: true, setup: func(s *Server, f *libvirtfake.Fake) {
			f.FailDomainStateReason = func(string) error { return errors.New("connection reset by peer") }
		}},
		"held by partition pause": {state: "running", named: false, setup: func(s *Server, f *libvirtfake.Fake) {
			if err := f.MarkPartitionPaused("vm1", "tok-1"); err != nil {
				panic(err)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := leftPaused(t, tc.state)
			if tc.setup != nil {
				tc.setup(s, fake)
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

// F1 (c): `lv start` of a VM a start of this host left paused finishes that
// start — VLANs on, then the resume, the row running — instead of failing
// with "domain is already running"; and it never drops the record of a start
// it does not finish: one held by something else is refused, record kept.
//
// Mutations: no finishStartLeftPaused in startVMLocked — red; the guard
// taking the record over (no refusal in Before) — red.
func TestStartVM_FinishesAStartLeftPaused(t *testing.T) {
	s, fake := leftPaused(t, "stopped")
	before := len(vlanDomainOps(fake, "vm1"))
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("StartVM of a start left paused: %v", err)
	}
	ops := vlanDomainOps(fake, "vm1")[before:]
	tap, resume, start := opIndex(ops, "vlan-tap"), opIndex(ops, "resume"), opIndex(ops, "start")
	if tap < 0 || resume < tap || start >= 0 {
		t.Fatalf("ops %q: want the VLAN on and the resume, and no second create", ops)
	}
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StateRunning {
		t.Fatalf("domain %v, want running", st)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "vm1"); vm == nil || vm.State != "running" {
		t.Fatalf("row %+v, want running", vm)
	}
	if marked, _ := s.startPausedMarked("vm1"); marked {
		t.Fatal("the finished start's record outlived it")
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

// F1 (d): `lv stop` (not --force) of a paused domain stops it: a paused
// guest cannot answer an ACPI shutdown, so it is killed, as the timeout would.
//
// Mutation: no paused branch in stopLocked — red.
func TestStopVM_StopsAPausedDomain(t *testing.T) {
	s, fake := leftPaused(t, "running")
	// As libvirt answers a shutdown of a paused guest (rc9 lab F1).
	fake.FailShutdownDomain = func(name string) error {
		if st, _ := fake.RawState(name); st == libvirtfake.StatePaused {
			return errors.New("Requested operation is not valid: domain is not running")
		}
		return nil
	}
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("StopVM of a paused domain: %v", err)
	}
	if st, _ := fake.RawState("vm1"); st == libvirtfake.StatePaused || st == libvirtfake.StateRunning {
		t.Fatalf("domain %v after the stop, want shut off", st)
	}
	if marked, _ := s.startPausedMarked("vm1"); marked {
		t.Fatal("the record of the start the stop ended outlived it")
	}
}

// A plain `lv stop` kills only a guest a start left paused (its record names
// this incarnation): that guest never ran. Any other paused guest — an I/O
// error's, a partition pause's, one whose record names another incarnation —
// has run, and a kill loses what it has not flushed: the plain stop is refused,
// naming the pause and the choices, and the guest is left as it is. `lv stop
// --force` stops it.
//
// Mutations: kill any paused guest on a plain stop (no record check) — red;
// skip the uuid match — red (the other-incarnation case is killed).
func TestStopVM_APlainStopRefusesAGuestThatHasRun(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, s *Server, fake *libvirtfake.Fake){
		"io-error pause": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			fake.SetState("vm1", libvirtfake.StateRunning)
			if err := fake.PauseOnIOError("vm1"); err != nil {
				t.Fatal(err)
			}
		},
		"partition pause": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			fake.SetState("vm1", libvirtfake.StatePaused)
			if err := fake.MarkPartitionPaused("vm1", "tok-1"); err != nil {
				t.Fatal(err)
			}
		},
		"a record of another incarnation": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
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
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := vlanStartServer(t)
			if err := corrosion.UpdateVMState(adminCtx(), s.db, "vm1", "running", ""); err != nil {
				t.Fatal(err)
			}
			setup(t, s, fake)
			fake.FailShutdownDomain = func(name string) error {
				if st, _ := fake.RawState(name); st == libvirtfake.StatePaused {
					return errors.New("Requested operation is not valid: domain is not running")
				}
				return nil
			}
			_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "paused") ||
				!strings.Contains(err.Error(), "lv stop --force vm1") {
				t.Fatalf("a plain stop of a paused guest that has run: %v, want FailedPrecondition naming the pause and --force", err)
			}
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
				t.Fatalf("the refused stop changed the guest: %v", st)
			}
			if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
				t.Fatalf("lv stop --force of a paused guest: %v", err)
			}
			if st, _ := fake.RawState("vm1"); st == libvirtfake.StatePaused || st == libvirtfake.StateRunning {
				t.Fatalf("after --force the guest is %v, want shut off", st)
			}
		})
	}
}
