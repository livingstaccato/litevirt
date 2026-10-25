package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// staleRecordSuspended is vm1 with a uuid-matched start record left from an
// earlier start, whose guest then ran and was suspended (an operator's
// `virsh suspend`): libvirt says paused (user), as for a start left paused,
// but QEMU says paused, not prelaunch.
func staleRecordSuspended(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, fake := leftPaused(t, "running")
	fake.SetState("vm1", libvirtfake.StateRunning) // the guest ran
	if err := fake.SuspendDomain("vm1"); err != nil {
		t.Fatal(err)
	}
	return s, fake
}

func assertNotNeverRan(t *testing.T, text string) {
	t.Helper()
	if strings.Contains(text, "loses nothing") || strings.Contains(text, "nothing is lost") || strings.Contains(text, "never ran (prelaunch)") {
		t.Fatalf("a guest that ran is described as never-ran: %q", text)
	}
	if !strings.Contains(text, "discards any guest state not flushed to disk") || !strings.Contains(text, "decide whether that matters") {
		t.Fatalf("%q does not say that --force discards unflushed guest state and the operator must decide", text)
	}
}

// Review F7 I1, probe F7-P1 ported: libvirt's "user" pause reason is no
// proof a guest never ran. A stale uuid-matched record on a guest that ran
// and was suspended gets no "never ran" from the plain-stop refusal, `lv
// start`, or the condition; each says --force discards unflushed state and
// the operator decides.
//
// Mutation: neverRan from the pause reason and uuid alone (no QEMU status)
// — red.
func TestStrandedStart_AUserPauseIsNoProofTheGuestNeverRan(t *testing.T) {
	s, fake := staleRecordSuspended(t)
	failShutdownPaused(fake)
	_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("plain stop of a suspended guest: %v, want refused", err)
	}
	assertNotNeverRan(t, status.Convert(err).Message())
	_, err = s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("lv start of a suspended guest with a start record: %v, want refused", err)
	}
	assertNotNeverRan(t, status.Convert(err).Message())
	s.ResumeStrandedStarts(context.Background())
	c, named := strandedCond(t, s)
	if !named {
		t.Fatal("the sweep did not name the suspended guest it keeps")
	}
	assertNotNeverRan(t, c.Evidence)
}

// Review F7 I1, probe F7-P2 ported: the sweep never resumes a guest QEMU
// does not report prelaunch, though its row is running here and its record
// names its incarnation. One whose QEMU status cannot be read is not
// resumed either.
//
// Mutations: Finish without the QEMU proof — red; an unreadable status taken
// as prelaunch — red.
func TestResumeStrandedStarts_ResumesOnlyAProvenNeverRanGuest(t *testing.T) {
	for name, setup := range map[string]func(*testing.T) (*Server, *libvirtfake.Fake){
		"suspended after it ran": staleRecordSuspended,
		"QEMU status unreadable": func(t *testing.T) (*Server, *libvirtfake.Fake) {
			s, fake := leftPaused(t, "running")
			fake.FailQEMUStatus = func(string) error { return errors.New("monitor connection reset") }
			return s, fake
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := setup(t)
			s.ResumeStrandedStarts(context.Background())
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
				t.Fatalf("the sweep left the guest %v, want paused", st)
			}
			c, named := strandedCond(t, s)
			if !named || !strings.Contains(c.Evidence, "cannot be shown that its guest never ran") {
				t.Fatalf("not named as unproven: %+v (named %v)", c, named)
			}
			if marked, _ := s.startPausedMarked("vm1"); !marked {
				t.Fatal("the record was dropped")
			}
		})
	}
	// And the proven case is still finished (rc9's).
	s, fake := leftPaused(t, "running")
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StateRunning {
		t.Fatalf("a proven never-ran start whose row is running: %v, want finished", st)
	}
}

// An I/O-error pause is no start's: with a record naming its incarnation it
// is still not called never-ran (review F7 X6).
func TestStopVM_AnIOErrorPauseWithARecordIsNotNeverRan(t *testing.T) {
	s, fake := leftPaused(t, "running")
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := fake.PauseOnIOError("vm1"); err != nil {
		t.Fatal(err)
	}
	failShutdownPaused(fake)
	_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("plain stop: %v, want refused", err)
	}
	assertNotNeverRan(t, status.Convert(err).Message())
}

// Review F7 m2, probe F7-P3 ported: a VM deleted while its start was left
// paused here leaves a paused qemu holding its disks. The record is kept,
// and the domain named, neither resumed nor killed.
//
// Mutation: drop the record of a deleted row (the old rule) — red.
func TestResumeStrandedStarts_NamesAStartWhoseVMIsDeleted(t *testing.T) {
	s, fake := leftPaused(t, "running")
	if err := corrosion.DeleteVM(adminCtx(), s.db, "vm1"); err != nil {
		t.Fatal(err)
	}
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("domain %v, want left paused", st)
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("the record of a deleted VM's paused domain was dropped")
	}
	c, named := strandedCond(t, s)
	if !named {
		t.Fatal("a deleted VM's paused qemu is not named")
	}
	for _, want := range []string{"row is gone", "`virsh destroy vm1`", "never ran"} {
		if !strings.Contains(c.Evidence, want) {
			t.Fatalf("condition %q does not say %q", c.Evidence, want)
		}
	}
}

// Review F7 X16: a domain a live firmware move holds is that move's: the
// sweep neither resumes nor names it, and keeps its record.
//
// Mutation: no firmware-move hold check in classifyStrandedStart — red.
func TestResumeStrandedStarts_LeavesAFirmwareMoveHoldAlone(t *testing.T) {
	s, fake := leftPaused(t, "running")
	h := fwmig.Hold{VM: "vm1", Source: "src-host", State: fwmig.HoldPrepared, Since: time.Now(), UEFI: true,
		NvramMaterialised: fwmig.NvramPending,
		Binding:           fwmig.Binding{UUID: "5a5a5a5a-0000-4000-8000-00000000f1f1", CreatedAt: "2026-10-25T00:00:00Z", Attempt: "6f1c2d3e-4b5a-4c6d-8e7f-001122334455"}}
	if err := s.fwRecords().PutHold(h); err != nil {
		t.Fatal(err)
	}
	before := len(vlanDomainOps(fake, "vm1"))
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("a firmware-move-held domain is %v, want left paused", st)
	}
	if ops := vlanDomainOps(fake, "vm1")[before:]; len(ops) != 0 {
		t.Fatalf("ops %q on a firmware-move-held domain, want none", ops)
	}
	if _, named := strandedCond(t, s); named {
		t.Fatal("a firmware-move-held domain was named as a stranded start")
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("the record was dropped")
	}
}

// Review F7 I1, record hygiene: a record whose domain runs (unpaused) is
// stale — its start ended — and the 30 s judge, a start and a stop each drop
// it. One whose domain is paused, or shut off (a start in flight before its
// create), is kept.
//
// Mutation: no dropStaleStartRecords in JudgeStrandedStarts — red; none in
// startLeftPausedRefusal or stopLocked — red.
func TestStaleStartRecordIsDroppedWhenItsDomainRuns(t *testing.T) {
	for name, act := range map[string]func(*Server) error{
		"judge": func(s *Server) error { s.JudgeStrandedStarts(adminCtx()); return nil },
		"start": func(s *Server) error {
			_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"})
			return err
		},
		"stop": func(s *Server) error {
			_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := leftPaused(t, "running")
			fake.SetState("vm1", libvirtfake.StateRunning)
			_ = act(s)
			if marked, _ := s.startPausedMarked("vm1"); marked {
				t.Fatalf("%s kept the record of a domain that runs", name)
			}
		})
	}
	for name, st := range map[string]libvirtfake.State{"paused": libvirtfake.StatePaused, "shut off": libvirtfake.StateShutdown} {
		t.Run("judge keeps it while "+name, func(t *testing.T) {
			s, fake := leftPaused(t, "running")
			fake.SetState("vm1", st)
			s.JudgeStrandedStarts(adminCtx())
			if marked, _ := s.startPausedMarked("vm1"); !marked {
				t.Fatalf("the judge dropped the record of a %s domain", name)
			}
		})
	}
}

// Review F7 m1: a snapshot restore of a VM with a start left paused is
// refused up front, before any destroy, undefine or overlay reset, pointing
// at `lv stop --force` first.
//
// Mutation: no startRecordRefusal in restoreSnapshot — red.
func TestRestoreSnapshot_RefusesUpFrontOverAStartLeftPaused(t *testing.T) {
	s, fake := leftPaused(t, "stopped")
	before := len(fake.EventLog())
	_, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "vm1", SnapshotName: "snap1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "`lv stop --force vm1` first") {
		t.Fatalf("restore over a start left paused: %v, want refused pointing at lv stop --force", err)
	}
	for _, e := range fake.EventLog()[before:] {
		if e.Domain == "vm1" {
			t.Fatalf("the refused restore touched the domain: %s %s", e.Op, e.Note)
		}
	}
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("domain %v, want still paused", st)
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("the refused restore dropped the record")
	}
}

// Review r8-m1: a start record whose domain is shut off (a destroy outside
// `lv stop --force`) holds no paused guest. The restore drops it, as the start
// guard treats it, and goes on: it is not refused with a text about a guest
// "left paused".
//
// Mutation: startRecordRefusal not dropping the record of an inactive domain
// — red.
func TestRestoreSnapshot_DropsTheStartRecordOfAShutOffDomain(t *testing.T) {
	s := lockTestServer(t)
	fake := seedRestorableVM(t, s, "disk")
	if err := s.markStartPaused("rs"); err != nil {
		t.Fatal(err)
	}
	fake.SetState("rs", libvirtfake.StateShutdown)
	if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err != nil {
		t.Fatalf("restore of a shut-off domain with a stale start record: %v", err)
	}
	if marked, _ := s.startPausedMarked("rs"); marked {
		t.Fatal("the restore kept the stale start record of a shut-off domain")
	}
}

// Review of the rc10 polish, m1: a reconciler or restart-policy start holds
// the VM's start lease, not its lock, and between recording its paused start
// and the paused create its domain is shut off. A restore in that window is
// refused at the lease, and must not drop that start's record first: the
// record is judged only once the restore holds the lease.
//
// Mutation: startRecordRefusal before holdStartLease, as before — red.
func TestRestoreSnapshot_KeepsTheRecordOfAStartThatHoldsTheLease(t *testing.T) {
	s := lockTestServer(t)
	fake := seedRestorableVM(t, s, "disk")
	if heldBy, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName+"/vmcheck", "rs", time.Now()); err != nil || heldBy != s.hostName+"/vmcheck" {
		t.Fatalf("setup: lease %q %v", heldBy, err)
	}
	if err := s.markStartPaused("rs"); err != nil {
		t.Fatal(err)
	}
	fake.SetState("rs", libvirtfake.StateShutdown)
	_, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RestoreSnapshot = %v, want refused while a start holds the lease", err)
	}
	if marked, _ := s.startPausedMarked("rs"); !marked {
		t.Fatal("the refused restore dropped the record of the start that holds the lease")
	}
}

// Review F7 m4: a plain stop of a paused guest is refused before anything
// runs: the VM's PreStop hook does not fire for a stop that is refused.
//
// Mutation: the refusal after hooks.Run(PreStop) (the old order) — red.
func TestStopVM_PausedRefusalRunsNoPreStopHook(t *testing.T) {
	s, fake := vlanStartServer(t)
	marker := filepath.Join(t.TempDir(), "pre-stop-ran")
	insertTestVMWithSpec(t, adminCtx(), s.db, "hookvm", "test-host", "running", seedSpecJSON(t, &pb.VMSpec{
		Name: "hookvm", Cpu: 1, MemoryMib: 512, Hooks: &pb.HooksSpec{PreStop: "touch " + marker}}))
	giveUUID(t, fake, "hookvm")
	fake.SetState("hookvm", libvirtfake.StateRunning)
	if err := fake.SuspendDomain("hookvm"); err != nil {
		t.Fatal(err)
	}
	failShutdownPaused(fake)
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "hookvm"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("plain stop of a paused guest: %v, want refused", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the PreStop hook ran for a stop that was refused")
	}
}

// Review F7 m5: a start that fails after its paused create, whose domain
// cannot be stopped (the destroy does not land), keeps its record and names
// the guest at once, not only at the next daemon start.
//
// Mutation: no PausedKept in NICStartGuard — red.
func TestStartVM_AFailedPausedStartIsNamedAtOnce(t *testing.T) {
	s, fake := vlanStartServer(t)
	fake.FailConfigureVLANTap = func(string, string, int) error { return errors.New("no such tap") }
	fake.FailDestroyDomain = func(string) error { return errors.New("connection reset by peer") }
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("the start succeeded with its VLAN refused")
	}
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("domain %v, want left paused (its destroy did not land)", st)
	}
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("the record of a start left paused was dropped")
	}
	c, named := strandedCond(t, s)
	if !named || !strings.Contains(c.Evidence, "a start failed") {
		t.Fatalf("the failed start's paused guest is not named at once: %+v (named %v)", c, named)
	}
}

// Review F7 m5: `lv start` while the reconciler's restart-policy start is in
// its paused window (row error, record, domain prelaunch) is refused but
// raises no condition: that start is in flight, not stranded.
//
// Mutation: startLeftPausedRefusal naming the start again — red.
func TestStartVM_RefusalRaisesNoAlarmForAStartInFlight(t *testing.T) {
	s, _ := leftPaused(t, "error")
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("lv start over a start in its paused window: %v, want refused", err)
	}
	if _, named := strandedCond(t, s); named {
		t.Fatal("lv start named a start that is in flight")
	}
}
