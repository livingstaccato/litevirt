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

// heldStart is a stuckStart whose start of web has been answered Unavailable
// past its wait: libvirt has not answered it, and it holds web.
func heldStart(t *testing.T) *stuckStart {
	t.Helper()
	st := newStuckStart(t)
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	return st
}

func (st *stuckStart) events(t *testing.T, typ, result string) []corrosion.VMEventRecord {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), st.s.db, "web", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []corrosion.VMEventRecord
	for _, e := range evs {
		if e.Type == typ && e.Result == result {
			out = append(out, e)
		}
	}
	return out
}

func (st *stuckStart) domainActive(t *testing.T) bool {
	t.Helper()
	active, err := st.s.virt.DomainIsActive("web")
	if err != nil {
		t.Fatalf("DomainIsActive: %v", err)
	}
	return active
}

// Batch 4's remaining limitation: a stop or restart of a VM whose start
// libvirt has not answered queued behind that start's lock for as long as
// libvirt did not answer — forever, on storage that never does. They now
// answer at once, Unavailable, saying a start is in progress and how to
// cancel it, and change nothing: the start goes on and settles as before.
//
// Mutation: the stop and restart wait on the lock (lockVM) — they do not
// return: red.
func TestStopVM_AStopOfAHeldStartAnswersAtOnce(t *testing.T) {
	st := heldStart(t)
	for _, op := range []string{"stop", "restart"} {
		err := within(t, 5*time.Second, "a plain "+op+" while the start is held", func() error {
			var err error
			if op == "stop" {
				_, err = st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web"})
			} else {
				_, err = st.s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "web"})
			}
			return err
		})
		if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "a start of it is in progress") ||
			!strings.Contains(err.Error(), "lv stop --force web") {
			t.Fatalf("%s while the start is held = %v, want Unavailable saying a start is in progress, naming lv stop --force web", op, err)
		}
	}
	if vm := st.row(t); vm.State != "starting" {
		t.Fatalf("web's row after the refused stop: %s, want starting", vm.State)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt answered")
	if vm := st.row(t); vm.State != "running" || !st.domainActive(t) {
		t.Fatalf("web after libvirt answered: %s, want running", vm.State)
	}
	if n := st.calls.Load(); n != 1 {
		t.Fatalf("libvirt was asked to start web %d times, want 1", n)
	}
}

// `lv stop --force` cancels a held start: it answers at once, the row says
// stopped by its operator, and no start of the VM is made meanwhile (a start
// asked for answers that it was cancelled). When libvirt answers that it
// started the domain, the domain is destroyed, and that is recorded once: one
// qemu, never two, and never a row that says running.
//
// Mutations: the late answer not told of the cancel (recorded running) — the
// VM runs and its row says running: red. The cancel not recorded on the row —
// the row still says starting: red.
func TestStopVM_ForceCancelsAHeldStartAndUndoesItsLateSuccess(t *testing.T) {
	st := heldStart(t)
	out := within(t, 5*time.Second, "lv stop --force while the start is held", func() *pb.VM {
		out, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true})
		if err != nil {
			t.Fatalf("stop --force while the start is held: %v", err)
		}
		return out
	})
	if out.GetState() != pb.VMState_VM_STOPPING || !strings.Contains(out.GetStateDetail(), "start cancelled") {
		t.Fatalf("stop --force answered %v %q, want VM_STOPPING saying the start is cancelled", out.GetState(), out.GetStateDetail())
	}
	if vm := st.row(t); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Fatalf("web's row after the cancel: %s/%s, want stopped/operator-stop", vm.State, vm.StateDetail)
	}
	if got := st.listed(t); got.GetState() != pb.VMState_VM_STOPPING {
		t.Fatalf("web listed after the cancel, libvirt not answered: %v, want VM_STOPPING", got.GetState())
	}
	// Still held: a start answers that the start was cancelled, and asks
	// libvirt nothing; a second cancel is the same cancel; a plain stop
	// finds the stop recorded.
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("start after the cancel = %v, want Unavailable saying the start was cancelled", err)
	}
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("a second stop --force: %v", err)
	}
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web"}); err != nil {
		t.Fatalf("a plain stop after the cancel: %v", err)
	}
	if n := st.calls.Load(); n != 1 {
		t.Fatalf("libvirt was asked to start web %d times, want 1", n)
	}

	close(st.release)
	st.waitLockFree(t, "after libvirt answered the cancelled start")
	if st.domainActive(t) {
		t.Fatal("the domain libvirt started for the cancelled start is running")
	}
	if vm := st.row(t); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Fatalf("web after the cancelled start was answered: %s/%s, want stopped/operator-stop", vm.State, vm.StateDetail)
	}
	if evs := st.events(t, "vm.started", "ok"); len(evs) != 0 {
		t.Fatalf("a cancelled start was recorded as started: %+v", evs)
	}
	destroyed := 0
	for _, e := range st.events(t, "vm.stopped", "ok") {
		if strings.Contains(e.Detail, "was destroyed") {
			destroyed++
		}
	}
	if destroyed != 1 {
		t.Fatalf("the cancelled start's late success was recorded %d times, want once", destroyed)
	}
	if holder, _ := st.leaseHolder(t); holder != "" {
		t.Fatalf("web's start lease after the cancelled start settled: still held by %q", holder)
	}
}

// A cancelled start libvirt answers with a failure is recorded as that, once,
// and the row stays as the cancel wrote it.
func TestStopVM_ACancelledHeldStartThatFailsIsRecordedOnce(t *testing.T) {
	st := heldStart(t)
	st.answer.Store(errors.New("qemu: cannot open disk"))
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt's late failure")
	if vm := st.row(t); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Fatalf("web: %s/%s, want stopped/operator-stop", vm.State, vm.StateDetail)
	}
	if evs := st.events(t, "vm.started", "error"); len(evs) != 1 || !strings.Contains(evs[0].Detail, "cannot open disk") {
		t.Fatalf("the cancelled start's failure recorded as %+v, want one failed-start event naming the cause", evs)
	}
}

// A VM whose row said error before the start (a failed failover start, its
// set-aside disk copies held there) keeps that row when its held start is
// cancelled, as a stop of an errored VM whose domain does not run leaves it.
func TestStopVM_ACancelledHeldStartOfAnErroredVMKeepsItsRow(t *testing.T) {
	st := newStuckStart(t)
	if err := corrosion.UpdateVMState(context.Background(), st.s.db, "web", "error", "failover start failed: disk missing"); err != nil {
		t.Fatal(err)
	}
	st.answer.Store(errors.New("qemu: cannot open disk"))
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	if vm := st.row(t); vm.State != "error" || vm.StateDetail != "failover start failed: disk missing" {
		t.Fatalf("web after the cancel: %s/%q, want error with its detail", vm.State, vm.StateDetail)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt's late failure")
	if vm := st.row(t); vm.State != "error" {
		t.Fatalf("web after the cancelled start failed: %s, want error", vm.State)
	}
}

// When the domain a cancelled start brought up cannot be destroyed, the VM
// runs, and its row says so (never stopped over a running domain); the
// failed cancel is recorded.
//
// Mutation: the row left as the cancel wrote it — stopped over a running
// domain: red.
func TestStopVM_ACancelledHeldStartWhoseDomainCannotBeDestroyedIsRecordedRunning(t *testing.T) {
	st := heldStart(t)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	st.s.virt.(*libvirtfake.Fake).FailDestroyDomain = func(string) error { return errors.New("destroy refused") }
	close(st.release)
	st.waitLockFree(t, "after libvirt answered the cancelled start")
	if !st.domainActive(t) {
		t.Fatal("the domain is not running, but its destroy was refused")
	}
	if vm := st.row(t); vm.State != "running" {
		t.Fatalf("web, whose domain runs: %s, want running", vm.State)
	}
	if evs := st.events(t, "vm.stopped", "error"); len(evs) != 1 || !strings.Contains(evs[0].Detail, "destroy refused") {
		t.Fatalf("the failed cancel recorded as %+v, want one event naming the cause", evs)
	}
}
