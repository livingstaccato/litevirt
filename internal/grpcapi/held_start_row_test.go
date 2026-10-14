package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func (st *stuckStart) listed(t *testing.T) *pb.VM {
	t.Helper()
	resp, err := st.s.ListVMs(adminCtx(), &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	for _, vm := range resp.GetVms() {
		if vm.GetName() == "web" {
			return vm
		}
	}
	t.Fatal("web is not listed")
	return nil
}

func (st *stuckStart) leaseHolder(t *testing.T) (string, string) {
	t.Helper()
	rows, err := st.s.db.Query(context.Background(), `SELECT holder, expires_at FROM vm_locks WHERE vm_name = 'web'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return "", ""
	}
	return rows[0].String("holder"), rows[0].String("expires_at")
}

// Lab 2 (batch 4, 5f12ab50): while a start was held past its five-minute
// answer, the VM's row said VM_STOPPED on every host, so an operator saw a
// stopped VM that was being started. The row now says starting, with when the
// start was asked for, for as long as libvirt has not answered; the daemon
// running the start lists it starting before that too. It never says running
// before libvirt has answered, and libvirt's answer settles it: running.
//
// A starting row is one the reconciler re-drives, so the start holds the VM's
// start lease meanwhile, and a reconcile pass leaves the VM to it rather than
// asking libvirt for a second start.
//
// Mutations: the row not written starting: red. The lease not taken — the
// reconcile pass starts the VM a second time (it waits on libvirt's start, and
// does not return): red. The in-flight start not shown by ListVMs before the
// hand-off — listed stopped: red.
func TestStartVM_AHeldStartSaysStartingUntilLibvirtAnswers(t *testing.T) {
	st := newStuckStart(t)
	st.s.startDomainWait = 600 * time.Millisecond
	errc := make(chan error, 1)
	go func() {
		_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
		errc <- err
	}()
	// Before the hand-off the start is answered by nobody yet: this daemon
	// lists the VM starting, and libvirt is not asked for its state.
	deadline := time.Now().Add(5 * time.Second)
	for st.calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("libvirt was never asked to start web")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if vm := st.listed(t); vm.GetState() != pb.VMState_VM_STARTING {
		t.Fatalf("web listed while its start waits on libvirt: %v, want VM_STARTING", vm.GetState())
	}
	wantStartInFlight(t, "start", <-errc)

	vm := st.row(t)
	if vm.State != "starting" || !strings.Contains(vm.StateDetail, "libvirt has not answered the start asked for at") {
		t.Fatalf("web's row while the start is held: %s/%q, want starting saying libvirt has not answered", vm.State, vm.StateDetail)
	}
	if got := st.listed(t); got.GetState() != pb.VMState_VM_STARTING {
		t.Fatalf("web listed while the start is held: %v, want VM_STARTING", got.GetState())
	}
	if holder, _ := st.leaseHolder(t); holder != health.OperatorStartLockHolder(st.s.hostName) {
		t.Fatalf("web's start lease while the start is held: %q, want %q", holder, health.OperatorStartLockHolder(st.s.hostName))
	}

	// The reconciler re-drives a starting row; it must leave this one to
	// the start that holds it.
	r := health.NewReconciler(st.s.hostName, st.s.dataDir, st.s.db, st.s.virt.(*libvirtfake.Fake))
	within(t, 5*time.Second, "a reconcile pass while the start is held", func() bool {
		r.ReconcileOnce(context.Background())
		return true
	})
	if n := st.calls.Load(); n != 1 {
		t.Fatalf("libvirt was asked to start web %d times, want 1", n)
	}
	if vm := st.row(t); vm.State != "starting" {
		t.Fatalf("web's row after a reconcile pass while the start is held: %s, want starting", vm.State)
	}

	close(st.release)
	st.waitLockFree(t, "after libvirt answered")
	if vm := st.row(t); vm.State != "running" {
		t.Fatalf("web after libvirt's late answer: %s, want running", vm.State)
	}
	if holder, _ := st.leaseHolder(t); holder != "" {
		t.Fatalf("web's start lease after the start settled: still held by %q", holder)
	}
}

// A held start renews the start lease it holds, so a start that libvirt
// leaves unanswered longer than the lease's TTL still excludes every other
// start path.
//
// Mutation: no renewal — the lease's expiry does not move: red.
func TestStartVM_AHeldStartRenewsItsStartLease(t *testing.T) {
	old := startLeaseRenewEvery
	startLeaseRenewEvery = 100 * time.Millisecond
	t.Cleanup(func() { startLeaseRenewEvery = old })
	st := newStuckStart(t)
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	_, first := st.leaseHolder(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		holder, exp := st.leaseHolder(t)
		if holder != health.OperatorStartLockHolder(st.s.hostName) {
			t.Fatalf("web's start lease while the start is held: %q", holder)
		}
		if exp > first {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("web's start lease was never renewed while the start is held (expires %s)", exp)
		}
		time.Sleep(50 * time.Millisecond)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt answered")
}

// A VM in error (a failover start that failed holds its set-aside disk
// copies there) whose start is held and then fails is put back to error, with
// its detail, not left starting or written stopped.
//
// Mutation: the row not put back on a late failure — it stays starting: red.
func TestStartVM_AHeldStartThatFailsPutsTheRowBack(t *testing.T) {
	st := newStuckStart(t)
	ctx := context.Background()
	if err := corrosion.UpdateVMState(ctx, st.s.db, "web", "error", "failover start failed: disk missing"); err != nil {
		t.Fatal(err)
	}
	st.answer.Store(errors.New("qemu: cannot open disk"))
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	if vm := st.row(t); vm.State != "starting" {
		t.Fatalf("web's row while the start is held: %s, want starting", vm.State)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt's late failure")
	if vm := st.row(t); vm.State != "error" || vm.StateDetail != "failover start failed: disk missing" {
		t.Fatalf("web after a held start failed: %s/%q, want error with its detail", vm.State, vm.StateDetail)
	}
}

// Review I-1: a held start libvirt answers late with success, whose read of
// the VM afterwards fails, used to be taken for a failed start: the row was
// put back to stopped/operator-stop over the running domain, and a failed
// start recorded. Only libvirt's answer (or the domain's state) decides
// whether the start failed.
//
// Mutation: restore on finish's error — the row is stopped over a running
// domain: red.
func TestStartVM_AHeldStartWhoseReadBackFailsStaysRunning(t *testing.T) {
	st := newStuckStart(t)
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	st.s.vmReadBackHook = func(string) error { return errors.New("corrosion: read failed") }
	close(st.release)
	st.waitLockFree(t, "after libvirt answered")
	if active, err := st.s.virt.DomainIsActive("web"); err != nil || !active {
		t.Fatalf("web's domain after libvirt started it: active=%v (%v)", active, err)
	}
	if vm := st.row(t); vm.State != "running" {
		t.Fatalf("web's row after a late success whose read-back failed: %s/%q, want running", vm.State, vm.StateDetail)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), st.s.db, "web", 50, "")
	for _, e := range evs {
		if e.Type == "vm.started" && e.Result == "error" {
			t.Fatalf("a late success was recorded as a failed start: %+v", e)
		}
	}
}

// Review m-7: StartVM's own answer for a start it has just completed says
// running, even when libvirt then does not answer the read of its state in
// time.
//
// Mutation: StartVM answers through vmToProto — VM_UNKNOWN: red.
func TestStartVM_ItsAnswerSaysRunningWhenTheStateReadDoesNotAnswer(t *testing.T) {
	st := newStuckStart(t)
	close(st.release)
	st.s.liveStateWait = 100 * time.Millisecond
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	st.s.virt.(*libvirtfake.Fake).FailDomainState = func(name string) error {
		// Only the read after libvirt has started it: the start's own
		// checks before StartDomain read the state too.
		if name == "web" && st.calls.Load() > 0 {
			<-hang
		}
		return nil
	}
	vm, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if vm.GetState() != pb.VMState_VM_RUNNING {
		t.Fatalf("StartVM answered %v %q for a start libvirt completed, want VM_RUNNING", vm.GetState(), vm.GetStateDetail())
	}
}
