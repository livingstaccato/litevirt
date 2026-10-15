package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// sweepWithin runs one sweep and waits at most limit for every judgement it
// started.
func (st *stuckStart) sweepWithin(t *testing.T, limit time.Duration, what string) {
	t.Helper()
	done := st.s.sweepCancelledStarts(context.Background())
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s: the sweep of cancelled starts did not finish within %v", what, limit)
	}
}

// lockFree reports whether web's VM lock can be taken now (and lets it go).
func (st *stuckStart) lockFree() bool {
	unlock, ok := st.s.tryLockVM("web")
	if ok {
		unlock()
	}
	return ok
}

// CR7-1: the sweep judged a cancelled start holding the VM lock and asked
// libvirt about the domain with no bound, for the very domain whose start
// libvirt may still not be answering: `lv stop`, `lv rm` and the rest then
// waited on the lock for as long as libvirt did, and the busy flag kept every
// later sweep off the VM. libvirt is now asked with the live-state bound and
// never with the VM lock held across a call that may hang; an unanswered read
// keeps the record, and the next sweep looks again.
//
// Mutations: the unbounded DomainIsActive back — the sweep does not finish:
// red. The lock taken before the read — the lock is held while libvirt does
// not answer: red.
func TestCancelledStart_AHungLibvirtDoesNotPinTheVMLock(t *testing.T) {
	st := newStuckStart(t)
	st.s.liveStateWait = 150 * time.Millisecond
	st.restarted(t, "stopped", "operator-stop")
	fake := st.s.virt.(*libvirtfake.Fake)
	hang := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-hang:
		default:
			close(hang)
		}
	})
	fake.FailDomainState = func(name string) error {
		<-hang
		return nil
	}
	judged := make(chan struct{})
	go func() {
		defer close(judged)
		<-st.s.sweepCancelledStarts(context.Background())
	}()
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !st.lockFree() {
			t.Fatal("web's lock is held while libvirt does not answer the sweep")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-judged:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep did not finish while libvirt does not answer")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("an unanswered read changed the record: %+v", recs)
	}
	// A later sweep is not kept off the VM; it does not wait again either.
	st.sweepWithin(t, 2*time.Second, "a second sweep while libvirt does not answer")

	close(hang)
	deadline = time.Now().Add(5 * time.Second)
	for st.domainActive(t) {
		if time.Now().After(deadline) {
			t.Fatal("the domain of the cancelled start still runs after libvirt answered")
		}
		st.sweepWithin(t, 2*time.Second, "a sweep after libvirt answered")
		time.Sleep(20 * time.Millisecond)
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the destroy: %+v", recs)
	}
}

// A destroy libvirt does not answer is not waited out under the VM lock:
// the sweep returns, the lock is free, and the record is kept.
//
// Mutations: DestroyDomain unbounded under the lock — the sweep does not
// finish: red. The outstanding destroy not held against a start: red.
func TestCancelledStart_AHungDestroyDoesNotPinTheVMLock(t *testing.T) {
	st := newStuckStart(t)
	st.s.liveStateWait = 150 * time.Millisecond
	st.restarted(t, "stopped", "operator-stop")
	fake := st.s.virt.(*libvirtfake.Fake)
	hang := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-hang:
		default:
			close(hang)
		}
	})
	fake.FailDestroyDomain = func(string) error {
		<-hang
		return nil
	}
	st.sweepWithin(t, 3*time.Second, "a sweep whose destroy libvirt does not answer")
	if !st.lockFree() {
		t.Fatal("web's lock is held after the sweep returned")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("a destroy libvirt has not answered ended the record: %+v", recs)
	}
	st.sweepWithin(t, 2*time.Second, "a second sweep while the destroy is outstanding")
	// A start of the VM is refused, at once, while that destroy may still
	// land on the domain it would start.
	if err := st.s.endCancelledStartForStart("web"); status.Code(err) != codes.Unavailable {
		t.Fatalf("a start while the sweep's destroy is outstanding = %v, want Unavailable", err)
	}
	close(hang)
	deadline := time.Now().Add(5 * time.Second)
	for len(st.cancelledStartsOnDisk(t)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the record was not ended once the destroy answered")
		}
		st.sweepWithin(t, 2*time.Second, "a sweep after the destroy answered")
		time.Sleep(20 * time.Millisecond)
	}
	if st.domainActive(t) {
		t.Fatal("the cancelled start's domain runs")
	}
}

// asIfRestarted ends st's daemon as a restart would, before libvirt answered
// its cancelled held start: the record on disk is kept as the cancel wrote
// it, and the start's late answer (a failure, which changes nothing else) is
// waited out here, so no goroutine of st's outlives the test and races its
// cleanup. Unlike a real restart, the shared database then also holds that
// late answer's one vm.started/error event; no test counts it.
func (st *stuckStart) asIfRestarted(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(st.s.cancelledStartsPath())
	if err != nil {
		t.Fatal(err)
	}
	st.answer.Store(errors.New("daemon gone"))
	close(st.release)
	st.waitLockFree(t, "after the first daemon's held start settled")
	if err := os.WriteFile(st.s.cancelledStartsPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// erroredHeldStart is a held start of web whose row said error before it
// (a failover start that failed, its set-aside disk copies held there).
func erroredHeldStart(t *testing.T) *stuckStart {
	t.Helper()
	st := newStuckStart(t)
	if err := corrosion.UpdateVMState(context.Background(), st.s.db, "web", "error", "failover start failed: disk missing"); err != nil {
		t.Fatal(err)
	}
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	return st
}

// CR7-3: the cancel of a held start of a VM in error was kept only in
// memory, so a daemon restart before libvirt answered let the domain libvirt
// then started run, although `lv stop --force` had answered success. It is
// now recorded on the host before the row is written, as for a stopped row,
// and the sweep destroys a domain libvirt started late, leaving the row error
// (which holds its set-aside disk copies).
//
// Mutations: no record for an error row — none on disk: red. The sweep's
// destroy writing stopped/operator-stop — the row is not error: red. The
// error row not recognised — the record dropped, the domain runs: red.
func TestCancelledStart_AnErroredVMsCancelSurvivesARestart(t *testing.T) {
	st := erroredHeldStart(t)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 || recs[0].VM != "web" {
		t.Fatalf("the cancel's record on disk: %+v, want web", recs)
	}
	st.asIfRestarted(t)

	st2 := newStuckStart(t)
	st2.s.db, st2.s.dataDir = st.s.db, st.s.dataDir
	if vm := st2.row(t); vm.State != "error" {
		t.Fatalf("web after the cancel: %s, want error", vm.State)
	}
	st2.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateRunning) // libvirt started it after the restart
	st2.sweep(t)
	if st2.domainActive(t) {
		t.Fatal("the domain of an errored VM's cancelled start runs after the restart")
	}
	if vm := st2.row(t); vm.State != "error" || vm.StateDetail != "failover start failed: disk missing" {
		t.Fatalf("web after the sweep: %s/%q, want error with its detail", vm.State, vm.StateDetail)
	}
	if recs := st2.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the destroy: %+v", recs)
	}
	if evs := st2.events(t, "vm.stopped", "ok"); len(evs) == 0 || !strings.Contains(evs[0].Detail, "left error") {
		t.Fatalf("the destroy recorded as %+v, want an event saying the row is left error", evs)
	}
}

// The start's own late success of an errored VM's cancelled start destroys
// the domain and leaves the row error, as the cancel's event says.
//
// Mutation: the late answer stopped through a plain forced stop — the row is
// written stopped/operator-stop, ending the hold: red.
func TestCancelledStart_AnErroredVMsLateSuccessKeepsItsRow(t *testing.T) {
	st := erroredHeldStart(t)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt answered the cancelled start")
	if st.domainActive(t) {
		t.Fatal("the domain of the cancelled start runs")
	}
	if vm := st.row(t); vm.State != "error" || vm.StateDetail != "failover start failed: disk missing" {
		t.Fatalf("web after the late success: %s/%q, want error with its detail", vm.State, vm.StateDetail)
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the late answer: %+v", recs)
	}
}

// HasCancelledStart, which keeps the reconciler from recording a running
// domain under an error row as running (the sweep destroys it instead),
// names exactly the VMs with a record here.
func TestCancelledStart_HasCancelledStartNamesTheRecord(t *testing.T) {
	st := newStuckStart(t)
	if st.s.HasCancelledStart("web", "error", "failover start failed") {
		t.Fatal("web has no cancelled start yet")
	}
	st.restarted(t, "error", "failover start failed")
	if !st.s.HasCancelledStart("web", "error", "failover start failed") {
		t.Fatal("web's cancelled start on disk is not reported")
	}
	if st.s.HasCancelledStart("db", "error", "failover start failed") {
		t.Fatal("db has none")
	}
}

// CR7-10: a cancelled-starts file that could not be read latched for the
// life of the process: removing it, as the log says, changed nothing until a
// restart. It is now read again on the next use.
//
// Mutation: the load error latched — the second cancel is refused: red.
func TestCancelledStart_AFixedFileIsReadAgain(t *testing.T) {
	st := heldStart(t)
	if err := os.WriteFile(st.s.cancelledStartsPath(), []byte("[{trunc"), 0o600); err != nil {
		t.Fatal(err)
	}
	st.s.cancelledStarts = cancelledStarts{}
	_, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true})
	if err == nil || !strings.Contains(err.Error(), "was not cancelled") {
		t.Fatalf("stop --force with an unreadable record = %v, want a refusal", err)
	}
	if !st.s.HasCancelledStart("web", "error", "failover start failed") {
		t.Fatal("an unreadable record is not taken as possibly naming web")
	}
	if err := os.Remove(st.s.cancelledStartsPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force once the file was removed: %v", err)
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("records after the fixed cancel: %+v", recs)
	}
}

// Round 1, I-1: the VM checker heals a stopped or error row whose domain runs
// to running every 10 s. Ticking before the 30 s sweep, it recorded the
// domain libvirt started late for an errored VM's cancelled start as
// running, and the sweep then found the row changed and ended the record,
// destroying nothing. With the cancelled-start probe the checker leaves the
// VM alone, and the sweep destroys the domain, the row kept error.
//
// Mutation: the checker not consulting the probe — the row is healed to
// running and the domain runs on: red.
func TestCancelledStart_AnErroredVMsLateDomainIsNotHealedBeforeTheSweep(t *testing.T) {
	st := erroredHeldStart(t)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	st.asIfRestarted(t)
	st2 := newStuckStart(t)
	st2.s.db, st2.s.dataDir = st.s.db, st.s.dataDir
	fake := st2.s.virt.(*libvirtfake.Fake)
	fake.SetState("web", libvirtfake.StateRunning) // libvirt started it after the restart

	checker := health.NewVMChecker(st2.s.hostName, t.TempDir(), st2.s.db, nil)
	checker.SetBackend(fake)
	checker.SetCancelledStartProbe(st2.s.HasCancelledStart)
	checker.SweepOnce(context.Background())
	if vm := st2.row(t); vm.State != "error" {
		t.Fatalf("web after the VM checker's pass: %s/%q, want error (the cancel's)", vm.State, vm.StateDetail)
	}

	st2.sweep(t)
	if st2.domainActive(t) {
		t.Fatal("the domain of an errored VM's cancelled start runs")
	}
	if vm := st2.row(t); vm.State != "error" || vm.StateDetail != "failover start failed: disk missing" {
		t.Fatalf("web after the sweep: %s/%q, want error with its detail", vm.State, vm.StateDetail)
	}
}

// Round 1: a domain that runs under a record made in an earlier boot is not
// the cancelled start's (it cannot have survived the boot): an onboot
// autostart whose running write failed, say. It is not destroyed, and the
// record ends.
//
// Mutation: the boot not looked at on a running domain — it is destroyed: red.
func TestCancelledStart_ADomainRunningAfterABootIsLeftAlone(t *testing.T) {
	st := newStuckStart(t)
	st.restartedInBoot(t, "stopped", "operator-stop", time.Now().Add(-time.Hour), testBootA)
	st.s.bootID = func() (string, error) { return testBootB, nil }
	st.sweep(t)
	if !st.domainActive(t) {
		t.Fatal("the sweep destroyed a domain started after the host booted")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("a record from an earlier boot outlived the sweep: %+v", recs)
	}
}

// Round 1, m-1: the record is checked again under the VM lock. A start of
// the VM that removed it while the sweep was asking libvirt about the
// domain made that domain its own, and it is not destroyed, even when its
// running write failed and the row still says stopped by its operator.
//
// Mutation: no check under the lock — the operator's start is destroyed: red.
func TestCancelledStart_ARecordEndedWhileLibvirtWasAskedDestroysNothing(t *testing.T) {
	st := newStuckStart(t)
	st.restarted(t, "stopped", "operator-stop")
	fake := st.s.virt.(*libvirtfake.Fake)
	var once sync.Once
	fake.FailDomainState = func(string) error {
		once.Do(func() {
			if err := st.s.endCancelledStartForStart("web"); err != nil {
				t.Errorf("a start's removal of the record: %v", err)
			}
		})
		return nil
	}
	st.sweep(t)
	if !st.domainActive(t) {
		t.Fatal("the sweep destroyed the domain of a start that removed the record")
	}
}

// Round 1, m-3: a destroy libvirt answers after the bound gets the same
// bookkeeping as one answered in time: the stop hooks run and the event is
// recorded, under the VM lock, and the record ends.
//
// Mutation: the late completion only records the event — no PostStop hook:
// red.
func TestCancelledStart_ALateDestroyRunsTheStopBookkeeping(t *testing.T) {
	st := newStuckStart(t)
	st.s.liveStateWait = 100 * time.Millisecond
	marker := filepath.Join(t.TempDir(), "post-stop")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, Hooks: &pb.HooksSpec{PostStop: "touch " + marker}})
	if err := st.s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'web'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	st.restarted(t, "stopped", "operator-stop")
	hang := make(chan struct{})
	st.s.virt.(*libvirtfake.Fake).FailDestroyDomain = func(string) error {
		<-hang
		return nil
	}
	st.sweepWithin(t, 3*time.Second, "a sweep whose destroy libvirt does not answer")
	close(hang)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, herr := os.Stat(marker)
		if herr == nil && len(st.cancelledStartsOnDisk(t)) == 0 && !st.s.cancelledStartDestroying("web") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the late destroy: post-stop hook ran=%v, records %+v", herr == nil, st.cancelledStartsOnDisk(t))
		}
		time.Sleep(20 * time.Millisecond)
	}
	n := 0
	for _, e := range st.events(t, "vm.stopped", "ok") {
		if strings.Contains(e.Detail, "after the daemon restarted") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the late destroy was recorded %d times, want once", n)
	}
}
