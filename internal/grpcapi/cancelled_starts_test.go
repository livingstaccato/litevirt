package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func (st *stuckStart) cancelledStartsOnDisk(t *testing.T) []cancelledStartRecord {
	t.Helper()
	raw, err := os.ReadFile(st.s.cancelledStartsPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var list []cancelledStartRecord
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("%s: %v", st.s.cancelledStartsPath(), err)
	}
	return list
}

// restarted makes st's server as a daemon that restarted after a cancel: web's
// row says stopped by its operator, its domain is running (libvirt started it
// after the restart), the cancel is recorded on disk, and nothing in memory
// remembers it.
func (st *stuckStart) restarted(t *testing.T, rowState, rowDetail string) {
	t.Helper()
	st.restartedAt(t, rowState, rowDetail, time.Now().Add(-time.Hour))
}

const (
	testBootA = "11111111-1111-4111-8111-111111111111"
	testBootB = "22222222-2222-4222-8222-222222222222"
)

// restartedAt is restarted with the record created at created.
func (st *stuckStart) restartedAt(t *testing.T, rowState, rowDetail string, created time.Time) {
	t.Helper()
	st.restartedInBoot(t, rowState, rowDetail, created, "")
}

// restartedInBoot is restartedAt with the record made in boot.
func (st *stuckStart) restartedInBoot(t *testing.T, rowState, rowDetail string, created time.Time, boot string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.UpdateVMState(ctx, st.s.db, "web", rowState, rowDetail); err != nil {
		t.Fatal(err)
	}
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateRunning)
	raw, _ := json.Marshal([]cancelledStartRecord{{VM: "web", StartAsked: "2026-10-14T15:39:20Z", Cancelled: "2026-10-14T15:45:07Z",
		Created: created.UTC().Format(time.RFC3339Nano), BootID: boot}})
	if err := os.WriteFile(st.s.cancelledStartsPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st.s.cancelledStarts = cancelledStarts{}
}

func (st *stuckStart) sweep(t *testing.T) {
	t.Helper()
	done := st.s.sweepCancelledStarts(context.Background())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep of cancelled starts did not finish within 5s")
	}
}

// Review I-2: a start cancelled by `lv stop --force` while libvirt had not
// answered it is undone when libvirt answers — but only by the start's own
// goroutine, so a daemon that restarted before libvirt answered forgot it,
// and the domain libvirt then started ran under a row stopped by its
// operator. The cancel is now recorded on the host before the row is
// written, and the sweep (at daemon start, and on each background pass)
// destroys such a domain, recording it once, and forgets the record.
//
// Mutations: the sweep does not destroy — the domain runs on: red. The record
// not written by the cancel — none on disk after it: red.
func TestCancelledStart_ADomainStartedAfterARestartIsDestroyed(t *testing.T) {
	st := heldStart(t)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 || recs[0].VM != "web" {
		t.Fatalf("the cancel's record on disk: %+v, want web", recs)
	}

	st.asIfRestarted(t)

	// A fresh daemon on the same host: a second one, sharing the data dir
	// and the database, with no start in flight.
	st2 := newStuckStart(t)
	st2.s.db, st2.s.dataDir = st.s.db, st.s.dataDir
	st2.restarted(t, "stopped", "operator-stop")
	st2.sweep(t)
	if st2.domainActive(t) {
		t.Fatal("the domain of a start cancelled before the restart still runs")
	}
	if vm := st2.row(t); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Fatalf("web after the sweep: %s/%s, want stopped/operator-stop", vm.State, vm.StateDetail)
	}
	n := 0
	for _, e := range st2.events(t, "vm.stopped", "ok") {
		if strings.Contains(e.Detail, "after the daemon restarted") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the destroy of the cancelled start's domain was recorded %d times, want once", n)
	}
	if recs := st2.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the destroy: %+v", recs)
	}
	st2.sweep(t)
	if evs := st2.events(t, "vm.stopped", "ok"); len(evs) > n+1 {
		t.Fatalf("a second sweep recorded again: %+v", evs)
	}
}

// A cancelled start whose VM the operator started again since (its row no
// longer says stopped by its operator) is not undone: its record is dropped
// and the running domain is left alone.
//
// Mutation: the row not looked at — the VM started again is destroyed: red.
func TestCancelledStart_AVMStartedAgainIsLeftRunning(t *testing.T) {
	st := newStuckStart(t)
	st.restarted(t, "running", "")
	st.sweep(t)
	if !st.domainActive(t) {
		t.Fatal("the sweep destroyed a VM its operator started again")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record of a start the operator made again was kept: %+v", recs)
	}
}

// A record made in an earlier boot of the host whose domain is shut off is
// forgotten, with nothing done: libvirt's queue of jobs did not survive the
// boot, so no start can still be pending for it.
//
// Mutation: the boot not compared (kept on any shut-off domain): red.
func TestCancelledStart_ADomainShutOffForgetsTheRecord(t *testing.T) {
	st := newStuckStart(t)
	st.restartedInBoot(t, "stopped", "operator-stop", time.Now().Add(-time.Hour), testBootA)
	st.s.bootID = func() (string, error) { return testBootB, nil }
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record of a cancelled start whose domain is shut off was kept: %+v", recs)
	}
	if evs := st.events(t, "vm.stopped", "ok"); len(evs) != 0 {
		t.Fatalf("a shut-off domain's record recorded a stop: %+v", evs)
	}
}

// The start's own late answer handles the cancel and forgets the record.
func TestCancelledStart_TheLateAnswerForgetsTheRecord(t *testing.T) {
	st := heldStart(t)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt answered the cancelled start")
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the late answer that handled it: %+v", recs)
	}
}

// Round 2: a domain seen shut off does not end the record while the start it
// cancelled could still complete — after a restart libvirt may still be
// working on it, and a shut-off domain says nothing about that. Only a record
// older than the held-start wait plus a margin is dropped on a shut-off
// domain; a younger one is kept, and the domain, once libvirt brings it up,
// is destroyed.
//
// Mutation: the age not looked at (dropped on any shut-off domain) — the
// young record is gone and the domain that comes up runs on: red.
func TestCancelledStart_AYoungRecordOutlivesAShutOffDomain(t *testing.T) {
	st := newStuckStart(t) // held-start wait 300ms
	fake := st.s.virt.(*libvirtfake.Fake)

	st.restartedAt(t, "stopped", "operator-stop", time.Now())
	fake.SetState("web", libvirtfake.StateShutdown)
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("a record younger than the start's window was dropped on a shut-off domain: %+v", recs)
	}
	// libvirt finishes the start it was still making.
	fake.SetState("web", libvirtfake.StateRunning)
	st.sweep(t)
	if st.domainActive(t) {
		t.Fatal("the domain the cancelled start brought up late runs on")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the destroy: %+v", recs)
	}
}

// CR7-0: a held start has no upper bound on when libvirt answers it, so the
// record of its cancel is not dropped for its age. A start queued in libvirt
// behind another job reads shut off for as long as it waits, then comes up:
// the record kept past any window destroys it then.
//
// Mutation: the age-based window back (dropped once older than the held-start
// wait plus a margin): the record is gone and the domain runs on: red.
func TestCancelledStart_AQueuedStartAfterAnyWindowIsStillUndone(t *testing.T) {
	st := newStuckStart(t)
	fake := st.s.virt.(*libvirtfake.Fake)
	st.restartedInBoot(t, "stopped", "operator-stop", time.Now().Add(-24*time.Hour), testBootA)
	st.s.bootID = func() (string, error) { return testBootA, nil }
	fake.SetState("web", libvirtfake.StateShutdown)
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("a day-old record was dropped on a shut-off domain in the same boot: %+v", recs)
	}
	// libvirt finally runs the start it had queued.
	fake.SetState("web", libvirtfake.StateRunning)
	st.sweep(t)
	if st.domainActive(t) {
		t.Fatal("the domain a queued cancelled start brought up late runs on")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the destroy: %+v", recs)
	}
}

// A record that names no boot (or a boot that cannot be read) is kept on a
// shut-off domain: only positive evidence ends it.
func TestCancelledStart_ARecordWithoutABootIsKept(t *testing.T) {
	st := newStuckStart(t)
	st.restartedAt(t, "stopped", "operator-stop", time.Now().Add(-time.Hour))
	st.s.bootID = func() (string, error) { return testBootB, nil }
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("a record naming no boot was dropped: %+v", recs)
	}
	st.restartedInBoot(t, "stopped", "operator-stop", time.Now().Add(-time.Hour), testBootA)
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	st.s.bootID = func() (string, error) { return "", errors.New("no boot_id") }
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("a record was dropped when this boot's ID cannot be read: %+v", recs)
	}
}

// The record carries when it was made, so the window survives a restart.
func TestCancelledStart_TheRecordCarriesItsCreationTime(t *testing.T) {
	st := heldStart(t)
	before := time.Now().Add(-time.Second)
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	recs := st.cancelledStartsOnDisk(t)
	if len(recs) != 1 {
		t.Fatalf("records on disk: %+v", recs)
	}
	created, err := time.Parse(time.RFC3339Nano, recs[0].Created)
	if err != nil || created.Before(before) || created.After(time.Now()) {
		t.Fatalf("the record's created %q (%v), want the time of the cancel", recs[0].Created, err)
	}
}

// Re-review R-1: after a restart, a cancel's record and an operator's new
// `lv start` of the same VM. The start succeeds but its running write fails,
// so the row still says stopped by its operator, with the domain running:
// the shape of the cancelled start's late success. The sweep must not
// destroy a VM its operator started again, so a start drops the VM's record,
// durably, before it starts the domain.
//
// Mutation: the record not dropped by the start — the sweep destroys the VM
// just started: red.
func TestCancelledStart_AStartAfterTheCancelEndsTheRecordBeforeItStarts(t *testing.T) {
	st := newStuckStart(t)
	st.restartedAt(t, "stopped", "operator-stop", time.Now())
	fake := st.s.virt.(*libvirtfake.Fake)
	fake.SetState("web", libvirtfake.StateShutdown)
	close(st.release)
	st.s.stateWriteHook = func(name, state string) error {
		if state == "running" {
			return errors.New("corrosion: write failed")
		}
		return nil
	}
	if _, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("lv start: %v", err)
	}
	if vm := st.row(t); vm.State != "stopped" || !st.domainActive(t) {
		t.Fatalf("setup: row %s with the domain active=%v, want stopped over a running domain", vm.State, st.domainActive(t))
	}
	st.sweep(t)
	if !st.domainActive(t) {
		t.Fatal("the sweep destroyed the VM its operator had just started")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the cancel's record outlived a start of the VM: %+v", recs)
	}
}

// A start refuses rather than run with the record on disk when it cannot
// remove it: the sweep would destroy what it started.
func TestCancelledStart_AStartThatCannotEndTheRecordIsRefused(t *testing.T) {
	st := newStuckStart(t)
	st.restartedAt(t, "stopped", "operator-stop", time.Now())
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	close(st.release)
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	if err := os.Chmod(st.s.dataDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(st.s.dataDir, 0o700) })
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	if err == nil || !strings.Contains(err.Error(), cancelledStartsFile) {
		t.Fatalf("start with a record it cannot remove = %v, want a refusal naming %s", err, cancelledStartsFile)
	}
	if st.calls.Load() != 0 {
		t.Fatal("libvirt was asked to start the VM")
	}
}

// Re-review R-6: a cancel whose record cannot be written is refused, and
// nothing changes: the row still says starting and the start goes on.
func TestCancelledStart_ACancelWhoseRecordCannotBeWrittenIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	st := heldStart(t)
	if err := os.Chmod(st.s.dataDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(st.s.dataDir, 0o700) })
	_, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true})
	if err == nil || !strings.Contains(err.Error(), "was not cancelled") {
		t.Fatalf("stop --force whose record cannot be written = %v, want a refusal saying the start was not cancelled", err)
	}
	if vm := st.row(t); vm.State != "starting" {
		t.Fatalf("web's row after the refused cancel: %s, want starting", vm.State)
	}
	if err := os.Chmod(st.s.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt answered")
	if vm := st.row(t); vm.State != "running" {
		t.Fatalf("web after libvirt answered the start that was not cancelled: %s, want running", vm.State)
	}
}
