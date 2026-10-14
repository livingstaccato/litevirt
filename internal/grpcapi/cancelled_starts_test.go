package grpcapi

import (
	"context"
	"encoding/json"
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
	ctx := context.Background()
	if err := corrosion.UpdateVMState(ctx, st.s.db, "web", rowState, rowDetail); err != nil {
		t.Fatal(err)
	}
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateRunning)
	raw, _ := json.Marshal([]cancelledStartRecord{{VM: "web", StartAsked: "2026-10-14T15:39:20Z", Cancelled: "2026-10-14T15:45:07Z"}})
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

// A record whose domain is shut off is forgotten, with nothing done.
func TestCancelledStart_ADomainShutOffForgetsTheRecord(t *testing.T) {
	st := newStuckStart(t)
	st.restarted(t, "stopped", "operator-stop")
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
