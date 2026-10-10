package health

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// heldFixture is vm1 held for node-a (restart-same, host-local disk on
// node-a), its row running there, its domain defined and shut off with reason
// unknown — what a power-off fence leaves.
func heldFixture(t *testing.T) (*corrosion.Client, *libvirtfake.Fake, *Reconciler) {
	t.Helper()
	db, fake, r, path := supersededFixture(t, "running")
	ctx := context.Background()
	disks := []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-a", Path: path, StorageType: "local"}}
	if _, err := RecordHeldForHost(ctx, db, "coord", "vm1", "node-a", disks, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain><name>vm1</name></domain>`); err != nil {
		t.Fatal(err)
	}
	return db, fake, r
}

func started(fake *libvirtfake.Fake, name string) bool {
	for _, e := range fake.EventLog() {
		if e.Domain == name && e.Op == "start" {
			return true
		}
	}
	return false
}

// N1: an operator stop that lands after the walk read the row wins: the held
// start re-reads the row under the VM lock and does not start a VM that is
// now stopped by intent.
//
// Mutation: drop the state/intent re-check in startPendingVM — the stopped
// VM is started and the test is red.
func TestStartHeldVM_AnOperatorStopAfterTheWalkWins(t *testing.T) {
	db, fake, r := heldFixture(t)
	ctx := context.Background()
	walked, _ := corrosion.GetVM(ctx, db, "vm1") // the walk's snapshot: running
	if err := db.Execute(ctx, `UPDATE vms SET state = 'stopped', state_detail = 'operator-stop', updated_at = ? WHERE name = 'vm1'`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	st, _ := fake.DomainStateReason("vm1")
	r.startHeldVM(ctx, *walked, st)
	if started(fake, "vm1") {
		t.Fatal("a VM the operator stopped after the walk was started")
	}
}

// N2: a held VM with saved state (a managed-save image) is never cold-booted:
// it stays held, with an event saying how to resume it, and is not synced.
//
// Mutation: drop the managed-save check in startHeldVM — the VM is started
// fresh and the test is red.
func TestStartHeldVM_NeverColdBootsSavedState(t *testing.T) {
	db, fake, r := heldFixture(t)
	ctx := context.Background()
	fake.SetManagedSaveImage("vm1", true)
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	st, _ := fake.DomainStateReason("vm1")
	if !r.startHeldVM(ctx, *vm, st) {
		t.Fatal("a held VM with saved state fell through to the stop sync")
	}
	if started(fake, "vm1") {
		t.Fatal("a held VM with saved state was started")
	}
	if h, _ := HeldForHostOf(ctx, db, "vm1"); h == nil {
		t.Fatal("the hold was cleared without the VM running")
	}
	evs, _ := corrosion.ListVMEvents(ctx, db, "vm1", 10, "")
	found := false
	for _, e := range evs {
		if e.Type == "vm.failover.held_saved_state" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no event saying the held VM has saved state: %+v", evs)
	}
}

// N3: the held start fires once per hold. Once the start took, the hold
// clears; a crash afterwards is the VM's restart policy's to handle, not
// another held start.
//
// Mutation: do not clear the hold after a start that took — the crashed VM is
// started again by the hold and the test is red.
func TestStartHeldVM_FiresOncePerHold(t *testing.T) {
	db, fake, r := heldFixture(t)
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	st, _ := fake.DomainStateReason("vm1")
	if !r.startHeldVM(ctx, *vm, st) || !started(fake, "vm1") {
		t.Fatal("the held VM was not started")
	}
	if h, _ := HeldForHostOf(ctx, db, "vm1"); h != nil {
		t.Fatalf("the hold is still open after the start took: %+v", h)
	}
	// It crashes.
	fake.SetState("vm1", libvirtfake.StateShutdown)
	fake.SetStateReason("vm1", "crashed")
	st, _ = fake.DomainStateReason("vm1")
	vm, _ = corrosion.GetVM(ctx, db, "vm1")
	if r.startHeldVM(ctx, *vm, st) {
		t.Fatal("a crash after the held start was handled as the hold again")
	}
}

// N5: a disk missing at its path keeps its record entry whatever the
// directory looks like — an empty mount point of a volume not mounted reads
// the same as a deleted file, so nothing is dropped on a missing file alone.
//
// Mutation: drop the entry when the directory exists — the entry is dropped
// with the mount point empty and the test is red.
func TestTendStrandedDisks_KeepsTheEntryUnderAnEmptyMountPoint(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	hidden := path + ".elsewhere"
	if err := os.Rename(path, hidden); err != nil { // the directory is there, empty of the disk
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if row, ev, ok := strandedRow(t, db, "web", "node-a"); !ok || row.Lifecycle == corrosion.ConditionResolved || len(ev.Disks) != 1 {
		t.Fatalf("the entry was dropped on a missing file: %+v %+v", row, ev)
	}
	if err := os.Rename(hidden, path); err != nil { // the volume is mounted
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if _, ev, _ := strandedRow(t, db, "web", "node-a"); len(ev.Disks) != 1 || ev.Disks[0].Copy == "" {
		t.Fatalf("once the disk is back it is not set aside: %+v", ev)
	}
}

// N6: a set-aside copy missing from its path keeps its record entry (an
// empty mount point reads like a deletion). The entry goes only when the
// operator's --remove or --restore reports the copy gone.
//
// Mutation: drop a copy's entry in tendStrandedDisk when its file is missing
// — the entry is dropped with the volume unmounted and the test is red.
func TestTendStrandedDisks_KeepsACopyEntryUntilTheOperatorRemovesIt(t *testing.T) {
	db, _, r, dataDir, _ := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	r.tendStrandedDisks(ctx)
	_, ev, _ := strandedRow(t, db, "web", "node-a")
	if len(ev.Disks) != 1 || ev.Disks[0].Copy == "" {
		t.Fatalf("setup: %+v", ev)
	}
	copyPath := ev.Disks[0].Copy
	if err := os.Rename(copyPath, copyPath+".unmounted"); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if row, ev, ok := strandedRow(t, db, "web", "node-a"); !ok || row.Lifecycle == corrosion.ConditionResolved || len(ev.Disks) != 1 {
		t.Fatalf("the copy's entry was dropped on a missing file: %+v %+v", row, ev)
	}
	if err := os.Rename(copyPath+".unmounted", copyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveSupersededDisks(ctx, db, dataDir, []string{copyPath}); err != nil {
		t.Fatal(err)
	}
	if row, _, ok := strandedRow(t, db, "web", "node-a"); !ok || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v, want resolved once --remove took the copy", row)
	}
}
