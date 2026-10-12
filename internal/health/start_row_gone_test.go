package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Lab 2 run c713, N-2. The start lease keeps a delete on THIS host out of a
// start (grpcapi deleteLockHolder), but a row can also go by replication —
// a delete an older binary ran without the lease, a removed host's rows
// deleted elsewhere, an LWW tombstone. A start whose row went while it was
// being prepared must not boot the domain: that is the running, record-less
// "ghost" the lab found, which no report could name because its stamp is
// written only from a live row.

// startRowGoneFixture is a VM recorded running on node-a with no domain —
// the self-heal restart's input — with one disk when withDisk.
func startRowGoneFixture(t *testing.T, withDisk bool) (*corrosion.Client, *libvirtfake.Fake, *Reconciler, corrosion.VMRecord) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	var disks []corrosion.DiskRecord
	if withDisk {
		p := filepath.Join(t.TempDir(), "vm1-root.qcow2")
		if err := os.WriteFile(p, []byte("disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		disks = []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-a", Path: p}}
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", vm, err)
	}
	return db, fake, r, *vm
}

func startedVM1(fake *libvirtfake.Fake) bool {
	for _, e := range fake.EventLog() {
		if e.Domain == "vm1" && e.Op == "start" {
			return true
		}
	}
	return false
}

// The row goes after the start lease's re-read, before the domain boots.
func TestStartPendingVM_RowGoneBeforeStartIsNotStarted(t *testing.T) {
	for _, withDisk := range []bool{false, true} {
		t.Run(map[bool]string{false: "diskless", true: "with-disk"}[withDisk], func(t *testing.T) {
			db, fake, r, vm := startRowGoneFixture(t, withDisk)
			ctx := context.Background()
			r.startDomainHook = func(ctx context.Context) {
				if err := corrosion.DeleteVM(ctx, db, "vm1"); err != nil {
					t.Errorf("tombstone vm1: %v", err)
				}
			}
			r.startPendingVM(ctx, vm)

			if startedVM1(fake) {
				t.Fatal("the reconciler booted vm1 although its row was gone before the start")
			}
			if fake.DomainExists("vm1") {
				t.Fatal("the reconciler left its own definition of vm1 behind with no row naming it")
			}
		})
	}
}

// The row goes while the domain is booting. The start cannot be taken back,
// so the guest it booted a moment ago is stopped. A disk-less domain holds
// nothing and is removed; one with disks is kept defined, shut off, and
// stamped as litevirt's so the orphan-runtime report names it — never
// undefined, so nothing that may still be wanted is lost.
func TestStartPendingVM_RowGoneDuringStartIsStoppedAndReported(t *testing.T) {
	for _, withDisk := range []bool{false, true} {
		t.Run(map[bool]string{false: "diskless", true: "with-disk"}[withDisk], func(t *testing.T) {
			db, fake, r, vm := startRowGoneFixture(t, withDisk)
			ctx := context.Background()
			fake.OnRunning = func(name string) {
				if name != "vm1" {
					return
				}
				if err := corrosion.DeleteVM(ctx, db, "vm1"); err != nil {
					t.Errorf("tombstone vm1: %v", err)
				}
			}
			r.startPendingVM(ctx, vm)
			fake.OnRunning = nil

			if !startedVM1(fake) {
				t.Fatal("the scenario never booted vm1; it did not reach the window")
			}
			if st, _ := fake.DomainState("vm1"); st == "running" {
				t.Fatal("vm1 is left running with no row: the ghost of lab 2 run c713 N-2")
			}
			if !withDisk {
				if fake.DomainExists("vm1") {
					t.Error("a disk-less domain the reconciler started for a deleted row was left defined")
				}
				return
			}
			if !fake.DomainExists("vm1") {
				t.Fatal("a domain with disks was undefined; it must be kept for the operator")
			}
			if stamped, err := fake.GetDomainManaged("vm1"); err != nil || !stamped {
				t.Fatalf("vm1 kept without the managed stamp (stamped=%v err=%v): the orphan report cannot name it", stamped, err)
			}

			// And the report names it, on its second sighting.
			r.reportOrphanRuntimes(ctx)
			r.reportOrphanRuntimes(ctx)
			conds, err := corrosion.ListHealthConditions(ctx, db, false)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, c := range conds {
				if c.Evaluator == OrphanRuntimeEvaluator && c.SubjectID == "vm1@node-a" {
					found = true
				}
			}
			if !found {
				t.Error("no orphan-runtime condition names vm1@node-a")
			}
		})
	}
}
