package health

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// missingDiskVM records VM name on host-a in state, with one disk whose file
// is missing and which has a backing image the reconciler could rebuild it
// from. It returns the disk path and a pointer to the number of image pulls.
func missingDiskVM(t *testing.T, db *corrosion.Client, dataDir, name, state string) (*Reconciler, *libvirtfake.Fake, string, *int) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: name, HostName: "host-a", State: state,
		Spec: `{"name":"` + name + `","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	path := store.DiskPath(name, "root")
	if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName: name, DiskName: "root", HostName: "host-a", Path: path,
		BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("host-a", dataDir, db, fake)
	pulls := new(int)
	r.SetAutoPullImage(func(context.Context, string) error {
		*pulls++
		return qcow2.Create(store.ImagePath("base"), 64<<20, nil)
	})
	return r, fake, path, pulls
}

// A VM this host's row says is running here, with no domain and no disk file,
// is never started from a blank overlay rebuilt from its image: that boots a
// VM whose data is gone as if nothing happened. The start is refused, the VM
// is put in error, and vm_disk_missing names it, the disk and the way out.
// It is the shape of finding N5 (a re-added host that took over a removed
// host's rows: "VM marked running but not in libvirt", then "recreated
// overlay disk").
//
// A pending ownership transfer onto this host still rebuilds the disk; that is
// TestStartPendingVM_RecreatedOverlayKeepsTheRecordedSize.
//
// Mutation: drop the local-start refusal (rebuild whatever the start is) — the
// VM starts on a fresh overlay and the test goes red. Skip the raise — the
// condition check goes red.
func TestStartLocalVM_MissingDiskIsNotRebuiltBlank(t *testing.T) {
	for _, state := range []string{"running", "starting"} {
		t.Run(state, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			r, fake, path, pulls := missingDiskVM(t, db, t.TempDir(), "vm-n5", state)

			r.reconcile(ctx)

			if startedOrDefined(fake, "vm-n5") {
				t.Fatal("the VM was started on a disk rebuilt blank from its image")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("a disk was created at %s (stat err %v)", path, err)
			}
			if *pulls != 0 {
				t.Fatalf("the backing image was pulled %d time(s) for a start that must not rebuild", *pulls)
			}
			vm, _ := corrosion.GetVM(ctx, db, "vm-n5")
			if vm == nil || vm.State != "error" || !strings.Contains(vm.StateDetail, path) {
				t.Fatalf("row = %+v, want state error with a detail naming %s", vm, path)
			}
			c, ok, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskMissing, "vm", "vm-n5@host-a")
			if err != nil || !ok || c.Lifecycle != corrosion.ConditionConfirmed || c.Severity != corrosion.SeverityCritical ||
				!strings.Contains(c.Evidence, path) || !strings.Contains(c.Evidence, "lv rebuild vm-n5") {
				t.Fatalf("condition = %+v, %v, %v; want a confirmed critical vm_disk_missing naming %s and lv rebuild", c, ok, err, path)
			}

			// A later pass on the same row changes nothing and starts nothing.
			r.reconcile(ctx)
			if startedOrDefined(fake, "vm-n5") {
				t.Fatal("a later pass started the VM")
			}
		})
	}
}

// The condition clears once the VM has left the refused state here: the
// operator restored the disk and started it, rebuilt it, deleted it, or it
// moved to another host.
//
// Mutation: never resolve — the test goes red.
func TestStartLocalVM_DiskMissingResolves(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, _, _, _ := missingDiskVM(t, db, t.TempDir(), "vm-n5", "running")
	r.reconcile(ctx)
	if _, ok, _ := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskMissing, "vm", "vm-n5@host-a"); !ok {
		t.Fatal("the condition was not raised")
	}

	if err := corrosion.UpdateVMState(ctx, db, "vm-n5", "stopped", "operator"); err != nil {
		t.Fatal(err)
	}
	r.reconcile(ctx)

	c, ok, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskMissing, "vm", "vm-n5@host-a")
	if err != nil || !ok || c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition = %+v, %v, %v; want it resolved once the VM left error", c, ok, err)
	}
}
