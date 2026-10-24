package health

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A failover rebuild the kept-create check refuses (the daemon's
// RecreateOverlayDisk returns KeptRebuildRefusedError) does not start the VM,
// fails the pending start as retryable, and raises vm_disk_kept_base naming
// the file; once the rebuild goes ahead and the VM starts, it resolves.
//
// Mutation: drop the keptRebuildRefused call - no condition: red. Drop the
// resolveKeptRebuildRefused call - the condition stays open after the start:
// red.
func TestStartPendingVM_AKeptRefusedRebuildRaisesVMDiskKeptBase(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "web", HostName: "host-a", State: "pending",
		Spec: `{"name":"web","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	path := store.DiskPath("web", "root")
	if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: "host-a",
		Path: path, BackingImage: "base", SizeBytes: 1 << 30,
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("host-a", dataDir, db, fake)
	r.SetAutoPullImage(func(context.Context, string) error {
		if _, err := os.Stat(store.ImagePath("base")); err == nil {
			return nil
		}
		return qcow2.Create(store.ImagePath("base"), 64<<20, nil)
	})
	refuse := true
	r.SetRecreateOverlay(func(vm, disk, img, size string) (string, error) {
		if refuse {
			return "", &KeptRebuildRefusedError{Path: path, Err: errors.New("the create writes " + path +
				", which /kept/old-top.qcow2 backs on although it is missing")}
		}
		return store.CreateOverlayDisk(vm, disk, img, size)
	})

	r.reconcile(ctx)

	if startedOrDefined(fake, "web") {
		t.Fatal("a VM whose disk rebuild was refused was started")
	}
	row, had, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", "web@host-a")
	if err != nil || !had || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("vm_disk_kept_base = %+v, %v, %v; want it open", row, had, err)
	}
	if !strings.Contains(row.Evidence, path) || !strings.Contains(row.Evidence, "/kept/old-top.qcow2") {
		t.Fatalf("vm_disk_kept_base does not name the file and the kept overlay: %s", row.Evidence)
	}

	refuse = false
	if err := corrosion.UpdateVMState(ctx, db, "web", "pending", ""); err != nil {
		t.Fatal(err)
	}
	r.reconcile(ctx)
	if !startedOrDefined(fake, "web") {
		vm, _ := corrosion.GetVM(ctx, db, "web")
		t.Fatalf("the VM did not start once the rebuild went ahead; row = %q / %q", vm.State, vm.StateDetail)
	}
	r.reconcile(ctx)
	row, _, _ = corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", "web@host-a")
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("vm_disk_kept_base still %s after the VM started", row.Lifecycle)
	}
}
