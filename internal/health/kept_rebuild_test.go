package health

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

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
// red. Resolve whatever the VM's state - resolved while still refused: red.
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

	// A pass while the start stays refused (the VM is in error: this start
	// carries no transfer proof) does not resolve it.
	r.reconcile(ctx)
	row, _, _ = corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", "web@host-a")
	if row.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("vm_disk_kept_base resolved while the VM is still refused on this host")
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

// vm_disk_kept_base's fix names the real cause, and a refusal repeated the
// same way is not written again (each retried pass would replicate a row).
// Mutations: one fix text for every cause - "unreadable" or "no answer" red;
// write on every call - "repeated" red.
func TestKeptRebuildRefused_FixNamesTheCauseAndRepeatsAreNotWritten(t *testing.T) {
	ctx := context.Background()
	markers := map[string]string{
		KeptRebuildOverlay:    "move that overlay off this host",
		KeptRebuildUnreadable: "cannot be read on host-a",
		KeptRebuildNoAnswer:   "did not answer while the kept disks were checked",
	}
	for cause, want := range markers {
		t.Run(cause, func(t *testing.T) {
			db := testReconcilerDB(t)
			r := NewReconciler("host-a", t.TempDir(), db, libvirtfake.New())
			r.keptRebuildRefused(ctx, "web", "root", &KeptRebuildRefusedError{Path: "/d/web-root.qcow2", Cause: cause, Err: errors.New("why")})
			row, _, _ := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", "web@host-a")
			if !strings.Contains(row.Evidence, want) {
				t.Fatalf("fix for %s does not say %q: %s", cause, want, row.Evidence)
			}
			for other, m := range markers {
				if other != cause && strings.Contains(row.Evidence, m) {
					t.Fatalf("fix for %s gives %s's advice: %s", cause, other, row.Evidence)
				}
			}
		})
	}
	t.Run("repeated", func(t *testing.T) {
		db := testReconcilerDB(t)
		r := NewReconciler("host-a", t.TempDir(), db, libvirtfake.New())
		now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
		r.Now = func() time.Time { return now }
		refusal := &KeptRebuildRefusedError{Path: "/d/web-root.qcow2", Cause: KeptRebuildOverlay, Err: errors.New("why")}
		r.keptRebuildRefused(ctx, "web", "root", refusal)
		first, _, _ := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", "web@host-a")
		now = now.Add(time.Minute)
		r.keptRebuildRefused(ctx, "web", "root", refusal)
		again, _, _ := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", "web@host-a")
		if again.LastSeen != first.LastSeen || again.ObserveCount != first.ObserveCount {
			t.Fatalf("an unchanged refusal was written again: %+v then %+v", first, again)
		}
		r.keptRebuildRefused(ctx, "web", "root", &KeptRebuildRefusedError{Path: "/d/web-root.qcow2", Cause: KeptRebuildNoAnswer, Err: errors.New("other")})
		changed, _, _ := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", "web@host-a")
		if changed.Evidence == first.Evidence || changed.FirstSeen != first.FirstSeen {
			t.Fatalf("a changed refusal was not written, or lost when it began: %+v", changed)
		}
	})
}
