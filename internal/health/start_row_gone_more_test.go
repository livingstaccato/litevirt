package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// recreateVM1 deletes vm1's row and creates it again on node-a: another
// incarnation of the name, as a delete and re-create arriving by
// replication inside one start look.
func recreateVM1(t *testing.T, ctx context.Context, db *corrosion.Client) string {
	t.Helper()
	if err := corrosion.DeleteVM(ctx, db, "vm1"); err != nil {
		t.Errorf("tombstone vm1: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped"}, nil, nil); err != nil {
		t.Errorf("re-create vm1: %v", err)
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("re-created vm1: %v %v", row, err)
	}
	return row.CreatedAt
}

// A row deleted and created again inside the start is another incarnation.
// The domain this pass built is the old one's and must not boot as the new
// one.
func TestStartPendingVM_RowRecreatedBeforeStartIsNotStarted(t *testing.T) {
	db, fake, r, vm := startRowGoneFixture(t, false)
	ctx := context.Background()
	r.startDomainHook = func(ctx context.Context) { recreateVM1(t, ctx, db) }
	r.startPendingVM(ctx, vm)
	if startedVM1(fake) {
		t.Fatal("the reconciler booted the old incarnation's domain under a re-created record")
	}
	if fake.DomainExists("vm1") {
		t.Fatal("the old incarnation's definition was left behind")
	}
}

// And after the boot: the guest is stopped, and no running state is
// published onto the new incarnation's row.
func TestStartPendingVM_RowRecreatedDuringStartIsStopped(t *testing.T) {
	db, fake, r, vm := startRowGoneFixture(t, false)
	ctx := context.Background()
	var created string
	fake.OnRunning = func(name string) {
		if name == "vm1" && created == "" {
			created = recreateVM1(t, ctx, db)
		}
	}
	r.startPendingVM(ctx, vm)
	fake.OnRunning = nil
	if !startedVM1(fake) {
		t.Fatal("the scenario never booted vm1")
	}
	if st, _ := fake.DomainState("vm1"); st == "running" {
		t.Fatal("the old incarnation's guest is left running under a re-created record")
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil || row.CreatedAt != created {
		t.Fatalf("re-created row = %+v (%v), want the new incarnation", row, err)
	}
	if row.State != "stopped" {
		t.Errorf("the new incarnation's row reads %q, want stopped: the old start published onto it", row.State)
	}
}

// A row that names another host by the boot is not started.
func TestStartPendingVM_RowMovedBeforeStartIsNotStarted(t *testing.T) {
	db, fake, r, vm := startRowGoneFixture(t, false)
	ctx := context.Background()
	r.startDomainHook = func(ctx context.Context) {
		if err := corrosion.UpdateVMHost(ctx, db, "vm1", "node-b", "pending"); err != nil {
			t.Errorf("move vm1: %v", err)
		}
	}
	r.startPendingVM(ctx, vm)
	if startedVM1(fake) {
		t.Fatal("the reconciler booted a VM whose record now names node-b")
	}
	if fake.DomainExists("vm1") {
		t.Fatal("the definition of a VM not started was left behind")
	}
}

// What the hardware pre-start claimed is given back once the guest booted
// for a deleted record is stopped.
func TestStartPendingVM_RowGoneDuringStartReleasesHardware(t *testing.T) {
	db, fake, r, vm := startRowGoneFixture(t, false)
	ctx := context.Background()
	released := 0
	r.SetHardwareStartPreparer(func(context.Context, *corrosion.VMRecord) (func(), error) {
		return func() { released++ }, nil
	})
	fake.OnRunning = func(name string) {
		if name == "vm1" {
			if err := corrosion.DeleteVM(ctx, db, "vm1"); err != nil {
				t.Errorf("tombstone vm1: %v", err)
			}
		}
	}
	r.startPendingVM(ctx, vm)
	fake.OnRunning = nil
	if released != 1 {
		t.Fatalf("hardware release ran %d times after the guest was stopped, want 1", released)
	}
}

// UEFI vars the ghost's boot created are removed with it, since they would
// refuse a create of the name; vars that were there before are never
// touched.
func TestStartPendingVM_RowGoneDuringStartNvram(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "created-by-the-boot", true: "there-before"}[before], func(t *testing.T) {
			db, fake, r, vm := startRowGoneFixture(t, false)
			ctx := context.Background()
			nvram := lv.NvramPath(r.dataDir, "vm1")
			if err := os.MkdirAll(filepath.Dir(nvram), 0o700); err != nil {
				t.Fatal(err)
			}
			if before {
				if err := os.WriteFile(nvram, []byte("kept vars"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fake.OnRunning = func(name string) {
				if name != "vm1" {
					return
				}
				// What libvirt does on a UEFI boot with no vars file.
				if !before {
					if err := os.WriteFile(nvram, []byte("template vars"), 0o600); err != nil {
						t.Error(err)
					}
				}
				if err := corrosion.DeleteVM(ctx, db, "vm1"); err != nil {
					t.Errorf("tombstone vm1: %v", err)
				}
			}
			r.startPendingVM(ctx, vm)
			fake.OnRunning = nil
			if fake.DomainExists("vm1") {
				t.Fatal("the disk-less ghost was left defined")
			}
			_, err := os.Stat(nvram)
			if before && err != nil {
				t.Fatalf("UEFI vars that predate the start were removed: %v", err)
			}
			if !before && err == nil {
				t.Fatal("the UEFI vars the ghost's boot created were left behind; a create of the name is refused")
			}
		})
	}
}
