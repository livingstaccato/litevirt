package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A replacement whose disk is missing on the new host is rebuilt as an
// overlay of its backing image, and that overlay must be the size the disk
// record says — not the backing image's. Drill D1 on main-8d1e56dc: pp1 and
// pp2 were created with 20 GiB roots, rescheduled restart-any to node-4, and
// came up on 112 MiB disks (cirros's virtual size). The guest lost its
// filesystem's room, and the later migrate --with-storage back failed with
// "Source and target image have different sizes".
//
// A record with no size (a row from before sizes were recorded) still
// inherits the backing image's.
//
// Mutation: pass "" for the size again — the "recorded size" subtest goes
// red with the backing image's 64 MiB.
func TestStartPendingVM_RecreatedOverlayKeepsTheRecordedSize(t *testing.T) {
	const backing = 64 << 20
	for _, tc := range []struct {
		name   string
		size   int64
		expect uint64
	}{
		{"recorded size", 20 << 30, 20 << 30},
		{"no recorded size", 0, backing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			dataDir := t.TempDir()
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm-sz", HostName: "host-a", State: "pending",
				Spec: `{"name":"vm-sz","cpu":1,"memory_mib":512}`,
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			store := image.NewStore(dataDir)
			if err := store.Init(); err != nil {
				t.Fatalf("store.Init: %v", err)
			}
			path := store.DiskPath("vm-sz", "root")
			if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
				VMName: "vm-sz", DiskName: "root", HostName: "host-a",
				Path: path, BackingImage: "base", SizeBytes: tc.size,
			}); err != nil {
				t.Fatalf("InsertDisk: %v", err)
			}
			fake := libvirtfake.New()
			r := NewReconciler("host-a", dataDir, db, fake)
			r.SetAutoPullImage(func(context.Context, string) error {
				return qcow2.Create(store.ImagePath("base"), backing, nil)
			})

			r.reconcile(ctx)

			if !startedOrDefined(fake, "vm-sz") {
				vm, _ := corrosion.GetVM(ctx, db, "vm-sz")
				t.Fatalf("the VM did not start; row = %q / %q", vm.State, vm.StateDetail)
			}
			info, err := qcow2.Info(path)
			if err != nil {
				t.Fatalf("recreated overlay: %v", err)
			}
			if info.VirtualSize != tc.expect {
				t.Fatalf("recreated overlay is %d bytes, want %d", info.VirtualSize, tc.expect)
			}
		})
	}
}
