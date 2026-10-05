// A VM's leftovers on a host it migrated away from go with the VM's delete.
//
// Observed on the lab: os1 had a disk hot-detached on node-3 (detach keeps the
// file by design), was migrated to another host and deleted there. The delete
// freed what the new owner held, and node-3 kept os1-post1.qcow2 and
// vms/os1/owner_epoch for good — the migration leaves both (the detached disk
// was not moved, the marker is a fence), and nothing after it looked back.
//
// Multi-node by construction: the delete runs on the new owner, the files are
// on the old one, and the request between them crosses real gRPC and is
// judged against the old host's own replica.
package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// TestFleet_DeleteRemovesWhatTheVMLeftOnAHostItMigratedFrom: os1 runs on src
// with a shared root and a host-local disk detached there, migrates to dst, and
// is deleted on dst. src's detached disk and marker survive the migration and
// are gone after the delete; with --keep-disks the disk stays and the marker
// still goes.
//
// Mutations: drop the fan-out from DeleteVM — both files stay on src; drop the
// vm_deleted branch on the receiving side — both stay; plan the disks for
// --keep-disks — the keep-disks subtest loses the disk.
func TestFleet_DeleteRemovesWhatTheVMLeftOnAHostItMigratedFrom(t *testing.T) {
	for _, keepDisks := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete", true: "keep-disks"}[keepDisks], func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			defer c.Stop()
			src, dst := c.Nodes[0], c.Nodes[1]
			srcData := filepath.Join(c.tmpRoot, src.Name, "data")

			post1 := filepath.Join(srcData, "disks", "os1-post1.qcow2")
			if err := os.MkdirAll(filepath.Dir(post1), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := qcow2.Create(post1, 1<<30, nil); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
				Name: "os1", HostName: src.Name, State: "running", CPUActual: 1, MemActual: 512,
			}, nil, []corrosion.DiskRecord{
				{VMName: "os1", DiskName: "root", HostName: src.Name, Path: "/var/lib/litevirt/disks/os1-root.qcow2",
					SizeBytes: 1 << 30, StorageType: "nfs", StorageVolume: "shared", TargetDev: "vda"},
				{VMName: "os1", DiskName: "post1", HostName: src.Name, Path: post1,
					SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vdb"},
			}); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			// lv detach-disk os1 post1: the row is soft-deleted, the file kept.
			if err := corrosion.SoftDeleteDisk(ctx, src.DB, "os1", "post1"); err != nil {
				t.Fatal(err)
			}
			if err := health.WriteVMOwnerEpochMarker(srcData, "os1", 1); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(srcData, "vms", "os1", "owner_epoch")
			src.Virt.SetState("os1", "running")

			if err := migrateAt(t, c, src, "os1", dst.Name); err != nil {
				t.Fatalf("migrate os1 %s → %s: %v", src.Name, dst.Name, err)
			}
			// libvirt undefines the source and the guest runs on the target;
			// the fakes do not model the move.
			if err := src.Virt.UndefineDomain("os1", false); err != nil {
				t.Fatal(err)
			}
			dst.Virt.SetState("os1", "running")

			// The migration leaves both on src, deliberately.
			if !present(post1) {
				t.Fatal("the migration removed a disk detached on the source; detach preserves it")
			}
			if !present(marker) {
				t.Fatal("the migration removed the source's owner-epoch marker, a fence for a stale replica")
			}

			if _, err := c.SelfClient(dst).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "os1", KeepDisks: keepDisks}); err != nil {
				t.Fatalf("DeleteVM on %s: %v", dst.Name, err)
			}

			deadline := time.Now().Add(10 * time.Second)
			settled := func() bool { return !present(marker) && (keepDisks || !present(post1)) }
			for !settled() && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if present(marker) {
				t.Fatalf("%s still holds vms/os1/owner_epoch after os1 was deleted on %s", src.Name, dst.Name)
			}
			if present(filepath.Dir(marker)) {
				t.Fatalf("%s still holds the vms/os1 directory after os1 was deleted", src.Name)
			}
			if keepDisks {
				if !present(post1) {
					t.Fatal("a --keep-disks delete removed the disk detached on the old host")
				}
				return
			}
			if present(post1) {
				t.Fatalf("%s still holds os1-post1.qcow2 after os1 was deleted on %s", src.Name, dst.Name)
			}
		})
	}
}

func present(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
