package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The lab (snapshot-lab.md): `lv rm -f` of a VM with two or more snapshots
// left the middle overlay <vm>-root.m1 behind, backing onto a file the
// delete had removed. The recorded disk (the live layer) went by its row and
// <vm>-root.qcow2 by the debris glob, which matches .qcow2 names only.
// Deleting the VM removes every layer of its own chain and every overlay of
// its disk's name — and never one another VM backs on.
func TestDeleteVM_RemovesItsSnapshotOverlays(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clone bool // another VM, unrecorded, backs on the middle overlay
	}{{"alone", false}, {"a clone backs on the middle overlay", true}} {
		t.Run(tc.name, func(t *testing.T) {
			needQemuImg(t)
			s, fake := provableCreateServer(t)
			fake.SetState("vm1", libvirtfake.StateRunning)
			dir := filepath.Join(s.dataDir, "disks")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(dir, "vm1-root.qcow2")
			m1 := filepath.Join(dir, "vm1-root.m1")
			m2 := filepath.Join(dir, "vm1-root.m2")
			stray := filepath.Join(dir, "vm1-root.m0") // out of the chain (a restored-older leftover)
			other := filepath.Join(dir, "vm1-x-root.m1")
			runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
			runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, m1)
			runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", m1, m2)
			runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, stray)
			runQemuImg(t, "create", "-q", "-f", "qcow2", other, "1M")
			ctx := adminCtx()
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running"}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: m2, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1-x", HostName: "test-host", State: "stopped"}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1-x", DiskName: "root", HostName: "test-host", Path: other, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			var clone string
			if tc.clone {
				clone = filepath.Join(dir, "cl-root.qcow2")
				runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", m1, clone)
				if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "cl", HostName: "test-host", State: "stopped"}, nil,
					[]corrosion.DiskRecord{{VMName: "cl", DiskName: "root", HostName: "test-host", Path: clone, StorageType: "local"}}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			gone := []string{m2, stray}
			kept := []string{other}
			if tc.clone {
				kept = append(kept, m1, root, clone)
			} else {
				gone = append(gone, m1, root)
			}
			for _, p := range gone {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("%s outlived the VM (%v)", filepath.Base(p), err)
				}
			}
			for _, p := range kept {
				if _, err := os.Stat(p); err != nil {
					t.Errorf("%s was removed: another VM uses it (%v)", filepath.Base(p), err)
				}
			}
		})
	}
}
