package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A disk recorded delete_with_vm=false (adopted: its file is not the VM's
// to remove) survives the VM's delete on every path — the recorded-volume
// delete, the <vm>-*.qcow2 debris sweep and the snapshot-overlay cleanup —
// with the layers under it. Main removed it through the first two.
func TestDeleteVM_AKeptDiskSurvivesEveryPath(t *testing.T) {
	needQemuImg(t)
	s, fake := provableCreateServer(t)
	fake.SetState("web", libvirtfake.StateRunning)
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "web-root.qcow2")
	data := filepath.Join(dir, "web-data.qcow2") // swept by name on main
	dataTop := filepath.Join(dir, "web-data.m1") // recorded: freed by its row on main
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", data, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", data, dataTop)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: "test-host", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, d := range []corrosion.DiskRecord{
		{VMName: "web", DiskName: "root", HostName: "test-host", Path: root, StorageType: "local", DeviceKind: "disk", DeleteWithVM: true},
		{VMName: "web", DiskName: "data", HostName: "test-host", Path: dataTop, StorageType: "local", DeviceKind: "disk", DeleteWithVM: false},
	} {
		if err := corrosion.InsertDisk(ctx, s.db, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	for _, p := range []string{data, dataTop} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s, a disk kept with the VM's delete, was removed: %v", filepath.Base(p), err)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the VM's own root disk outlived it (%v)", err)
	}
}
