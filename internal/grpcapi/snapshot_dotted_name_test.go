package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Re-review R2-M3: a snapshot named like v1.2 worked on main and keeps
// working. libvirt names its overlay <disk stem>.v1.2; the disk is found
// again by the VM's known snapshot names, not by cutting at the last dot
// (which read the disk as dv-root.v1), so the record follows the overlay
// through create, restore and rm.
func TestSnapshot_ADottedNameCreateRestoreRm(t *testing.T) {
	s := lockTestServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	root := "/var/lib/litevirt/disks/dv-root.qcow2"
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "dv", HostName: s.hostName, State: "stopped",
		Spec: `{"name":"dv","cpu":1,"memory_mib":512}`}, nil,
		[]corrosion.DiskRecord{{VMName: "dv", DiskName: "root", HostName: s.hostName, Path: root, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	fake.SetDiskSource("dv", "vda", root)
	recorded := func() string {
		d, _ := corrosion.GetVMDisks(adminCtx(), s.db, "dv")
		if len(d) != 1 {
			t.Fatalf("disks %+v", d)
		}
		return d[0].Path
	}
	if _, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "dv", Name: "v1.2"}); err != nil {
		t.Fatalf("CreateSnapshot v1.2: %v", err)
	}
	if got, want := recorded(), "/var/lib/litevirt/disks/dv-root.v1.2"; got != want {
		t.Fatalf("after the snapshot the record names %s, want the overlay %s", got, want)
	}
	if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "dv", SnapshotName: "v1.2"}); err != nil {
		t.Fatalf("RestoreSnapshot v1.2: %v", err)
	}
	fake.SetDiskSource("dv", "vda", root) // libvirt's merge leaves it on the base
	if _, err := s.DeleteSnapshot(adminCtx(), &pb.DeleteSnapshotRequest{VmName: "dv", SnapshotName: "v1.2"}); err != nil {
		t.Fatalf("DeleteSnapshot v1.2: %v", err)
	}
	if got := recorded(); got != root {
		t.Fatalf("after the delete the record names %s, want %s", got, root)
	}
}

// VM delete finds a dotted snapshot's layers by the VM's snapshot names: a
// restore-older overlay dv-root.v1.2-r<time> on the base, the out-of-chain
// overlay dv-root.v1.2 and a later one above it all go; a file of the name
// whose suffix is no snapshot of the VM's stays.
func TestDeleteVM_ADottedSnapshotNamesLayers(t *testing.T) {
	needQemuImg(t)
	s, fake := provableCreateServer(t)
	fake.SetState("dv", libvirtfake.StateRunning)
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := func(n string) string { return filepath.Join(dir, n) }
	runQemuImg(t, "create", "-q", "-f", "qcow2", p("dv-root.qcow2"), "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", p("dv-root.qcow2"), p("dv-root.v1.2"))
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", p("dv-root.v1.2"), p("dv-root.v1.3"))
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", p("dv-root.qcow2"), p("dv-root.v1.2-r1700000000"))
	if err := os.WriteFile(p("dv-root.notes.txt"), []byte("an operator's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "dv", HostName: "test-host", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "dv", DiskName: "root", HostName: "test-host", Path: p("dv-root.v1.2-r1700000000"), StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"v1.2", "v1.3"} {
		if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{ID: "dv-" + n, VMName: "dv", HostName: "test-host", Name: n, State: "ok", Type: "disk"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "dv"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	for _, n := range []string{"dv-root.qcow2", "dv-root.v1.2", "dv-root.v1.3", "dv-root.v1.2-r1700000000"} {
		if _, err := os.Stat(p(n)); !os.IsNotExist(err) {
			t.Errorf("%s outlived the VM (%v)", n, err)
		}
	}
	if _, err := os.Stat(p("dv-root.notes.txt")); err != nil {
		t.Errorf("dv-root.notes.txt, no layer of the VM's, was removed: %v", err)
	}
}
