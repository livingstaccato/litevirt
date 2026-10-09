package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A rebuild tears the VM down as a delete does, so it removes the snapshot
// overlays of its own disks and the RAM images its memory snapshots' records
// name (final whole-branch review M3): before, only DeleteVM did, and a
// rebuilt VM left <vm>-<disk>.<snap> and vmstate/<vm>/<snap> behind for a
// later snapshot of the same name to meet. Another VM's file, one that only
// shares a name prefix, and a record naming a file that is not this VM's RAM
// image are kept.
func TestRebuildVM_RemovesItsSnapshotOverlaysAndRAMImages(t *testing.T) {
	f := newOverlayDeleteFixture(t, true)
	s := f.s
	ctx := adminCtx()
	if err := s.db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'web'`,
		`{"name":"web","cpu":1,"memory_mib":512,"placement":{"host":"test-host"}}`); err != nil {
		t.Fatal(err)
	}
	stray := f.file(t, "web-root.m0", f.root) // out of the chain: a restored-older leftover
	other := filepath.Join(f.dir, "web-x-root.m1")
	runQemuImg(t, "create", "-q", "-f", "qcow2", other, "1M")
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web-x", HostName: "test-host", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "web-x", DiskName: "root", HostName: "test-host", Path: other, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	write := func(p string) string {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("ram"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ram := write(lv.VMStatePath(s.dataDir, "web", "mem1"))
	otherRAM := write(lv.VMStatePath(s.dataDir, "web-x", "mem1"))
	forged := write(filepath.Join(s.dataDir, "keep.save"))
	for _, r := range []corrosion.SnapshotRecord{
		{ID: "web-mem1", VMName: "web", HostName: "test-host", Name: "mem1", State: "ok", Type: "memory", VMStatePath: ram},
		{ID: "web-mem2", VMName: "web", HostName: "test-host", Name: "mem2", State: "ok", Type: "memory", VMStatePath: forged},
	} {
		if err := corrosion.InsertSnapshot(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("RebuildVM: %v", err)
	}
	for _, p := range []string{f.m2, f.m1, f.root, stray, ram} {
		if fileThere(p) {
			t.Errorf("%s outlived the rebuild", filepath.Base(p))
		}
	}
	for _, p := range []string{other, otherRAM, forged} {
		if !fileThere(p) {
			t.Errorf("%s was removed: it is not the rebuilt VM's", filepath.Base(p))
		}
	}
}
