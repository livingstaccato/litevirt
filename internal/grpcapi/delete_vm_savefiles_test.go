package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A memory snapshot whose delete failed keeps its record and its RAM image;
// on the lab `lv rm -f` of the VM then left <data_dir>/vmstate/sr1-m1.save
// (192 MB) behind (snapshot-repro.md, incidental finding 2). Deleting the VM
// removes the RAM images its snapshot records name, at the path this host
// gives that VM's snapshot, and nothing else.
func TestDeleteVM_RemovesItsSnapshotsRAMImages(t *testing.T) {
	s, fake := provableCreateServer(t)
	fake.SetState("vm1", libvirtfake.StateRunning)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running"}, nil, nil); err != nil {
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
	own := write(lv.VMStatePath(s.dataDir, "vm1", "m1"))
	// Another VM's image a name glob of vm1-* would catch.
	other := write(lv.VMStatePath(s.dataDir, "vm1-x", "m1"))
	// A record naming a file that is not this VM's image.
	forged := write(filepath.Join(s.dataDir, "keep.save"))
	for _, r := range []corrosion.SnapshotRecord{
		{ID: "vm1-m1", VMName: "vm1", HostName: "test-host", Name: "m1", State: "ok", Type: "memory", VMStatePath: own},
		{ID: "vm1-m2", VMName: "vm1", HostName: "test-host", Name: "m2", State: "ok", Type: "memory", VMStatePath: forged},
	} {
		if err := corrosion.InsertSnapshot(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Errorf("the VM's RAM image %s outlived it (%v)", own, err)
	}
	for _, p := range []string{other, forged} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed: it is not this VM's RAM image (%v)", p, err)
		}
	}
}
