package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// insertCephTemplate records a stopped VM "tpl" whose one disk is a ceph root
// disk of size bytes in the fixture's pool.
func (f *cephPoolFixture) insertCephTemplate(t *testing.T, size int64) {
	t.Helper()
	f.world.mu.Lock()
	f.world.images["lv/tpl-root"] = map[string]bool{}
	f.world.mu.Unlock()
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), f.s.db,
		corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", SizeBytes: size,
			Path:        "rbd:lv/tpl-root:id=litevirt:keyring=" + f.keyring + ":lvpool=ceph",
			StorageType: "ceph", StorageVolume: "ceph"}}); err != nil {
		t.Fatal(err)
	}
}

// setPoolUsage records a sampled size and use on this host's row of pool.
func setPoolUsage(t *testing.T, s *Server, pool, driver string, total, used int64) {
	t.Helper()
	ctx := context.Background()
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, "test-host", pool)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		rec = corrosion.StoragePoolRecord{HostName: "test-host", Name: pool, Driver: driver, State: "active"}
	}
	rec.TotalBytes, rec.UsedBytes = total, used
	if err := corrosion.UpsertStoragePool(ctx, s.db, rec); err != nil {
		t.Fatal(err)
	}
}

// A ceph disk is copied inside its own pool (docs/storage.md, "Clone"), with
// or without a target pool: --pool places only the file disks. So the space
// it takes is admitted where it lands — its ceph pool — and never against the
// target pool or this host's filesystem, which it never touches.
//
// Mutations: count the ceph disk in requireCloneSpace — the clone into a
// nearly full target filesystem is refused; count it in the target pool's
// capacity admission — refused too; drop the ceph pool's own admission — the
// clone into a full ceph pool is made.
func TestCloneVM_CephDiskIsAdmittedWhereItLands(t *testing.T) {
	const size = 100 << 30
	f := newCephPoolFixture(t)
	f.insertCephTemplate(t, size)
	addDirPool(t, f.s, "ssd")
	// The target pool's filesystem and its sampled capacity hold far less than
	// the ceph disk: neither is where it goes.
	f.s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 10 << 30, 100 << 30, nil }
	setPoolUsage(t, f.s, "ssd", "dir", 100<<30, 90<<30)

	if _, err := f.s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "copy", TargetPool: "ssd"}); err != nil {
		t.Fatalf("clone of a ceph-only VM with a target pool: %v (calls %v)", err, f.world.calls)
	}
	if f.world.count("deep cp lv/tpl-root lv/copy-root") != 1 {
		t.Fatalf("not copied in the ceph pool: %v", f.world.calls)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "copy")
	if len(disks) != 1 || disks[0].StorageVolume != "ceph" || !strings.HasPrefix(disks[0].Path, "rbd:lv/copy-root:") {
		t.Fatalf("clone disk rows %+v; want the copy in the ceph pool", disks)
	}

	// The ceph pool itself full: refused before the copy, naming that pool.
	setPoolUsage(t, f.s, "ceph", "ceph", 200<<30, 195<<30)
	before := f.world.count("deep cp lv/tpl-root lv/full-root")
	_, err := f.s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "full", TargetPool: "ssd"})
	if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), `"ceph"`) {
		t.Fatalf("clone into a full ceph pool = %v; want ResourceExhausted naming pool \"ceph\"", err)
	}
	if f.world.count("deep cp lv/tpl-root lv/full-root") != before {
		t.Error("a clone refused for the ceph pool's space still copied the disk")
	}
	if vm, _ := corrosion.GetVM(context.Background(), f.s.db, "full"); vm != nil {
		t.Error("a refused clone left a VM row")
	}
}

// A cross-host clone with a target pool reads its result back: a ceph disk
// that stayed in its own pool is where this release puts it, not a sign of an
// older source that ignored target_pool. And only the file disks are moved
// into the target pool on the destination (MoveVolume moves no ceph disk).
//
// Mutations: drop the ceph skip from cloneTargetIgnored, or from
// clonePoolMoves — that case goes red.
func TestCloneVM_TargetPoolLeavesCephDisksInTheirPool(t *testing.T) {
	req := &pb.CloneVMRequest{Target: "copy", DestinationHost: "h2", TargetPool: "ssd"}
	vm := &pb.VM{Name: "copy", HostName: "h2", Disks: []*pb.VMDisk{
		{Name: "root", Path: "rbd:lv/copy-root:id=litevirt", StorageType: "ceph", StorageVolume: "ceph"},
		{Name: "data", Path: "/pools/ssd/copy-data.qcow2", StorageType: "dir", StorageVolume: "ssd"},
	}}
	if err := cloneTargetIgnored(req, vm, "h1"); err != nil {
		t.Errorf("a ceph disk left in its pool was taken for an ignored target_pool: %v", err)
	}
	vm.Disks[1].StorageVolume = ""
	if err := cloneTargetIgnored(req, vm, "h1"); err == nil {
		t.Error("a file disk outside the target pool was not reported")
	}

	moves := clonePoolMoves([]corrosion.DiskRecord{
		{DiskName: "root", Path: "rbd:lv/copy-root:id=litevirt", StorageType: "ceph"},
		{DiskName: "data", Path: "/var/lib/litevirt/disks/copy-data.qcow2", StorageType: "local"},
	})
	if len(moves) != 1 || moves[0].DiskName != "data" {
		t.Errorf("disks moved into the target pool = %+v; want only data", moves)
	}
}
