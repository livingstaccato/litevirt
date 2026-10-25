package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// liveStackMoveFixture is a running VM pg-1 of stack "pg" on this host, its
// disk root in pool "hot", with a domain the fake libvirt runs, and a local
// pool "warm" under <data_dir>/pools to move it into. It returns the server
// and the path the move's copy is written at.
func liveStackMoveFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	dstDir := filepath.Join(s.dataDir, "pools", "warm")
	srcDir := filepath.Join(s.dataDir, "hot")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	src := filepath.Join(srcDir, "disk.qcow2")
	if err := writeFile(src, 4096); err != nil {
		t.Fatal(err)
	}
	seedPool(t, s, ctx, "warm", "local", dstDir)
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: dstDir}})
	seedStackVM(t, s, ctx, "pg", "pg-1", "running", "hot", src, 4096)
	f := libvirtfake.New()
	if err := f.DefineDomain(fakeDomainXML("pg-1", "vda", src)); err != nil {
		t.Fatal(err)
	}
	f.SetDiskSource("pg-1", "vda", src)
	f.SetState("pg-1", libvirtfake.StateRunning)
	s.virt = f
	if s.sourceClosedForPlainCopy(&corrosion.VMRecord{Name: "pg-1", State: "running"}) {
		t.Fatal("the domain must read running, so the move takes the live path")
	}
	fastPoll(t)
	return s, filepath.Join(dstDir, "pg-1-root.qcow2")
}

// The kept check of a volume move is made before the live path is taken, so
// a running VM's move (blockdev-mirror into a preallocated copy) is refused
// at a kept overlay's missing base as a stopped VM's is
// (TestMoveVolume_AKeptOverlayMissingItsBaseRefusesIt), from `lv move-volume`
// and from `lv stack migrate-volumes` alike, before the copy is preallocated
// or the block copy starts.
//
// Mutation (review m1b): move the keptPathRefusal in moveOneVolume below the
// live-path dispatch, so only the offline path is checked: every subtest
// red (the live move preallocates and writes the base).
func TestMoveVolume_Live_AKeptOverlayMissingItsBaseRefusesIt(t *testing.T) {
	t.Run("move-volume, the destination is the missing base", func(t *testing.T) {
		s, _, src, destPath := liveMoveServerWithVirt(t, false)
		mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
		s.SetLiveMover(mover)
		fastPoll(t)
		top := registryKeep(t, s, "old", destPath)
		err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm", DeleteSource: true},
			&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
		wantMissingBaseRefusal(t, "live volume move", err, top, destPath)
		if mover.startCalls != 0 || !exists(src) {
			t.Fatalf("a refused live move started its block copy (%d) or lost its source (there=%v)", mover.startCalls, exists(src))
		}
	})
	t.Run("move-volume, an unreadable kept-disks.json and a file on this host backing on the copy", func(t *testing.T) {
		s, _, src, destPath := liveMoveServerWithVirt(t, false)
		mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
		s.SetLiveMover(mover)
		fastPoll(t)
		ov := filepath.Join(s.dataDir, "disks", "db-snap1.qcow2")
		overlayOn(t, ov, destPath)
		named := keptUnknown(t, s, "registry")
		err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"},
			&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) || !strings.Contains(err.Error(), ov) {
			t.Fatalf("live move while %s cannot be read = %v; want FailedPrecondition naming it and %s", named, err, ov)
		}
		if strings.Contains(err.Error(), "create") {
			t.Fatalf("live move refusal = %v; it names a create, not the move", err)
		}
		if exists(destPath) || mover.startCalls != 0 || !exists(src) {
			t.Fatalf("a refused live move wrote its copy (%v), started its block copy (%d) or lost its source", exists(destPath), mover.startCalls)
		}
	})
	t.Run("stack migrate-volumes, the destination is the missing base", func(t *testing.T) {
		s, destPath := liveStackMoveFixture(t)
		mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
		s.SetLiveMover(mover)
		top := registryKeep(t, s, "old", destPath)
		rec := &streamRecorder[pb.StackVolumeProgress]{ctx: adminCtx()}
		err := s.MigrateStackVolumes(&pb.MigrateStackVolumesRequest{StackName: "pg", DefaultPool: "warm", Parallel: 1}, rec)
		if err == nil || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), destPath) {
			t.Fatalf("stack migrate-volumes = %v; want a refusal naming the overlay %s and its missing base %s", err, top, destPath)
		}
		if exists(destPath) || mover.startCalls != 0 {
			t.Fatalf("a refused live move wrote the kept overlay's missing base (%v) or started its block copy (%d)", exists(destPath), mover.startCalls)
		}
		if disks, _ := corrosion.GetVMDisks(adminCtx(), s.db, "pg-1"); len(disks) != 1 || disks[0].StorageVolume != "hot" {
			t.Fatalf("a refused move changed the disk row: %+v", disks)
		}
	})
	t.Run("a live move no kept overlay names goes ahead", func(t *testing.T) {
		s, _, _, destPath := liveMoveServerWithVirt(t, false)
		mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
		s.SetLiveMover(mover)
		fastPoll(t)
		registryKeep(t, s, "old", filepath.Join(filepath.Dir(destPath), "old-root.qcow2"))
		if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"},
			&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
			t.Fatalf("live move into a pool no kept overlay's missing base is at: %v", err)
		}
		if mover.pivotCalls != 1 {
			t.Fatalf("the live move did not pivot (%d): this proves nothing", mover.pivotCalls)
		}
	})
}
