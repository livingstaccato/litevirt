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
)

// fix/iscsi-followups: residuals parked from the iSCSI re-reviews
// (iscsi-lun-rereview-5.md R-2).

// addLUNDirPool registers a dir pool name on s's host, at a fresh directory.
func addLUNDirPool(t *testing.T, s *Server, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "dir", Target: dir, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool %s: %v", name, err)
	}
	return dir
}

// R-2: a disk's storage is its own, not that of the last disk sharing its
// name. Two disks named alike on two dir pools are each created on their own
// pool, as on main — not both on the last one, where the second create finds
// the first's file.
//
// Mutation: key the resolved storages by disk name again — both disks resolve
// to dir pool b, a's directory stays empty, and this goes red.
func TestCreateVM_TwoDisksOfOneNameKeepTheirOwnStorage(t *testing.T) {
	s := lunTestServer(t)
	dirA, dirB := addLUNDirPool(t, s, "da"), addLUNDirPool(t, s, "db")
	spec := &pb.VMSpec{Name: "x", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: "test-host"},
		Disks: []*pb.DiskSpec{
			{Name: "root", Size: "1G"},
			{Name: "data", Size: "1G", Storage: "da"},
			{Name: "data", Size: "1G", Storage: "db"},
		}}
	if _, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: spec}); err != nil {
		t.Fatalf("create with two disks named data on two dir pools: %v", err)
	}
	for _, dir := range []string{dirA, dirB} {
		if _, err := os.Stat(filepath.Join(dir, "x-data.qcow2")); err != nil {
			t.Errorf("disk data was not created on its own pool %s: %v", dir, err)
		}
	}
}

// R-2: a disk name shared with an iSCSI LUN disk is refused before anything
// is created. A VM's disks are recorded by name, so the LUN under a shared
// name would be held by no disk row of its own; and the other disk of that
// name must never be put on the LUN.
//
// Mutation: drop the shared-name refusal — the create goes ahead and this goes
// red.
func TestCreateVM_ISCSI_ADiskNameSharedWithALUNDiskIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		disks []*pb.DiskSpec
	}{
		{"dir then lun", []*pb.DiskSpec{
			{Name: "root", Size: "1G", Storage: "lun1"},
			{Name: "data", Size: "1G", Storage: "d"},
			{Name: "data", Size: "1G", Storage: "lun0"},
		}},
		{"lun then dir", []*pb.DiskSpec{
			{Name: "root", Size: "1G", Storage: "lun1"},
			{Name: "data", Size: "1G", Storage: "lun0"},
			{Name: "data", Size: "1G", Storage: "d"},
		}},
		{"two luns", []*pb.DiskSpec{
			{Name: "data", Size: "1G", Storage: "lun0"},
			{Name: "data", Size: "1G", Storage: "lun1"},
		}},
		{"local then lun", []*pb.DiskSpec{
			{Name: "root", Size: "1G"},
			{Name: "root", Size: "1G", Storage: "lun0"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			addLUNDirPool(t, s, "d")
			spec := &pb.VMSpec{Name: "x", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: "test-host"},
				Disks: tc.disks}
			_, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: spec})
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "disks named") {
				t.Fatalf("a disk name shared with a LUN disk: got %v, want InvalidArgument", err)
			}
			requireNoVM(t, s, "x")
		})
	}
}

// R-2, the recreate's judge: a re-created spec sharing a LUN disk's name is
// refused before the teardown, as a create is.
func TestRecreateFixedDeviceUses_ADiskNameSharedWithALUNDiskIsRefused(t *testing.T) {
	s := lunTestServer(t)
	addLUNDirPool(t, s, "d")
	spec := &pb.VMSpec{Name: "x", Disks: []*pb.DiskSpec{
		{Name: "data", Size: "1G", Storage: "d"},
		{Name: "data", Size: "1G", Storage: "lun0"},
	}}
	if _, err := s.recreateFixedDeviceUses(adminCtx(), spec, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("recreate judge with a disk name shared with a LUN disk: got %v, want InvalidArgument", err)
	}
}
