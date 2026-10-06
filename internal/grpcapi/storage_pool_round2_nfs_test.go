package grpcapi

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// N4: an NFS export mounted without nosuid,nodev,noexec,nosymfollow (by hand,
// or by an earlier build) is refused until litevirt mounts it again. Nothing
// remounts it.
func TestPoolRound2_WeakNFSMountIsRefused(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nas", Driver: "nfs", Source: "nas:/x", Target: dir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	flags := "rw,relatime"
	defer storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 1 0:1 / %s %s - nfs4 nas:/x rw\n", dir, flags)), nil
	})()

	if _, err := s.resolveVolume(adminCtx(), "", "nas"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a disk on a weak NFS mount: got %v, want FailedPrecondition", err)
	}
	if _, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "nas"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("listing a weak NFS mount: got %v, want FailedPrecondition", err)
	}
	flags = "rw,nosuid,nodev,noexec,nosymfollow,relatime"
	if _, err := s.resolveVolume(adminCtx(), "", "nas"); err != nil {
		t.Fatalf("a hardened mount: %v", err)
	}
}
