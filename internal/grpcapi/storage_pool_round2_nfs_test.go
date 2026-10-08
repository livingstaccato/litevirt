package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// N4, as restored by C1: an NFS export mounted without
// nosuid,nodev,noexec,nosymfollow — by an earlier build (vers=4,hard,intr), or
// by hand — is hardened in place by a bind remount at its first use, and then
// keeps working. Only one whose remount fails is refused.
func TestPoolRound2_WeakNFSMountIsHardenedInPlaceOrRefused(t *testing.T) {
	defer storage.OverrideNosymfollowSupportForTest(true)()
	s := newPoolTestServer(t)
	dir := t.TempDir()
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nas", Driver: "nfs", Source: "nas:/x", Target: dir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	flags := "rw,relatime" // what main mounted
	defer storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 1 0:1 / %s %s - nfs4 nas:/x rw\n", dir, flags)), nil
	})()
	failRemount := true
	var remounts []string
	defer storage.OverrideNFSRemountForTest(func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		remounts = append(remounts, cmd+" "+strings.Join(args, " "))
		if failRemount {
			return nil, errors.New("permission denied")
		}
		flags = strings.TrimPrefix(args[1], "remount,bind,")
		return nil, nil
	})()

	if _, err := s.resolveVolume(adminCtx(), "", "nas"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a weak NFS mount that cannot be hardened: got %v, want FailedPrecondition", err)
	}
	if _, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "nas"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("listing a weak NFS mount that cannot be hardened: got %v, want FailedPrecondition", err)
	}
	failRemount = false
	if _, err := s.resolveVolume(adminCtx(), "", "nas"); err != nil {
		t.Fatalf("main's NFS mount after the upgrade: %v", err)
	}
	if !strings.Contains(flags, "nosymfollow") || !strings.Contains(flags, "noexec") {
		t.Fatalf("flags after the in-place hardening = %q", flags)
	}
	if want := "mount -o remount,bind,"; !strings.HasPrefix(remounts[len(remounts)-1], want) || !strings.HasSuffix(remounts[len(remounts)-1], " -- "+dir) {
		t.Fatalf("remount = %q, want %s<flags> -- %s", remounts[len(remounts)-1], want, dir)
	}
	if _, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "nas"}); err != nil {
		t.Fatalf("listing main's NFS pool after the upgrade: %v", err)
	}
}
